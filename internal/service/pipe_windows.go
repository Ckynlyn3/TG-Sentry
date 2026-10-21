//go:build windows

package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// N2 and deadline/reply-margin precedents: socket_unix.go. No new wire limits.
const controlMaxFrame = 8192
const controlTimeout = 15 * time.Second
const controlReplyMargin = 100 * time.Millisecond
const controlPipe = `\\.\pipe\tg-sentry-ctl`

// Individual rights deliberately omit FILE_CREATE_PIPE_INSTANCE (the same bit
// as FILE_APPEND_DATA). Microsoft, Named Pipe Security and Access Rights.
const pipeClientRights = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.READ_CONTROL | windows.SYNCHRONIZE

var impersonatePipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
var waitNamedPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")

func pipeSecurity(owner string) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if owner != "" {
		sid, err := windows.StringToSid(owner)
		if err != nil {
			return nil, errors.New("invalid machine owner SID")
		}
		sddl += "(A;;0x00120003;;;" + sid.String() + ")"
	}
	return windows.SecurityDescriptorFromString(sddl)
}

func newControlPipe(name, owner string) (windows.Handle, error) {
	sd, err := pipeSecurity(owner)
	if err != nil {
		return 0, err
	}
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	// CreateNamedPipeW: first-instance prevents squatting, reject-remote prevents
	// network callers; a single byte-stream instance matches the Unix serializer.
	return windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, controlMaxFrame, controlMaxFrame, uint32(controlTimeout/time.Millisecond), &sa)
}

// ImpersonateNamedPipeClient impersonates the LAST MESSAGE READ; call only after
// readFrame. Pin the OS thread through query + revert. A failed revert cannot
// return a still-impersonating thread to Go's scheduler (Microsoft RevertToSelf,
// Remarks requires terminating the process in that case).
func pipeAuthorized(handle windows.Handle, owner string) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ok, _, err := impersonatePipeClient.Call(uintptr(handle))
	if ok == 0 {
		return false, errors.New("kernel pipe identity unavailable")
	}
	defer func() {
		if windows.RevertToSelf() != nil {
			os.Exit(ExitUsage)
		}
	}()
	var token windows.Token
	if err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return false, err
	}
	defer token.Close()
	return tokenAuthorized(token, owner)
}

func tokenAuthorized(token windows.Token, owner string) (bool, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return false, err
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) || (owner != "" && user.User.Sid.String() == owner) {
		return true, nil
	}
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	// CheckTokenMembership honors enabled groups, deny-only UAC and restrictions.
	return token.IsMember(admin)
}

type pipeStream struct {
	handle   windows.Handle
	ctx      context.Context
	deadline time.Time
}

// Microsoft "Named Pipe Server Using Overlapped I/O" and CancelIoEx, Remarks:
// cancel AND wait for completion before releasing buffers/OVERLAPPED/events.
// One operation at a time, like the landed Unix maintenance endpoint.
func (p *pipeStream) operation(start func(*windows.Overlapped, *uint32) error) (uint32, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, err
	}
	if !p.deadline.IsZero() && !p.deadline.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	cancelled, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(cancelled)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(p.ctx, func() { windows.SetEvent(cancelled); close(callbackDone) })
	defer func() {
		if !stop() {
			<-callbackDone
		}
	}()
	overlapped := windows.Overlapped{HEvent: event}
	var immediate uint32
	startErr := start(&overlapped, &immediate)
	if startErr == nil {
		return immediate, nil
	}
	if startErr == windows.ERROR_PIPE_CONNECTED {
		return 0, nil
	}
	if startErr != windows.ERROR_IO_PENDING {
		return 0, startErr
	}
	timeout := uint32(windows.INFINITE)
	if !p.deadline.IsZero() {
		remaining := time.Until(p.deadline)
		if remaining <= 0 {
			return p.cancel(&overlapped, os.ErrDeadlineExceeded)
		}
		timeout = uint32((remaining + time.Millisecond - 1) / time.Millisecond)
	}
	result, err := windows.WaitForMultipleObjects([]windows.Handle{event, cancelled}, false, timeout)
	if err != nil {
		return p.cancel(&overlapped, err)
	}
	switch result {
	case windows.WAIT_OBJECT_0:
		var done uint32
		err := windows.GetOverlappedResult(p.handle, &overlapped, &done, false)
		return done, err
	case windows.WAIT_OBJECT_0 + 1:
		return p.cancel(&overlapped, p.ctx.Err())
	case uint32(windows.WAIT_TIMEOUT):
		return p.cancel(&overlapped, os.ErrDeadlineExceeded)
	default:
		return p.cancel(&overlapped, errors.New("unexpected pipe wait result"))
	}
}

func (p *pipeStream) cancel(overlapped *windows.Overlapped, reason error) (uint32, error) {
	cancelErr := windows.CancelIoEx(p.handle, overlapped)
	if cancelErr == windows.ERROR_NOT_FOUND {
		cancelErr = nil
	} // Completion raced cancellation.
	var done uint32
	completeErr := windows.GetOverlappedResult(p.handle, overlapped, &done, true)
	if completeErr == windows.ERROR_OPERATION_ABORTED {
		completeErr = nil
	}
	return 0, errors.Join(reason, cancelErr, completeErr)
}

func (p *pipeStream) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	n, err := p.operation(func(o *windows.Overlapped, done *uint32) error { return windows.ReadFile(p.handle, data, done, o) })
	runtime.KeepAlive(data)
	if err == windows.ERROR_BROKEN_PIPE || (err == nil && n == 0) {
		return 0, io.EOF
	}
	return int(n), err
}

func (p *pipeStream) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	n, err := p.operation(func(o *windows.Overlapped, done *uint32) error { return windows.WriteFile(p.handle, data, done, o) })
	runtime.KeepAlive(data)
	return int(n), err
}

func readFrame(r io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size == 0 || size > controlMaxFrame {
		return nil, errors.New("control frame exceeds input budget")
	}
	data := make([]byte, size)
	_, err := io.ReadFull(r, data)
	return data, err
}

func writeFrame(w io.Writer, data []byte) error {
	if len(data) == 0 || len(data) > controlMaxFrame {
		return errors.New("invalid control frame size")
	}
	var frame bytes.Buffer
	if err := binary.Write(&frame, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	frame.Write(data)
	_, err := io.Copy(w, &frame)
	return err
}

func (d *windowsDaemon) handle(ctx context.Context, stream *pipeStream) {
	deadline := time.Now().Add(controlTimeout)
	stream.deadline = deadline
	data, err := readFrame(stream)
	if err != nil {
		return
	}
	allowed, err := d.peer(stream.handle, d.owner)
	if err != nil || !allowed {
		return
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.Validate() != nil || decoder.Decode(new(any)) != io.EOF {
		return
	}
	if !request.Deadline.IsZero() && request.Deadline.Before(deadline) {
		deadline = request.Deadline
	}
	stream.deadline = deadline
	backend, cancel := context.WithDeadline(ctx, deadline.Add(-controlReplyMargin))
	defer cancel()
	state, err := d.status(backend, request.Verb)
	if err != nil {
		return
	}
	data, err = json.Marshal(state)
	if err == nil {
		_ = writeFrame(stream, data)
	} // One-shot transport failure closes the request.
}

// Named Pipe Client / WaitNamedPipeW, Remarks: a busy single instance waits
// within the original budget; another client may win the open, so retry it.
func connectControlPipe(path string, deadline time.Time) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		// Identification permits token queries, not acting as the client.
		handle, err := windows.CreateFile(name, pipeClientRights, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err != windows.ERROR_PIPE_BUSY {
			return handle, err
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		ok, _, waitErr := waitNamedPipe.Call(uintptr(unsafe.Pointer(name)), uintptr((remaining+time.Millisecond-1)/time.Millisecond))
		runtime.KeepAlive(name)
		if ok == 0 {
			return 0, waitErr
		}
	}
}

func callWindows(root string, request Request) (Status, error) {
	if !validWindowsMachineRoot(root) {
		return Status{}, errors.New("invalid machine root for the system control pipe")
	}
	if err := request.Validate(); err != nil {
		return Status{}, err
	}
	deadline := time.Now().Add(controlTimeout)
	if !request.Deadline.IsZero() && request.Deadline.Before(deadline) {
		deadline = request.Deadline
	}
	if !deadline.After(time.Now()) {
		return Status{}, os.ErrDeadlineExceeded
	}
	request.Deadline = deadline
	handle, err := connectControlPipe(controlPipe, deadline)
	if err != nil {
		return Status{}, errors.New("machine control endpoint unavailable")
	}
	defer windows.CloseHandle(handle)
	// The kernel-assigned SYSTEM owner authenticates the server, as peerUID=0
	// does on Unix. An ordinary user cannot assign SYSTEM ownership to a pipe.
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return Status{}, errors.New("untrusted machine control server")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return Status{}, errors.New("untrusted machine control server")
	}
	stream := &pipeStream{handle: handle, ctx: context.Background(), deadline: deadline}
	data, err := json.Marshal(request)
	if err != nil {
		return Status{}, err
	}
	if err := writeFrame(stream, data); err != nil {
		return Status{}, err
	}
	data, err = readFrame(stream)
	if err != nil {
		return Status{}, err
	}
	var state Status
	if json.Unmarshal(data, &state) != nil {
		return Status{}, errors.New("invalid control response")
	}
	return state, nil
}
