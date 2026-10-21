//go:build windows && native

package service

import (
	"aegishook/internal/core"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsPipeFramingT3(t *testing.T) {
	for _, size := range []uint32{0, controlMaxFrame + 1} {
		var b bytes.Buffer
		if err := binary.Write(&b, binary.BigEndian, size); err != nil {
			t.Fatal(err)
		}
		if _, err := readFrame(&b); err == nil {
			t.Fatal("invalid frame accepted", size)
		}
	}
	for _, data := range [][]byte{nil, bytes.Repeat([]byte{'x'}, controlMaxFrame+1)} {
		if writeFrame(&bytes.Buffer{}, data) == nil {
			t.Fatal("invalid write accepted")
		}
	}
	var b bytes.Buffer
	if err := writeFrame(&b, []byte(`{"verb":"status"}`)); err != nil {
		t.Fatal(err)
	}
	data, err := readFrame(&b)
	if err != nil || string(data) != `{"verb":"status"}` {
		t.Fatalf("round trip = %q %v", data, err)
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 2, 1})); err == nil {
		t.Fatal("truncated body accepted")
	}
}

func TestWindowsPipeDescriptorT3(t *testing.T) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := current.User.Sid.String()
	sd, err := pipeSecurity(owner)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !administratorSID(sid) && (sid.String() != owner || uint32(ace.Mask) != pipeClientRights) {
			t.Fatal("unexpected pipe client rights")
		}
	}
	noOwner, err := pipeSecurity("")
	if err != nil {
		t.Fatal(err)
	}
	noOwnerACL, _, err := noOwner.DACL()
	if err != nil || noOwnerACL.AceCount != 2 {
		t.Fatal("missing owner did not leave only SYSTEM/admin")
	}
	if _, err := pipeSecurity("not a SID)(A;;GA;;;WD)"); err == nil {
		t.Fatal("SDDL injection accepted")
	}
}

func requireNativeSystem(t *testing.T) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("NOT RUN: actual pipe owner/authentication tests require the Windows SYSTEM fixture")
	}
}

func testPipePair(t *testing.T) (*pipeStream, *pipeStream) {
	t.Helper()
	requireNativeSystem(t)
	name := fmt.Sprintf(`\\.\pipe\tg-sentry-ctl-test-%d-%s`, os.Getpid(), strings.ReplaceAll(t.Name(), "/", "-"))
	server, err := newControlPipe(name, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	t.Cleanup(cancel)
	t.Cleanup(func() { windows.CloseHandle(server) })
	s := &pipeStream{handle: server, ctx: ctx, deadline: time.Now().Add(controlTimeout)}
	connected := make(chan error, 1)
	go func() {
		_, err := s.operation(func(o *windows.Overlapped, _ *uint32) error { return windows.ConnectNamedPipe(server, o) })
		connected <- err
	}()
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	client, err := windows.CreateFile(path, pipeClientRights, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(client) })
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	return s, &pipeStream{handle: client, ctx: ctx, deadline: time.Now().Add(controlTimeout)}
}

func TestWindowsPipeKernelIdentityT3(t *testing.T) {
	server, client := testPipePair(t)
	if err := writeFrame(client, []byte(`{"verb":"status"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(server); err != nil {
		t.Fatal(err)
	}
	allowed, err := pipeAuthorized(server.handle, "")
	if err != nil || !allowed {
		t.Fatal("kernel SYSTEM peer not authorized", err)
	}
	if allowed, err := pipeAuthorized(windows.InvalidHandle, ""); err == nil || allowed {
		t.Fatal("identity failure did not deny")
	}
	// Reversion must have removed the thread token; the main test goroutine may
	// move threads, so pipeAuthorized itself owns pin/query/revert correctness.
}

func TestWindowsPipeRejectsMalformedAndIdentityFailureT3(t *testing.T) {
	for _, c := range []struct {
		name, frame     string
		identityFailure bool
	}{
		{"identity failure", `{"verb":"status"}`, true},
		{"unknown field", `{"verb":"status","root":"untrusted"}`, false},
		{"unknown verb", `{"verb":"install"}`, false},
		{"trailing json", `{"verb":"status"}{}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			server, client := testPipePair(t)
			validated := false
			d := windowsDaemon{options: core.MachineOptions{Root: core.DefaultRoot(), ValidatePath: func(string, bool) error { validated = true; return errors.New("must not read state") }},
				peer: func(windows.Handle, string) (bool, error) {
					if c.identityFailure {
						return false, errors.New("forced lookup failure")
					}
					return true, nil
				}}
			done := make(chan struct{})
			go func() { d.handle(server.ctx, server); close(done) }()
			if err := writeFrame(client, []byte(c.frame)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-server.ctx.Done():
				t.Fatal("handler did not complete")
			}
			if validated {
				t.Fatal("rejected caller/frame reached private state")
			}
		})
	}
}

func TestWindowsPipeCancellationAndDeadline(t *testing.T) {
	server, _ := testPipePair(t)
	server.deadline = time.Now().Add(-controlReplyMargin)
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("expired IO deadline not enforced", err)
	}
	server.deadline = time.Time{}
	ctx, cancel := context.WithCancel(server.ctx)
	server.ctx = ctx
	done, armed := make(chan error, 1), make(chan struct{})
	go func() {
		var data [1]byte
		_, err := server.operation(func(o *windows.Overlapped, count *uint32) error {
			err := windows.ReadFile(server.handle, data[:], count, o)
			close(armed)
			return err
		})
		done <- err
	}()
	select {
	case <-armed:
	case <-time.After(controlTimeout):
		t.Fatal("read never submitted")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(controlTimeout):
		t.Fatal("pending read did not cancel")
	}
}

func TestWindowsPipeImmediateCompletion(t *testing.T) {
	stream := pipeStream{ctx: context.Background(), deadline: time.Now().Add(controlTimeout)}
	n, err := stream.operation(func(_ *windows.Overlapped, done *uint32) error { *done = uint32(len("ready")); return nil })
	if err != nil || n != uint32(len("ready")) {
		t.Fatal("synchronous completion incorrectly waited for event", n, err)
	}
}
