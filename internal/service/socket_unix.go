//go:build darwin || linux

package service

import (
	"aegishook/internal/core"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"time"
)

// N2: the plan's length-prefixed JSON convention uses S1's 8192-byte input
// budget. Connection/command deadlines reuse S1's 15-second enrollment bound.
const controlMaxFrame = 8192
const controlTimeout = 15 * time.Second

// NAMED LOCAL EXCEPTION controlReplyMargin: reserve 100ms for the local framed
// reply, not a protocol standard. TestReviewStalledBackendStatusBeforeClientDeadline
// validates this margin against the observed 15.002s pre-fix timeout reproduction.
const controlReplyMargin = 100 * time.Millisecond

func (d *unixDaemon) authorized(uid uint32) bool {
	if uid == 0 || (d.owner != "" && d.owner == strconv.FormatUint(uint64(uid), 10)) {
		return true
	}
	admin, err := d.admin(uid)
	return err == nil && admin
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

func (d *unixDaemon) handle(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	deadline := time.Now().Add(controlTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return
	}
	uid, err := peerUID(conn)
	if err != nil || !d.authorized(uid) {
		return
	}
	data, err := readFrame(conn)
	if err != nil {
		return
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.Validate() != nil || decoder.Decode(new(any)) != io.EOF {
		return
	}
	// gRPC deadline propagation: preserve the caller's remaining budget. The
	// same-host clock permits an absolute deadline; a client cannot extend ours.
	if !request.Deadline.IsZero() && request.Deadline.Before(deadline) {
		deadline = request.Deadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return
	}
	backend, cancel := context.WithDeadline(ctx, deadline.Add(-controlReplyMargin))
	defer cancel()
	state, err := d.status(backend, request.Verb)
	if err != nil {
		return // No private-state errors, credentials or request bytes on the wire.
	}
	data, err = json.Marshal(state)
	if err == nil {
		_ = writeFrame(conn, data) // Transport failure closes this one-shot request.
	}
}

func callUnix(root string, request Request, serverUID uint32) (Status, error) {
	if err := request.Validate(); err != nil {
		return Status{}, err
	}
	deadline := time.Now().Add(controlTimeout)
	if !request.Deadline.IsZero() && request.Deadline.Before(deadline) {
		deadline = request.Deadline
	}
	request.Deadline = deadline
	conn, err := (&net.Dialer{Deadline: deadline}).Dial("unix", core.MachinePaths(root).Socket)
	if err != nil {
		return Status{}, errors.New("machine control endpoint unavailable")
	}
	defer conn.Close()
	peer, err := peerUID(conn.(*net.UnixConn))
	if err != nil || peer != serverUID {
		return Status{}, errors.New("untrusted machine control server")
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Status{}, err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return Status{}, err
	}
	if err := writeFrame(conn, data); err != nil {
		return Status{}, err
	}
	data, err = readFrame(conn)
	var state Status
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return Status{}, errors.New("invalid control response")
	}
	return state, nil
}

func callNativeUnix(root string, request Request) (Status, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return Status{}, errors.New("invalid machine root")
	}
	if err := validatePublicChain(core.MachinePaths(root).Run, core.ValidateMachinePath); err != nil {
		return Status{}, err
	}
	return callUnix(root, request, 0)
}
