//go:build darwin || linux

package service

import (
	"aegishook/internal/core"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func testDaemon(t *testing.T) (*unixDaemon, string) {
	t.Helper()
	// Darwin sockaddr_un has a short pathname; use a private short child of
	// the existing system test directory, never a production application path.
	root, err := os.MkdirTemp("", "s3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(root, "aegishook")
	if err := os.WriteFile(binaryPath, []byte("isolated fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	validate := func(path string, private bool) error {
		// Only tests inject storage validation; production always uses S1's
		// root-owned FIO15-C validator. Still reject links and unsafe modes.
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 || (!st.IsDir() && !st.Mode().IsRegular()) {
			return errors.New("unsafe fixture")
		}
		if private && st.Mode().Perm()&0077 != 0 {
			return errors.New("public fixture")
		}
		return nil
	}
	o := core.MachineOptions{Root: root, Binary: binaryPath, NoCommit: true, ValidatePath: validate}
	if _, err := core.MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	d := &unixDaemon{options: o, registered: func() error { return nil }, admin: func(uint32) (bool, error) { return false, nil }, uid: uint32(os.Geteuid())}
	return d, root
}

func startTestDaemon(t *testing.T, d *unixDaemon) {
	t.Helper()
	if err := d.listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func TestEndpointUnixT3KernelPeerAndOwner(t *testing.T) {
	d, root := testDaemon(t)
	d.owner = strconv.Itoa(os.Geteuid())
	startTestDaemon(t, d)
	state, err := callUnix(root, Request{Verb: "status"}, d.uid)
	if err != nil || !state.Installed || !state.Service || state.Enrolled || state.Loaded != "unknown" {
		t.Fatalf("%+v %v", state, err)
	}
	if state.ExitCode("enrolled") != ExitNotEnrolled {
		t.Fatal(state)
	}
	if _, err := callUnix(root, Request{Verb: "install"}, d.uid); err == nil {
		t.Fatal("install accepted")
	}
	if _, err := callUnix(root, Request{Verb: "status"}, d.uid+1); err == nil {
		t.Fatal("untrusted server accepted")
	}
}

func TestEndpointUnixT3Authorization(t *testing.T) {
	for _, tc := range []struct {
		name, owner string
		uid         uint32
		admin       bool
		err         error
		want        bool
	}{
		{"root", "", 0, false, nil, true},
		{"owner", "501", 501, false, nil, true},
		{"administrator", "502", 501, true, nil, true},
		{"non-owner", "502", 501, false, nil, false},
		{"missing-owner-admin", "", 501, true, nil, true},
		{"missing-owner-user", "", 501, false, nil, false},
		{"lookup-failure", "502", 501, true, errors.New("lookup failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := unixDaemon{owner: tc.owner, admin: func(uint32) (bool, error) { return tc.admin, tc.err }}
			if got := d.authorized(tc.uid); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestEndpointUnixT3DeniedBeforeRequest(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary-user denial does not apply to an authorized root peer")
	}
	d, root := testDaemon(t)
	startTestDaemon(t, d)
	if _, err := callUnix(root, Request{Verb: "repair"}, d.uid); err == nil {
		t.Fatal("non-owner accepted")
	}
	if _, err := os.Stat(core.MachinePaths(root).Rollback); err != nil {
		t.Fatal("denied repair changed transaction", err)
	}
}

func TestEndpointUnixT3MalformedFrames(t *testing.T) {
	d, root := testDaemon(t)
	d.owner = strconv.Itoa(os.Geteuid())
	startTestDaemon(t, d)
	for _, payload := range [][]byte{nil, []byte("{"), []byte(`{"verb":"install"}`), []byte(`{"verb":"status","uid":0}`), []byte(`{"verb":"status"} {}`)} {
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: core.MachinePaths(root).Socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if payload == nil {
			if err := binary.Write(conn, binary.BigEndian, uint32(0)); err != nil {
				t.Fatal(err)
			}
		} else if err := writeFrame(conn, payload); err != nil {
			t.Fatal(err)
		}
		if _, err := readFrame(conn); err == nil {
			t.Fatal("malformed request accepted", string(payload))
		}
		conn.Close()
	}
	var oversize bytes.Buffer
	binary.Write(&oversize, binary.BigEndian, uint32(controlMaxFrame+1))
	if _, err := readFrame(&oversize); err == nil {
		t.Fatal("oversize frame accepted")
	}
	var framed bytes.Buffer
	want, _ := json.Marshal(Request{Verb: "status"})
	if err := writeFrame(&framed, want); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&framed)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%q %v", got, err)
	}
}

func TestEndpointUnixT9IntegratedStatusAndRepairPending(t *testing.T) {
	d, root := testDaemon(t)
	d.owner = strconv.Itoa(os.Geteuid())
	startTestDaemon(t, d)
	state, err := callUnix(root, Request{Verb: "repair"}, d.uid)
	if err != nil || state.ExitCode("service") != ExitOK || state.ExitCode("enrolled") != ExitNotEnrolled {
		t.Fatalf("%+v %v", state, err)
	}
	if _, err := os.Stat(core.MachinePaths(root).Rollback); err != nil {
		t.Fatal("pending snapshot was collected", err)
	}
	if _, err := os.Stat(filepath.Join(core.MachinePaths(root).Rollback, ".committed")); !os.IsNotExist(err) {
		t.Fatal("repair implicitly committed")
	}
}
