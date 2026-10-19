//go:build darwin

package service

import (
	"aegishook/internal/core"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestDaemonConfigureIdentityAndFailClosed(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"", account.Uid, account.Username, "tg-sentry-nonexistent-fixture-user"} {
		t.Run(owner, func(t *testing.T) {
			d, root := testDaemon(t)
			data := []byte(`{"owner":` + strconv.Quote(owner) + `}`)
			if err := os.WriteFile(core.MachinePaths(root).Config, data, 0600); err != nil {
				t.Fatal(err)
			}
			err := d.configure()
			if owner == "tg-sentry-nonexistent-fixture-user" {
				if err == nil {
					t.Fatal("unknown owner accepted")
				}
			} else if err != nil || (owner != "" && d.owner != account.Uid) {
				t.Fatalf("owner %q: %s %v", owner, d.owner, err)
			}
		})
	}
	d, root := testDaemon(t)
	if err := os.WriteFile(core.MachinePaths(root).Config, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if d.configure() == nil {
		t.Fatal("invalid config accepted")
	}
	os.Remove(core.MachinePaths(root).Config)
	if d.configure() == nil {
		t.Fatal("missing config accepted")
	}
	d.options.Root = "relative"
	if d.configure() == nil {
		t.Fatal("relative root accepted")
	}
	ctx, cancel := daemonContext()
	cancel()
	if ctx.Err() == nil {
		t.Fatal("signal context was not cancelled")
	}
}

func TestNativeMembershipAndCommandBounds(t *testing.T) {
	// Real Apple membership API wrapper, not a simulated group-list scan.
	if _, err := isDarwinAdmin(uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	var output commandOutput
	if _, err := output.Write(bytes.Repeat([]byte("x"), controlMaxFrame)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("x")); err == nil {
		t.Fatal("unbounded command output")
	}
	if _, err := boundedCommand("/usr/bin/false"); err == nil {
		t.Fatal("command failure ignored")
	}
	if _, err := boundedCommand("/usr/bin/printf", "%s", string(bytes.Repeat([]byte("x"), controlMaxFrame+1))); err == nil {
		t.Fatal("oversize output accepted")
	}
	// No service is installed by this suite. Missing/foreign registration must fail.
	if err := checkLaunchd(); err == nil {
		t.Skip("an installed daemon exists; mutation-free registration failure case not applicable")
	}
}

func TestDaemonListenSafetyAndRecovery(t *testing.T) {
	t.Run("bad-storage", func(t *testing.T) {
		d, _ := testDaemon(t)
		d.options.Root = "relative"
		if d.listen() == nil {
			t.Fatal("invalid storage accepted")
		}
	})
	t.Run("binary-changed", func(t *testing.T) {
		d, _ := testDaemon(t)
		os.WriteFile(d.options.Binary, []byte("tampered"), 0700)
		if d.listen() == nil {
			t.Fatal("tampered binary accepted")
		}
	})
	t.Run("run-link", func(t *testing.T) {
		d, root := testDaemon(t)
		os.Remove(core.MachinePaths(root).Run)
		os.Symlink(filepath.Join(root, "private"), core.MachinePaths(root).Run)
		if d.listen() == nil {
			t.Fatal("symlink run accepted")
		}
	})
	t.Run("stale-socket", func(t *testing.T) {
		d, root := testDaemon(t)
		path := core.MachinePaths(root).Socket
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		listener.Close()
		if err := d.listen(); err != nil {
			t.Fatal(err)
		}
		defer d.close()
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0666 {
			t.Fatalf("socket mode: %v %v", st, err)
		}
		other := *d
		if other.listen() == nil {
			t.Fatal("second daemon acquired socket")
		}
	})
	t.Run("live-and-foreign-socket", func(t *testing.T) {
		_, root := testDaemon(t)
		path := core.MachinePaths(root).Socket
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if removeStaleSocket(path, uint32(os.Geteuid())) == nil {
			t.Fatal("live socket removed")
		}
		if removeStaleSocket(path, uint32(os.Geteuid()+1)) == nil {
			t.Fatal("foreign socket removed")
		}
	})
	t.Run("replacement-retained", func(t *testing.T) {
		d, root := testDaemon(t)
		if err := d.listen(); err != nil {
			t.Fatal(err)
		}
		path := core.MachinePaths(root).Socket
		os.Remove(path)
		os.WriteFile(path, []byte("foreign"), 0600)
		if d.close() == nil {
			t.Fatal("replacement was not reported")
		}
		if data, _ := os.ReadFile(path); string(data) != "foreign" {
			t.Fatal("replacement removed")
		}
	})
}

func TestSocketFrameAndClientErrors(t *testing.T) {
	if _, err := callDarwin("relative", Request{Verb: "status"}); err == nil {
		t.Fatal("relative client root")
	}
	if _, err := Call(t.TempDir(), Request{Verb: "status"}); err == nil {
		t.Fatal("user-controlled server")
	}
	if _, err := callUnix(t.TempDir(), Request{Verb: "status"}, 0); err == nil {
		t.Fatal("missing server")
	}
	if err := writeFrame(io.Discard, nil); err == nil {
		t.Fatal("empty frame")
	}
	if err := writeFrame(io.Discard, bytes.Repeat([]byte("x"), controlMaxFrame+1)); err == nil {
		t.Fatal("oversize frame")
	}
	if err := writeFrame(errorWriter{}, []byte("x")); err == nil {
		t.Fatal("write error ignored")
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fds[1])
	file := os.NewFile(uintptr(fds[0]), "peer")
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if _, err := peerUID(conn.(*net.UnixConn)); err == nil {
		t.Fatal("closed connection identity accepted")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestDaemonStatusRevalidates(t *testing.T) {
	d, root := testDaemon(t)
	d.registered = func() error { return errors.New("registration changed") }
	state, err := d.status(context.Background(), "status")
	if err != nil || state.Service || !state.Installed {
		t.Fatalf("%+v %v", state, err)
	}
	os.WriteFile(d.options.Binary, []byte("tampered"), 0700)
	state, err = d.status(context.Background(), "status")
	if err != nil || state.Installed {
		t.Fatalf("%+v %v", state, err)
	}
	os.Chmod(core.MachinePaths(root).Private, 0755)
	if _, err := d.status(context.Background(), "repair"); err == nil {
		t.Fatal("unsafe private directory accepted")
	}
	if validateDaemonPaths("/", core.ValidateMachinePath) == nil {
		t.Fatal("filesystem root accepted")
	}
	if validateDaemonPaths(filepath.Join(root, "missing"), d.options.ValidatePath) == nil {
		t.Fatal("missing directory accepted")
	}
	if validatePublicChain(d.options.Binary, d.options.ValidatePath) == nil {
		t.Fatal("file ancestor accepted")
	}
}

func TestLaunchdPlistRefusesForeignDefinition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foreign.plist")
	if err := os.WriteFile(path, []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>foreign</string></dict></plist>`), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyLaunchdPlist(path) == nil {
		t.Fatal("foreign registration accepted")
	}
	if verifyLaunchdPlist(path+".missing") == nil {
		t.Fatal("missing registration accepted")
	}
}
