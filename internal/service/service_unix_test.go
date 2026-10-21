//go:build darwin || linux

package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"

	"aegishook/internal/core"
)

func TestServiceUnixT4CancellationClosesIdleConnection(t *testing.T) {
	d, root := testDaemon(t)
	d.owner = strconv.Itoa(os.Geteuid())
	if err := d.listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx) }()
	conn, err := net.Dial("unix", core.MachinePaths(root).Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(core.MachinePaths(root).Socket); !os.IsNotExist(err) {
		t.Fatal("socket not removed", err)
	}
}

func TestServiceUnixT4SIGTERM(t *testing.T) {
	if os.Getenv("TG_SENTRY_S3_SIGNAL_CHILD") == "1" {
		d, _ := testDaemon(t)
		if err := d.listen(); err != nil {
			t.Fatal(err)
		}
		ctx, stop := daemonContext()
		defer stop()
		if _, err := os.Stdout.Write([]byte("ready\n")); err != nil {
			t.Fatal(err)
		}
		if err := d.serve(ctx); err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServiceUnixT4SIGTERM$")
	cmd.Env = append(os.Environ(), "TG_SENTRY_S3_SIGNAL_CHILD=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	var ready [6]byte
	if _, err := io.ReadFull(stdout, ready[:]); err != nil || string(ready[:]) != "ready\n" {
		t.Fatalf("%q %v", ready, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal("SIGTERM was not clean", err)
	}
}

func TestServiceUnixRegistrationAndSocketFailures(t *testing.T) {
	d, root := testDaemon(t)
	d.registered = func() error { return errors.New("not registered") }
	if err := d.listen(); err == nil {
		t.Fatal("unregistered daemon accepted")
	}
	d.registered = func() error { return nil }
	if err := os.MkdirAll(core.MachinePaths(root).Run, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(core.MachinePaths(root).Socket, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.listen(); err == nil {
		t.Fatal("foreign socket path replaced")
	}
	if b, _ := os.ReadFile(core.MachinePaths(root).Socket); string(b) != "foreign" {
		t.Fatal("foreign resource modified")
	}
}
