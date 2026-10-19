//go:build unix

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestHomeOwnerMismatchAfterReplacement(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(home, home+".old"); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.Symlink(other, home); err != nil {
		t.Fatal(err)
	}
	// Inject the enumerated UID, not the ownership check or Root operations.
	// This also exercises rejection without requiring chown privileges.
	r, state, reason := OpenHome(home, strconv.Itoa(os.Getuid()+1))
	if r != nil || state != HomeDenied || reason != ReasonOwnerMismatch {
		t.Fatalf("OpenHome = %v %v %q", r, state, reason)
	}
	if r, state, reason = OpenHome(home, "invalid-uid"); r != nil || state != HomeDenied || reason != ReasonOwnerMismatch {
		t.Fatalf("invalid UID OpenHome = %v %v %q", r, state, reason)
	}
}

func TestRenameDirectoryToEscapeBetweenProbeAndOpen(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, "dir/asset", []byte("inside"))
	outside := t.TempDir()
	fixtureFile(t, outside, "asset", []byte("OUTSIDE_SENTINEL"))
	if _, err := r.root.Lstat("dir/asset"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(home, "dir"), filepath.Join(home, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "dir")); err != nil {
		t.Fatal(err)
	}
	// openRegular is the actual nonblocking Root.OpenFile + handle-stat step.
	f, _, reason := r.openRegular("dir/asset")
	if f != nil || reason != ReasonEscapedRoot {
		t.Fatalf("openRegular = %v %q", f, reason)
	}
}

func TestFIFOAndDirectoryReplacementDoNotBlock(t *testing.T) {
	r, home := fixtureRoot(t)
	fifo := filepath.Join(home, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, reason := r.HashFile(context.Background(), "fifo"); reason != ReasonNotRegularFile {
		t.Fatal(reason)
	}
	// Simulate a regular-file Lstat racing a replacement with a real FIFO.
	// Call the exact production open step; without O_NONBLOCK this hangs.
	f, _, reason := r.openRegular("fifo")
	if f != nil || reason != ReasonNotRegularFile {
		t.Fatalf("FIFO openRegular = %v %q", f, reason)
	}
	f, _, reason = r.openRegular(".")
	if f != nil || reason != ReasonNotRegularFile {
		t.Fatalf("directory openRegular = %v %q", f, reason)
	}
}

func TestUnreadableFileAndHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged execution; run the nonroot gate")
	}
	r, home := fixtureRoot(t)
	fixtureFile(t, home, "secret", []byte("SENTINEL"))
	if err := os.Chmod(filepath.Join(home, "secret"), 0); err != nil {
		t.Fatal(err)
	}
	if _, reason := r.ReadConfig(context.Background(), "secret"); reason != ReasonUnreadable {
		t.Fatal(reason)
	}
	denied := t.TempDir()
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0700) })
	root, state, reason := OpenHome(denied, strconv.Itoa(os.Getuid()))
	if root != nil || state != HomeDenied || reason != ReasonHomeDenied {
		t.Fatalf("OpenHome = %v %v %q", root, state, reason)
	}
}
