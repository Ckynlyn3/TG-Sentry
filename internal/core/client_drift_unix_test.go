//go:build unix

package core

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestClientDriftNonblockingFIFOOpen(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "fifo")
	driftFIFO(t, path)
	root, err := openDriftRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Exercise the actual O_NONBLOCK open, independently of Lstat's early refusal.
	file, err := openDriftFile(root, "fifo")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil || st.Mode().IsRegular() {
		t.Fatal("FIFO handle must not pass the regular-file guard")
	}
	if _, err := readDriftFile(root, "fifo"); err == nil {
		t.Fatal("FIFO accepted for reading")
	}
}

func TestClientDriftOwnerMismatch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing a fixture directory owner requires Unix root")
	}
	home, _ := driftFixture(t, "claude")
	// A different measured UID, not a hard-coded production identity.
	if err := os.Chown(home, os.Geteuid()+1, -1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chown(home, os.Geteuid(), -1) })
	st, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture owner UID unavailable")
	}
	// Go testing.T.Skip precedent: https://pkg.go.dev/testing#hdr-Skipping (filesystem preconditions).
	if owner.Uid != uint32(os.Geteuid()+1) {
		t.Skip("fixture chown ineffective on this filesystem (e.g. Colima bind mount); ownership-drift precondition unmet")
	}
	report, err := ClientDrift(home)
	if err != nil || report.Manifest != ManifestUnreadable || len(report.Entries) != 0 {
		t.Fatal("foreign-owned home was trusted")
	}
}

func TestClientDriftRootHandleSurvivesPathReplacement(t *testing.T) {
	home := t.TempDir()
	root, err := openDriftRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	driftWrite(t, filepath.Join(home, "probe"), []byte("inside-fixture"))
	outside := t.TempDir()
	driftWrite(t, filepath.Join(outside, "probe"), []byte("outside-fixture"))
	moved := home + "-moved"
	if err := os.Rename(home, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if err := os.Symlink(outside, home); err != nil {
		t.Fatal(err)
	}
	data, err := readDriftFile(root, "probe")
	if err != nil || string(data) != "inside-fixture" {
		t.Fatal("path replacement redirected the held root")
	}
}
