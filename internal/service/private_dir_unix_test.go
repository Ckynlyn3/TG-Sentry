//go:build darwin || linux

package service

import (
	"aegishook/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateDirUnixT2FailsClosedForUnprivilegedTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary-user case requires non-root; root denial belongs to Gate B")
	}
	d, root := testDaemon(t)
	if err := validateDaemonPaths(root, core.ValidateMachinePath); err == nil {
		t.Fatal("user-owned destination accepted")
	}
	for _, name := range []string{"setup-code", "enrolled.json", "adapter/connection.json", "rollback/temp"} {
		path := filepath.Join(core.MachinePaths(root).Private, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := core.ValidateMachinePath(path, true); err == nil {
			t.Fatalf("user-owned secret accepted: %s", name)
		}
	}
	if err := d.validate(); err != nil {
		t.Fatal("isolated test validator", err)
	}
}

func TestPrivateDirUnixT2SymlinkAndPublicSecret(t *testing.T) {
	d, root := testDaemon(t)
	path := filepath.Join(core.MachinePaths(root).Private, "setup-code")
	if err := os.Symlink(filepath.Join(root, "aegishook"), path); err != nil {
		t.Fatal(err)
	}
	if err := d.validate(); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := d.validate(); err == nil {
		t.Fatal("world-readable secret accepted")
	}
}

func TestPrivateDirUnixT2ProductionEntryPointRefusesUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary user")
	}
	if err := Run(t.TempDir()); err == nil {
		t.Fatal("ordinary user started production daemon")
	}
}
