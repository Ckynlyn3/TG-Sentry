//go:build windows

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A directory symlink is a Windows reparse point. This native fixture is not
// exercised by cross-vet; it requires a Windows runner with symlink privileges.
func TestWindowsReparseEscape(t *testing.T) {
	r, home := fixtureRoot(t)
	outside := t.TempDir()
	fixtureFile(t, outside, "secret", []byte("OUTSIDE_SENTINEL"))
	if err := os.Symlink(outside, filepath.Join(home, "reparse")); err != nil {
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	if data, reason := r.ReadConfig(context.Background(), "reparse/secret"); data != nil || reason != ReasonEscapedRoot {
		t.Fatalf("ReadConfig = %q %q", data, reason)
	}
	if _, reason := r.HashFile(context.Background(), "reparse/secret"); reason != ReasonEscapedRoot {
		t.Fatal(reason)
	}
}
