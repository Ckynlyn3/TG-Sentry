//go:build unix

package discovery

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO member is not a regular file. The walk rejects it from the metadata
// alone, before any open, so an unreadable member cannot block the capture
// (fsroot_unix_test.go:59, same nonblocking requirement).
func TestCaptureSkillSnapshotRejectsFIFOMember(t *testing.T) {
	parent := captureTempParent(t)
	r, home := fixtureRoot(t)
	fixtureFile(t, home, captureSkillRoot+"/SKILL.md", []byte("# example\n"))
	if err := syscall.Mkfifo(filepath.Join(home, captureSkillRoot, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	// SKILL.md sorts before pipe, so the good member is copied first and the
	// rejected capture must still leave no snapshot behind.
	captured, reason := r.CaptureSkill(context.Background(), captureSkillRoot)
	requireRejected(t, parent, captured, reason, ReasonNotRegularFile)
}
