package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// S2 immutable-capture fixtures: synthetic temp trees only (no real skill
// payloads). CaptureSkill writes a real snapshot, so rejected captures are
// proven to leave the snapshot parent empty, and accepted ones are removed by
// their test.

const captureSkillRoot = ".claude/skills/example"

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func captureBody() map[string]string {
	return map[string]string{
		captureSkillRoot + "/SKILL.md":        "# example\n",
		captureSkillRoot + "/scripts/run.sh":  "echo run\n",
		captureSkillRoot + "/assets/data.txt": "payload\n",
	}
}

// captureTempParent isolates the parent CaptureSkill creates its snapshot in, so
// a rejection can be proven to leave nothing on disk. os.TempDir reads TMPDIR on
// every call.
func captureTempParent(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	return parent
}

func requireRejected(t *testing.T, parent string, captured SkillCapture, reason, want Reason) {
	t.Helper()
	if reason != want || captured.Dir != "" || captured.Files != nil {
		t.Fatalf("CaptureSkill = %+v %q, want zero %q", captured, reason, want)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected capture (%s) left %d snapshot entries", want, len(entries))
	}
}

// captureFixture writes the same content in the given creation order, so tests
// can prove the walk order owns the result, not the filesystem listing order.
func captureFixture(t *testing.T, order []string) (*HomeRoot, map[string]string) {
	t.Helper()
	body := captureBody()
	r, home := fixtureRoot(t)
	for _, rel := range order {
		fixtureFile(t, home, rel, []byte(body[rel]))
	}
	return r, body
}

func memberPath(skillRel string) string {
	return strings.TrimPrefix(skillRel, captureSkillRoot+"/")
}

func TestCaptureSkillSnapshotCompleteMembership(t *testing.T) {
	body := captureBody()
	order := []string{
		captureSkillRoot + "/scripts/run.sh",
		captureSkillRoot + "/SKILL.md",
		captureSkillRoot + "/assets/data.txt",
	}
	r, _ := captureFixture(t, order)
	captured, reason := r.CaptureSkill(context.Background(), captureSkillRoot)
	if reason != "" {
		t.Fatalf("CaptureSkill reason = %q", reason)
	}
	defer os.RemoveAll(captured.Dir)

	// The captured membership is exactly the declared tree, hashed
	// independently here from the known bytes.
	want := map[string]string{}
	for skillRel, data := range body {
		want[memberPath(skillRel)] = sha256Hex(data)
	}
	if !reflect.DeepEqual(captured.Files, want) {
		t.Fatalf("Files = %v, want %v", captured.Files, want)
	}
	// The snapshot holds the exact bytes the hashes were taken from.
	for skillRel, data := range body {
		got, err := os.ReadFile(filepath.Join(captured.Dir, filepath.FromSlash(memberPath(skillRel))))
		if err != nil || string(got) != data {
			t.Fatalf("snapshot %s = %q %v, want %q", skillRel, got, err, data)
		}
	}
}

func TestCaptureSkillSnapshotOrderDeterministic(t *testing.T) {
	forward, _ := captureFixture(t, []string{
		captureSkillRoot + "/SKILL.md",
		captureSkillRoot + "/scripts/run.sh",
		captureSkillRoot + "/assets/data.txt",
	})
	reverse, _ := captureFixture(t, []string{
		captureSkillRoot + "/assets/data.txt",
		captureSkillRoot + "/scripts/run.sh",
		captureSkillRoot + "/SKILL.md",
	})
	first, reason := forward.CaptureSkill(context.Background(), captureSkillRoot)
	if reason != "" {
		t.Fatal(reason)
	}
	defer os.RemoveAll(first.Dir)
	again, reason := forward.CaptureSkill(context.Background(), captureSkillRoot)
	if reason != "" {
		t.Fatal(reason)
	}
	defer os.RemoveAll(again.Dir)
	last, reason := reverse.CaptureSkill(context.Background(), captureSkillRoot)
	if reason != "" {
		t.Fatal(reason)
	}
	defer os.RemoveAll(last.Dir)
	if !reflect.DeepEqual(first.Files, again.Files) || !reflect.DeepEqual(first.Files, last.Files) {
		t.Fatalf("membership depends on capture/creation order: %v %v %v", first.Files, again.Files, last.Files)
	}
}

func TestCaptureSkillSnapshotRejectsEscapedPaths(t *testing.T) {
	parent := captureTempParent(t)
	r, home := fixtureRoot(t)
	outside := t.TempDir()
	fixtureFile(t, outside, "secret", []byte("OUTSIDE_SENTINEL"))
	fixtureFile(t, home, "SKILL.md", []byte("# inside\n"))
	if err := os.Symlink(outside, filepath.Join(home, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		rel  string
		want Reason
	}{
		{"symlink to directory is not a skill root", "escape", ReasonNotRegularFile},
		{"path through symlink escapes", "escape/secret", ReasonEscapedRoot},
		{"dot dot", "../secret", ReasonEscapedRoot},
		{"nested dot dot", "a/../../secret", ReasonEscapedRoot},
		{"absolute", outside + "/secret", ReasonEscapedRoot},
		{"regular file is not a skill root", "SKILL.md", ReasonNotRegularFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captured, reason := r.CaptureSkill(context.Background(), tc.rel)
			requireRejected(t, parent, captured, reason, tc.want)
		})
	}
}

// A symlink inside the root is rejected on its own, whether it points outside
// the root or at a sibling member: os.Root would follow it (pkg.go.dev/os#Root)
// and the snapshot must not carry a link as a member.
func TestCaptureSkillSnapshotRejectsSymlinks(t *testing.T) {
	outside := t.TempDir()
	fixtureFile(t, outside, "secret", []byte("OUTSIDE_SENTINEL"))
	for _, tc := range []struct {
		name   string
		link   string
		target func(home string) string
	}{
		{"link to outside", "link", func(home string) string {
			return filepath.Join(outside, "secret")
		}},
		{"self link to sibling member", "self", func(home string) string {
			return filepath.Join(home, captureSkillRoot, "SKILL.md")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := captureTempParent(t)
			r, home := fixtureRoot(t)
			fixtureFile(t, home, captureSkillRoot+"/SKILL.md", []byte("# example\n"))
			if err := os.Symlink(tc.target(home), filepath.Join(home, captureSkillRoot, tc.link)); err != nil {
				t.Fatal(err)
			}
			// The walk captures SKILL.md first and only then meets the link: an
			// incomplete capture is never returned as a partial one.
			captured, reason := r.CaptureSkill(context.Background(), captureSkillRoot)
			requireRejected(t, parent, captured, reason, ReasonNotRegularFile)
		})
	}
}

// Names the capture must refuse because they cannot be subject members:
// supply_chain.go:107-109 rejects LF, CR, backslash and drive prefixes, and
// report.go:285 rejects the drive prefix. A capture that accepted one would
// succeed and then fail to bind.
func TestCaptureSkillSnapshotRejectsUnrepresentableNames(t *testing.T) {
	for _, name := range []string{"line\nbreak", "carriage\rreturn", "C:drive", "back\\slash"} {
		t.Run(strings.ReplaceAll(name, "\n", "\\n"), func(t *testing.T) {
			parent := captureTempParent(t)
			r, home := fixtureRoot(t)
			fixtureFile(t, home, captureSkillRoot+"/SKILL.md", []byte("# example\n"))
			fixtureFile(t, home, captureSkillRoot+"/"+name, []byte("member\n"))
			captured, reason := r.CaptureSkill(context.Background(), captureSkillRoot)
			requireRejected(t, parent, captured, reason, ReasonEscapedRoot)
		})
	}
}

func TestCaptureSkillSnapshotCanceledLeavesNoSnapshot(t *testing.T) {
	parent := captureTempParent(t)
	r, _ := captureFixture(t, []string{captureSkillRoot + "/SKILL.md"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	captured, reason := r.CaptureSkill(ctx, captureSkillRoot)
	requireRejected(t, parent, captured, reason, ReasonCanceled)
}

func TestCaptureSkillSnapshotRejectsOversizedMember(t *testing.T) {
	parent := captureTempParent(t)
	r, home := fixtureRoot(t)
	fixtureFile(t, home, captureSkillRoot+"/SKILL.md", []byte("# example\n"))
	fixtureFile(t, home, captureSkillRoot+"/big.bin", []byte(strings.Repeat("x", ConfigParseBudgetBytes+1)))
	captured, reason := r.CaptureSkill(context.Background(), captureSkillRoot)
	requireRejected(t, parent, captured, reason, ReasonTooLarge)
}

// captureHandle is the same-handle seam: a member changed between the open stat
// and the read pass is rejected. No sleeps and no other writer; the test mutates
// the pathname after the handle and its metadata were taken, mirroring
// TestHashDetectsChangedHandle.
func TestCaptureSnapshotHandleDetectsChangedMember(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, "asset", []byte("before"))
	f, info, reason := r.openRegular("asset")
	if reason != "" {
		t.Fatal(reason)
	}
	defer f.Close()
	if err := os.Truncate(filepath.Join(home, "asset"), 0); err != nil {
		t.Fatal(err)
	}
	hash, reason := captureHandle(context.Background(), f, info, filepath.Join(t.TempDir(), "copy"))
	if reason != ReasonChangedDuringRead || hash != "" {
		t.Fatalf("captureHandle = %q %q, want %q", hash, reason, ReasonChangedDuringRead)
	}
}

// A member that grows past the cap after its initial stat is rejected during the
// copy, not copied unbounded and not truncated (fsroot.go:126-141).
func TestCaptureSnapshotHandleRejectsGrowthPastCap(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, "asset", []byte("small"))
	f, info, reason := r.openRegular("asset")
	if reason != "" {
		t.Fatal(reason)
	}
	defer f.Close()
	fixtureFile(t, home, "asset", []byte(strings.Repeat("x", ConfigParseBudgetBytes)+"growth"))
	dst := filepath.Join(t.TempDir(), "copy")
	hash, reason := captureHandle(context.Background(), f, info, dst)
	if reason != ReasonTooLarge || hash != "" {
		t.Fatalf("captureHandle = %q %q, want %q", hash, reason, ReasonTooLarge)
	}
	copied, err := os.Stat(dst)
	if err != nil || copied.Size() != captureMemberMaxBytes+1 {
		t.Fatalf("overflow copied beyond cap+1: %v %v", copied, err)
	}
}

// Err observes the real copy at chunk boundaries, just like contextReader's
// existing readFunc seam. It injects cancellation only after bytes reach disk.
type captureContext struct {
	context.Context
	check func()
}

func (c captureContext) Err() error {
	c.check()
	return c.Context.Err()
}

func TestCaptureSkillSnapshotCanceledAfterPartialCopy(t *testing.T) {
	parent := captureTempParent(t)
	r, home := fixtureRoot(t)
	fixtureFile(t, home, captureSkillRoot+"/SKILL.md", []byte(strings.Repeat("x", ConfigParseBudgetBytes)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var partial int64
	observed := captureContext{ctx, func() {
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			info, err := os.Stat(filepath.Join(parent, entry.Name(), "SKILL.md"))
			if err == nil && info.Size() > 0 && info.Size() < ConfigParseBudgetBytes {
				partial = info.Size()
				cancel()
			}
		}
	}}
	captured, reason := r.CaptureSkill(observed, captureSkillRoot)
	requireRejected(t, parent, captured, reason, ReasonCanceled)
	if partial == 0 {
		t.Fatal("cancellation did not observe a partial snapshot copy")
	}
}

// Check-to-open replacement regression: captureMember is the seam where a writer
// could swap the checked entry for a relative, inside-root symlink. The checked
// metadata is taken first, the swap happens, then the production open path runs:
// the handle is a different object and the whole capture is refused.
func TestCaptureSkillSnapshotRejectsSwappedMember(t *testing.T) {
	parent := captureTempParent(t)
	r, home := fixtureRoot(t)
	fixtureFile(t, home, captureSkillRoot+"/SKILL.md", []byte("# example\n"))
	fixtureFile(t, home, captureSkillRoot+"/run.sh", []byte("echo run\n"))
	ctx := context.Background()
	checked, err := r.lstat(ctx, captureSkillRoot+"/run.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Keep the checked inode alive but point at a distinct inside-root object.
	// A link back to moved.sh would still be the checked inode (FIO45-C ceiling).
	fixtureFile(t, home, captureSkillRoot+"/target.sh", []byte("echo target\n"))
	if err := os.Rename(filepath.Join(home, captureSkillRoot, "run.sh"), filepath.Join(home, captureSkillRoot, "moved.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.sh", filepath.Join(home, captureSkillRoot, "run.sh")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string]string{}
	if reason := r.captureMember(ctx, captureSkillRoot+"/run.sh", "run.sh", checked, dir, files); reason != ReasonChangedDuringRead {
		t.Fatalf("captureMember = %q, want %q", reason, ReasonChangedDuringRead)
	}
	if len(files) != 0 {
		t.Fatalf("swapped member was captured: %v", files)
	}
	// The tree-level capture of the swapped entry is refused as well.
	captured, reason := r.CaptureSkill(ctx, captureSkillRoot)
	requireRejected(t, parent, captured, reason, ReasonNotRegularFile)
}

// The existing directory-listing budget also applies to capture, with cleanup.
func TestCaptureSkillSnapshotRejectsTooManyEntries(t *testing.T) {
	parent := captureTempParent(t)
	r, home := fixtureRoot(t)
	for i := range DirectoryEntryBudget + 1 {
		fixtureFile(t, home, fmt.Sprintf("%s/%04d", captureSkillRoot, i), nil)
	}
	captured, reason := r.CaptureSkill(context.Background(), captureSkillRoot)
	requireRejected(t, parent, captured, reason, ReasonTooManyEntries)
}

func TestCaptureSnapshotHandleAcceptsExactCap(t *testing.T) {
	r, home := fixtureRoot(t)
	data := strings.Repeat("x", ConfigParseBudgetBytes)
	fixtureFile(t, home, "asset", []byte(data))
	f, info, reason := r.openRegular("asset")
	if reason != "" {
		t.Fatal(reason)
	}
	defer f.Close()
	dst := filepath.Join(t.TempDir(), "copy")
	hash, reason := captureHandle(context.Background(), f, info, dst)
	if reason != "" || hash != sha256Hex(data) {
		t.Fatalf("exact cap = %q %q", hash, reason)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != data {
		t.Fatalf("exact cap snapshot differs: %v", err)
	}
}

// Both a skill root and a descended directory must compare their checked object
// to the opened handle. The seam swaps the path after lstat and before open.
func TestCaptureSkillSnapshotRejectsSwappedDirectories(t *testing.T) {
	for _, member := range []string{"", "scripts"} {
		t.Run(member, func(t *testing.T) {
			parent := captureTempParent(t)
			r, home := fixtureRoot(t)
			fixtureFile(t, home, captureSkillRoot+"/scripts/run.sh", []byte("echo run\n"))
			fixtureFile(t, home, "target/asset", []byte("target\n"))
			rel := captureSkillRoot
			if member != "" {
				rel += "/" + member
			}
			checked, err := r.lstat(context.Background(), rel)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(home, rel), filepath.Join(home, "original")); err != nil {
				t.Fatal(err)
			}
			target, err := filepath.Rel(filepath.Dir(filepath.Join(home, rel)), filepath.Join(home, "target"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(home, rel)); err != nil {
				t.Fatal(err)
			}
			f, reason := r.openedSameFile(rel, checked, func(info os.FileInfo) bool { return info.IsDir() })
			if f != nil {
				_ = f.Close()
			}
			if f != nil || reason != ReasonChangedDuringRead {
				t.Fatalf("swapped directory = %v %q", f, reason)
			}
			captured, reason := r.CaptureSkill(context.Background(), captureSkillRoot)
			requireRejected(t, parent, captured, reason, ReasonNotRegularFile)
		})
	}
}
