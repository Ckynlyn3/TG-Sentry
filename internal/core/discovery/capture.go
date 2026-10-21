package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// S2 immutable capture (plan §3 "Hash-bound results" and "Anti-forgery and
// TOCTOU boundary"). One skill package is acquired before any scanner runs: the
// complete declared membership under the skill root is copied into a snapshot
// directory and hashed in the same single read per member, so the bytes a
// scanner will see and the digests that bind them can never describe two reads.
//
// discovery/v1 stays metadata-only: this adds no Report or Category field, and
// CollectSkills (collect_skills.go) keeps hashing only SKILL.md.
//
// discovery cannot return core.SupplyChainSubject: core imports discovery
// (discovery_client.go), and an in-package test that imports core is rejected as
// an import cycle. The caller binds Captured.Files with
// core.NewSupplyChainSubject (supply_chain.go), which computes the membership
// digest over exactly this map.
//
// Acquisition is confined and identity-checked: os.Root confines traversal but
// follows in-root symbolic links. Capture rejects checked links and compares the
// lstat identity with the opened handle (SEI CERT FIO45-C, POSIX solution):
// https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/input-output-fio/fio45-c
// This does not prove that a path stayed link-free: a replacement link back to
// the checked inode passes SameFile. Hardlink provenance is also out of scope
// (fsroot.go:13-14); this is not a native no-follow-open guarantee.

// SkillCapture is one complete capture: relative member path -> SHA-256 of the
// captured bytes, plus the directory that holds those exact bytes. The caller
// owns Dir and must remove it.
type SkillCapture struct {
	Files map[string]string
	Dir   string
}

// Named local exception, not a measured whole-package ceiling. Plan §3 requires
// documented precedent or measurement before a resource ceiling is enforced, and
// states that existing discovery limits are local exceptions, not automatically
// appropriate for whole-package scanning. This reuses the existing 2 MiB
// config-parse budget (report.go:22, plan R7) as a per-member read cap only.
// There is deliberately no whole-capture byte or member-count budget: one member
// is in memory at a time, the snapshot is written to disk, and per-directory
// listings are already bounded by DirectoryEntryBudget.
const captureMemberMaxBytes = ConfigParseBudgetBytes

// CaptureSkill acquires the complete declared membership under skillRel into a
// fresh temp snapshot directory. Every entry is re-lstat'd through the acquired
// root, so a symlink, a special file, a path that escapes the root, an
// unrepresentable name, an oversized member, a member replaced between its check
// and its open, or a member changed during its read fails the whole capture: a
// partial or unverifiable capture is never returned, and its snapshot is removed.
// A capture that finds no member at all returns an empty membership, which
// NewSupplyChainSubject rejects.
func (r *HomeRoot) CaptureSkill(ctx context.Context, skillRel string) (SkillCapture, Reason) {
	if err := ctx.Err(); err != nil {
		return SkillCapture{}, ReasonCanceled
	}
	dir, err := os.MkdirTemp("", "tg-sentry-skill-capture-")
	if err != nil {
		return SkillCapture{}, fileReason(err)
	}
	files := map[string]string{}
	if reason := r.captureTree(ctx, skillRel, "", dir, files); reason != "" {
		// Drop every partial copy with the rejected capture.
		_ = os.RemoveAll(dir)
		return SkillCapture{}, reason
	}
	return SkillCapture{Files: files, Dir: dir}, ""
}

// captureTree walks one directory of the membership. rel is root-relative (the
// wire path), member is the path inside the skill and inside the snapshot.
func (r *HomeRoot) captureTree(ctx context.Context, rel, member, dir string, files map[string]string) Reason {
	f, reason := r.openCaptureDir(ctx, rel)
	if reason != "" {
		return reason
	}
	// Listing budget and sort order are the ones HomeRoot.ReadDir applies
	// (fsroot.go:108-139); this handle is the one just identity-checked.
	entries, err := f.ReadDir(DirectoryEntryBudget + 1)
	_ = f.Close()
	if ctx.Err() != nil {
		return ReasonCanceled
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fileReason(err)
	}
	if len(entries) > DirectoryEntryBudget {
		return ReasonTooManyEntries
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	for _, entry := range entries {
		child := path.Join(rel, entry.Name())
		memberPath := path.Join(member, entry.Name())
		// Member paths are wire paths (report.go validSourcePath) plus the
		// characters the subject contract additionally rejects (supply_chain.go:107-109).
		if !captureMemberPath(memberPath) {
			return ReasonEscapedRoot
		}
		checked, err := r.lstat(ctx, child)
		if err != nil {
			return fileReason(err)
		}
		if checked.Mode()&os.ModeSymlink != 0 {
			return ReasonNotRegularFile
		}
		switch {
		case checked.IsDir():
			if reason := r.captureTree(ctx, child, memberPath, dir, files); reason != "" {
				return reason
			}
		case checked.Mode().IsRegular():
			if reason := r.captureMember(ctx, child, memberPath, checked, dir, files); reason != "" {
				return reason
			}
		default:
			return ReasonNotRegularFile
		}
	}
	return ""
}

// captureMemberPath is the discovery/v1 source-path rule (report.go:285) plus LF
// and CR, which the supply-chain subject rejects (supply_chain.go:107-109), so a
// successful capture can never hold membership NewSupplyChainSubject refuses.
func captureMemberPath(member string) bool {
	return validSourcePath(member) && !strings.ContainsAny(member, "\n\r")
}

// openCaptureDir opens one directory after confirming that the handle is the
// very object lstat inspected. os.Root follows symbolic links inside the root,
// so without this compare a pathname swapped for an in-root relative symlink
// between the check and the open could substitute a different directory. The
// lstat→open→fstat compare rejects that substitution (FIO45-C POSIX solution);
// it retains the same-inode ceiling documented above.
func (r *HomeRoot) openCaptureDir(ctx context.Context, rel string) (*os.File, Reason) {
	checked, err := r.lstat(ctx, rel)
	if err != nil {
		return nil, fileReason(err)
	}
	if checked.Mode()&os.ModeSymlink != 0 || !checked.IsDir() {
		return nil, ReasonNotRegularFile
	}
	return r.openedSameFile(rel, checked, func(info os.FileInfo) bool { return info.IsDir() })
}

// captureMember opens the member once through the confined root and hashes the
// bytes it copies out of that same handle, which must be the object the walk
// checked.
func (r *HomeRoot) captureMember(ctx context.Context, rel, member string, checked os.FileInfo, dir string, files map[string]string) Reason {
	f, info, reason := r.openRegular(rel)
	if reason != "" {
		return reason
	}
	// openRegular already required a regular handle; this requires the checked
	// object itself (see openCaptureDir).
	if !os.SameFile(checked, info) || !info.Mode().IsRegular() {
		_ = f.Close()
		return ReasonChangedDuringRead
	}
	dst := filepath.Join(dir, filepath.FromSlash(member))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		_ = f.Close()
		return fileReason(err)
	}
	hash, reason := captureHandle(ctx, f, info, dst)
	_ = f.Close()
	if reason != "" {
		return reason
	}
	files[member] = hash
	return ""
}

// openedSameFile opens rel and rejects it unless the handle is the object
// checked inspected and satisfies want. A pathname replaced between the two is
// indistinguishable from a changed member, so it shares that Reason.
func (r *HomeRoot) openedSameFile(rel string, checked os.FileInfo, want func(os.FileInfo) bool) (*os.File, Reason) {
	f, info, reason := r.open(rel)
	if reason != "" {
		return nil, reason
	}
	if !os.SameFile(checked, info) || !want(info) {
		_ = f.Close()
		return nil, ReasonChangedDuringRead
	}
	return f, ""
}

// captureHandle is the same-handle seam, mirroring hashOpened (hash.go:26): one
// read pass feeds the snapshot copy and the SHA-256 together, and the before and
// after metadata come from that same handle, so pathname replacement cannot
// substitute an object. before must be the metadata of f.
//
// The pass is bounded by the member cap exactly as ReadConfig bounds a config
// read (fsroot.go:142-162): a member that grew after the initial stat is
// rejected instead of being copied unboundedly or silently truncated.
//
// Ceiling, stated rather than hidden (plan §3 "Anti-forgery and TOCTOU
// boundary"): a member rewritten in place between the before and after stats
// with identical size and mtime is not detected. The snapshot and its digest
// still describe the same bytes, because both come from this one pass; the
// remaining exposure is that the captured bytes may be a mixture, and a
// compromised endpoint can always make this contract untrue.
func captureHandle(ctx context.Context, f *os.File, before os.FileInfo, dst string) (string, Reason) {
	if before.Size() > captureMemberMaxBytes {
		return "", ReasonTooLarge
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fileReason(err)
	}
	hash := sha256.New()
	read, err := io.Copy(io.MultiWriter(hash, out), contextReader{ctx, io.LimitReader(f, captureMemberMaxBytes+1)})
	if err == nil {
		err = out.Close()
	} else {
		_ = out.Close()
	}
	if err != nil {
		return "", fileReason(err)
	}
	if read > captureMemberMaxBytes {
		return "", ReasonTooLarge
	}
	if reason := unchanged(f, before, read); reason != "" {
		return "", reason
	}
	return hex.EncodeToString(hash.Sum(nil)), ""
}
