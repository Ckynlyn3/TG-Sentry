package discovery

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// HomeRoot owns the acquired home handle. All discovery I/O stays relative to it.
// os.Root confines traversal, not mount points or hard links (go.dev/blog/osroot).
// Callers must Close it after probing and collecting this account.
type HomeRoot struct{ root *os.Root }

// OpenHome acquires before validating: a pathname pre-check would race OpenRoot.
// accountID is the enumerated numeric UID on Unix (SID on Windows).
func OpenHome(homePath, accountID string) (*HomeRoot, HomeState, Reason) {
	root, err := os.OpenRoot(homePath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, HomeDenied, ReasonHomeDenied
		}
		return nil, HomeUnavailable, ReasonHomeUnavailable
	}
	info, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, HomeDenied, ReasonHomeDenied
	}
	if !info.IsDir() || !homeOwnerMatches(info, accountID) {
		_ = root.Close()
		return nil, HomeDenied, ReasonOwnerMismatch
	}
	return &HomeRoot{root: root}, HomeReadable, ""
}

func (r *HomeRoot) Close() error { return r.root.Close() }

// localPath uses the S1 wire-path contract and stdlib platform localization.
// Reject dot-dot components rather than cleaning away their traversal semantics.
func localPath(rel string) (string, Reason) {
	if rel != "." && !validSourcePath(rel) {
		return "", ReasonEscapedRoot
	}
	name, err := filepath.Localize(rel)
	if err != nil {
		return "", ReasonEscapedRoot
	}
	return name, ""
}

func (r *HomeRoot) lstat(ctx context.Context, rel string) (os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, reason := localPath(rel)
	if reason != "" {
		return nil, reason
	}
	return r.root.Lstat(name)
}

// OpenRegular rejects special entries before opening and validates the opened
// handle again. Never use the pre-open Lstat as the asset's metadata.
func (r *HomeRoot) OpenRegular(ctx context.Context, rel string) (*os.File, os.FileInfo, Reason) {
	info, err := r.lstat(ctx, rel)
	if err != nil {
		return nil, nil, fileReason(err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ReasonNotRegularFile
	}
	return r.openRegular(rel)
}

func (r *HomeRoot) openRegular(rel string) (*os.File, os.FileInfo, Reason) {
	f, info, reason := r.open(rel)
	if reason != "" {
		return nil, nil, reason
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, ReasonNotRegularFile
	}
	return f, info, ""
}

func (r *HomeRoot) open(rel string) (*os.File, os.FileInfo, Reason) {
	name, reason := localPath(rel)
	if reason != "" {
		return nil, nil, reason
	}
	f, err := r.root.OpenFile(name, readOnlyFlags(), 0)
	if err != nil {
		return nil, nil, fileReason(err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fileReason(err)
	}
	return f, info, ""
}

// ReadDir bounds work at the filesystem API, not after an unbounded listing.
// DirectoryEntryBudget is the provisional named local budget from plan R7.
// Returned entries are sorted; callers must re-open children through HomeRoot,
// never DirEntry.Info (which can resolve a stale pathname outside the handle).
func (r *HomeRoot) ReadDir(ctx context.Context, rel string) ([]os.DirEntry, Reason) {
	info, err := r.lstat(ctx, rel)
	if err != nil {
		return nil, fileReason(err)
	}
	if !info.IsDir() {
		return nil, ReasonNotRegularFile
	}
	f, info, reason := r.open(rel)
	if reason != "" {
		return nil, reason
	}
	defer f.Close()
	if !info.IsDir() {
		return nil, ReasonNotRegularFile
	}
	entries, err := f.ReadDir(DirectoryEntryBudget + 1)
	if ctx.Err() != nil {
		return nil, ReasonCanceled
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fileReason(err)
	}
	if len(entries) > DirectoryEntryBudget {
		return nil, ReasonTooManyEntries
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, ""
}

// ReadConfig returns local-only bytes for S4 parsers; they never enter Report.
func (r *HomeRoot) ReadConfig(ctx context.Context, rel string) ([]byte, Reason) {
	f, info, reason := r.OpenRegular(ctx, rel)
	if reason != "" {
		return nil, reason
	}
	defer f.Close()
	if info.Size() > ConfigParseBudgetBytes {
		return nil, ReasonTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, ConfigParseBudgetBytes+1))
	if err != nil {
		return nil, fileReason(err)
	}
	if len(data) > ConfigParseBudgetBytes {
		return nil, ReasonTooLarge
	}
	if reason := unchanged(f, info, int64(len(data))); reason != "" {
		return nil, reason
	}
	return data, ""
}

// Reason implements error so lexical/cancellation failures can share the private
// lstat path without exposing OS error strings through exported results.
func (r Reason) Error() string { return string(r) }

func fileReason(err error) Reason {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ReasonCanceled
	}
	if errors.Is(err, ReasonEscapedRoot) {
		return ReasonEscapedRoot
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		// os.errPathEscapes is private. Match its exact fixed sentinel, never a
		// pathname-containing PathError string (Go src/os/file.go, Go 1.27.2).
		if cause.Error() == "path escapes from parent" {
			return ReasonEscapedRoot
		}
	}
	return ReasonUnreadable
}
