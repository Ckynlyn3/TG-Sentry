package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"time"
)

// FileDigest describes only the opened, stat'd file; no content is retained.
type FileDigest struct {
	Hash  string
	Size  int64
	Mtime time.Time
}

func (r *HomeRoot) HashFile(ctx context.Context, rel string) (FileDigest, Reason) {
	f, info, reason := r.OpenRegular(ctx, rel)
	if reason != "" {
		return FileDigest{}, reason
	}
	defer f.Close()
	return hashOpened(ctx, f, info)
}

// hashOpened never re-opens a pathname: metadata and SHA-256 share one handle.
func hashOpened(ctx context.Context, f *os.File, info os.FileInfo) (FileDigest, Reason) {
	hash := sha256.New()
	n, err := io.Copy(hash, contextReader{ctx, f})
	if err != nil {
		return FileDigest{}, fileReason(err)
	}
	if reason := unchanged(f, info, n); reason != "" {
		return FileDigest{}, reason
	}
	return FileDigest{hex.EncodeToString(hash.Sum(nil)), info.Size(), info.ModTime()}, ""
}

func unchanged(f *os.File, before os.FileInfo, read int64) Reason {
	after, err := f.Stat()
	if err != nil {
		return fileReason(err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		before.Size() != after.Size() || before.Size() != read ||
		!before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		return ReasonChangedDuringRead
	}
	return ""
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	if cancel := r.ctx.Err(); cancel != nil {
		return n, cancel
	}
	return n, err
}
