package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func fixtureRoot(t *testing.T) (*HomeRoot, string) {
	t.Helper()
	home := t.TempDir()
	r, state, reason := OpenHome(home, strconv.Itoa(os.Getuid()))
	if state != HomeReadable || reason != "" || r == nil {
		t.Fatalf("OpenHome = %v %q", state, reason)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, home
}

func fixtureFile(t *testing.T, home, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenHomeMissingAndFile(t *testing.T) {
	home := t.TempDir()
	fixtureFile(t, home, "file", nil)
	for _, p := range []string{"missing", "file"} {
		r, state, reason := OpenHome(filepath.Join(home, p), strconv.Itoa(os.Getuid()))
		if r != nil || state != HomeUnavailable || reason != ReasonHomeUnavailable {
			t.Fatalf("%s: %v %v %q", p, r, state, reason)
		}
	}
}

func TestConfinedReadRejectsTraversalAndSpecialEntries(t *testing.T) {
	r, home := fixtureRoot(t)
	outside := t.TempDir()
	fixtureFile(t, outside, "secret", []byte("OUTSIDE_SENTINEL"))
	if err := os.Symlink(outside, filepath.Join(home, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want Reason
	}{
		{"escape/secret", ReasonEscapedRoot}, {"../secret", ReasonEscapedRoot},
		{"a/../../secret", ReasonEscapedRoot}, {outside + "/secret", ReasonEscapedRoot},
		{"link", ReasonNotRegularFile}, {"directory", ReasonNotRegularFile},
		{"missing", ReasonUnreadable}, {"C:\\secret", ReasonEscapedRoot},
	} {
		t.Run(tc.path, func(t *testing.T) {
			data, reason := r.ReadConfig(context.Background(), tc.path)
			if reason != tc.want || data != nil {
				t.Fatalf("ReadConfig = %q %q, want nil %q", data, reason, tc.want)
			}
		})
	}
}

func TestDirectoryBudgetBoundaries(t *testing.T) {
	for _, count := range []int{DirectoryEntryBudget, DirectoryEntryBudget + 1} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			r, home := fixtureRoot(t)
			for i := range count {
				fixtureFile(t, home, fmt.Sprintf("entries/%04d", i), nil)
			}
			entries, reason := r.ReadDir(context.Background(), "entries")
			if count == DirectoryEntryBudget {
				if reason != "" || len(entries) != count {
					t.Fatalf("ReadDir = %d %q", len(entries), reason)
				}
			} else if reason != ReasonTooManyEntries || entries != nil {
				t.Fatalf("oversize ReadDir = %d %q", len(entries), reason)
			}
		})
	}
}

func TestConfigBudgetBoundaries(t *testing.T) {
	r, home := fixtureRoot(t)
	for _, size := range []int{ConfigParseBudgetBytes, ConfigParseBudgetBytes + 1} {
		data := bytes.Repeat([]byte("x"), size)
		fixtureFile(t, home, "config", data)
		got, reason := r.ReadConfig(context.Background(), "config")
		if size == ConfigParseBudgetBytes {
			if reason != "" || !bytes.Equal(got, data) {
				t.Fatalf("boundary read length=%d reason=%q", len(got), reason)
			}
		} else if got != nil || reason != ReasonTooLarge {
			t.Fatalf("oversize read length=%d reason=%q", len(got), reason)
		}
	}
}

func TestHashUsesOpenedHandleAfterPathReplacement(t *testing.T) {
	r, home := fixtureRoot(t)
	original := []byte("original content")
	fixtureFile(t, home, "asset", original)
	f, info, reason := r.OpenRegular(context.Background(), "asset")
	if reason != "" {
		t.Fatal(reason)
	}
	defer f.Close()
	// A path replacement must not change the already stat'd/hashable object.
	fixtureFile(t, home, "replacement", []byte("replacement"))
	if err := os.Rename(filepath.Join(home, "replacement"), filepath.Join(home, "asset")); err != nil {
		t.Fatal(err)
	}
	got, reason := hashOpened(context.Background(), f, info)
	want := sha256.Sum256(original)
	if reason != "" || got.Hash != hex.EncodeToString(want[:]) || got.Size != int64(len(original)) || !got.Mtime.Equal(info.ModTime()) {
		t.Fatalf("hashOpened = %+v %q", got, reason)
	}
}

func TestHashDetectsChangedHandle(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, "asset", []byte("before"))
	f, info, reason := r.OpenRegular(context.Background(), "asset")
	if reason != "" {
		t.Fatal(reason)
	}
	defer f.Close()
	if err := os.Truncate(filepath.Join(home, "asset"), 0); err != nil {
		t.Fatal(err)
	}
	got, reason := hashOpened(context.Background(), f, info)
	if reason != ReasonChangedDuringRead || got.Hash != "" {
		t.Fatalf("hashOpened = %+v %q", got, reason)
	}
}

func TestConfinedOperationsCancellationAndClosedRoot(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, "asset", []byte("content"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, reason := r.HashFile(ctx, "asset"); reason != ReasonCanceled {
		t.Fatal(reason)
	}
	if _, reason := r.ReadConfig(ctx, "asset"); reason != ReasonCanceled {
		t.Fatal(reason)
	}
	if _, reason := r.ReadDir(ctx, "."); reason != ReasonCanceled {
		t.Fatal(reason)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, reason := r.HashFile(context.Background(), "asset"); reason != ReasonUnreadable {
		t.Fatal(reason)
	}
	if _, reason := r.ReadDir(context.Background(), "."); reason != ReasonUnreadable {
		t.Fatal(reason)
	}
}

type readFunc func([]byte) (int, error)

func (f readFunc) Read(p []byte) (int, error) { return f(p) }

func TestReadCancellationAtChunkBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := contextReader{ctx, readFunc(func(p []byte) (int, error) {
		cancel()
		return copy(p, "data"), nil
	})}
	if _, err := io.ReadAll(reader); fileReason(err) != ReasonCanceled {
		t.Fatalf("read error = %v", err)
	}
	if _, err := reader.Read(make([]byte, 1)); fileReason(err) != ReasonCanceled {
		t.Fatalf("pre-read cancellation error = %v", err)
	}
}

func TestClosedFileDoesNotProduceDigestOrChangedMetadata(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, "asset", []byte("content"))
	f, info, reason := r.OpenRegular(context.Background(), "asset")
	if reason != "" {
		t.Fatal(reason)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if digest, reason := hashOpened(context.Background(), f, info); digest.Hash != "" || reason != ReasonUnreadable {
		t.Fatalf("closed hash = %+v %q", digest, reason)
	}
	if reason := unchanged(f, info, info.Size()); reason != ReasonUnreadable {
		t.Fatal(reason)
	}
}

func TestHashFileAndDirectoryFailures(t *testing.T) {
	r, home := fixtureRoot(t)
	fixtureFile(t, home, "asset", []byte("content"))
	got, reason := r.HashFile(context.Background(), "asset")
	want := sha256.Sum256([]byte("content"))
	if reason != "" || got.Hash != hex.EncodeToString(want[:]) {
		t.Fatalf("HashFile = %+v %q", got, reason)
	}
	for _, p := range []string{"../escape", "asset", "missing"} {
		if _, reason := r.ReadDir(context.Background(), p); reason == "" {
			t.Fatalf("ReadDir(%q) succeeded", p)
		}
	}
}
