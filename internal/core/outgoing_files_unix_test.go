//go:build unix

package core

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO substituted for the requested path must not block the hook, and a
// device must not be read. Both are refused after one non-blocking open.
func TestCaptureOutgoingFilesRefusesNonRegularTargets(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	link := filepath.Join(dir, "device-link")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path string }{
		{"fifo", fifo},
		{"device", "/dev/zero"},
		{"symlink-to-device", link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			var files []ReviewScript
			var status string
			go func() {
				defer close(done)
				files, status = CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": tc.path}, nil, "not_applicable")
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("capture blocked on a non-regular target")
			}
			if status != "incomplete" || len(files) != 1 || files[0].Content != "" || files[0].ReadError == "" {
				t.Fatalf("non-regular target was read: status=%s files=%+v", status, files)
			}
		})
	}
}

// Symlinks to regular files are allowed: the endpoint reads the same bytes the
// agent is about to read.
func TestCaptureOutgoingFilesFollowsSymlinkToRegularFile(t *testing.T) {
	dir := t.TempDir()
	target := outgoingFile(t, dir, "target.txt", "linked\n")
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": link}, nil, "not_applicable")
	if status != "complete" || len(files) != 1 || files[0].Content != "linked\n" {
		t.Fatalf("symlink to a regular file was refused: status=%s files=%+v", status, files)
	}
}

// ".." is resolved by the kernel, not lexically: here the link points at
// sub/deeper, so ".." means sub, not the parent of the link's own directory.
// Trimming or path.Clean reads the wrong file (review #24 HIGH 1).
func TestCaptureOutgoingFilesResolvesDotDotNatively(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(filepath.Join(sub, "deeper"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sub, "note.txt")
	if err := os.WriteFile(target, []byte("native\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// What a lexical clean would have chosen instead.
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("cleaned\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(sub, "deeper"), link); err != nil {
		t.Fatal(err)
	}
	files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": link + "/../note.txt"}, nil, "not_applicable")
	if status != "complete" || len(files) != 1 || files[0].Content != "native\n" {
		t.Fatalf("dot-dot was resolved lexically: status=%s files=%+v", status, files)
	}
}

// Only ENOENT is the not-applicable exception. A symlink loop and a path
// through a regular file fail with their own errno and must fail incomplete,
// content-free, with the class retained (review #24 HIGH 3).
func TestCaptureOutgoingFilesOpenFailuresAreIncomplete(t *testing.T) {
	dir := t.TempDir()
	regular := outgoingFile(t, dir, "file.txt", "content\n")
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path, class string }{
		{"notdir", filepath.Join(regular, "child.txt"), "not a directory"},
		{"symlink-loop", loop, "too many levels of symbolic links"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": tc.path}, nil, "not_applicable")
			if status != "incomplete" || len(files) != 1 || files[0].Content != "" || files[0].SHA256 != "" || !strings.Contains(files[0].ReadError, tc.class) {
				t.Fatalf("failure was not content-free incomplete with its class: status=%s files=%+v", status, files)
			}
		})
	}
	// A dangling symlink still reports ENOENT, so it keeps the exception.
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "gone.txt"), dangling); err != nil {
		t.Fatal(err)
	}
	if files, status := CaptureOutgoingFiles(dir, "Read", map[string]any{"file_path": dangling}, nil, "not_applicable"); status != "not_applicable" || files != nil {
		t.Fatalf("dangling symlink changed the carrier: status=%s files=%+v", status, files)
	}
}
