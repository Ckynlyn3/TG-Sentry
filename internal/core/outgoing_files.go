package core

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// Outgoing-file capture reuses the script snapshot carrier: the sensitive
// detector already scans Scripts (sensitive_review.go), the store already
// strips their content on persistence (store.go ReviewListView) and an
// incomplete capture already forces the human path (reviews.go). No new wire
// field or adapter contract is added.
//
// Slice scope (plan §6/D5): only clients whose hook contract documents a scalar
// path field are read. Claude Code hooks deliver tool_input per tool
// (https://code.claude.com/docs/en/hooks, "Common input fields"); Cursor's
// generic preToolUse covers Read (docs/remote-clients.md). Codex has no
// documented file-reading contract, so it stays unread (D5). Write/Edit content
// already travels inline in Arguments and needs no capture.
var outgoingFileTools = []string{"Read"}

const outgoingFileOverLimit = "文件超过外发扫描限制（1 MiB），未读取内容"
const outgoingFileGrown = "文件在采集期间变大，未能完整读取"
const outgoingFileNotText = "文件不是有效 UTF-8 文本"

// OutgoingFileOverEnvelope marks a capture dropped to keep the review request
// inside the existing 2 MiB transport bound (bridge.fitOutgoingFiles).
const OutgoingFileOverEnvelope = "文件快照会使审查请求超过传输上限（2 MiB），未附加内容"

// CaptureOutgoingFiles appends the content of the file a file-reading tool is
// about to send. It never executes or fetches anything, and it leaves a
// non-matching tool's carrier and status exactly as the caller supplied them.
// The whole file is captured regardless of Read.offset/limit: a windowed read
// must not hide an identifier later in the file.
func CaptureOutgoingFiles(workingDir, tool string, arguments map[string]any, prior []ReviewScript, status string) ([]ReviewScript, string) {
	if !hasExact(tool, outgoingFileTools...) {
		return prior, status
	}
	path := argumentText(arguments, "path", "file_path", "filePath")
	if path == "" {
		return prior, status
	}
	// The path is opened literally: no trimming and no lexical cleaning. Both
	// would open a different file than the agent does — a name may legally
	// begin or end with a space, and ".." after a symlink resolves against the
	// link target, not against the string. A relative path is joined to the
	// hook cwd and left for the OS to resolve.
	target := path
	if !filepath.IsAbs(target) && workingDir != "" {
		// Join by prefix only: the tool's path is appended verbatim so ".."
		// still resolves natively through any symlinked component.
		target = workingDir + string(os.PathSeparator) + target
	}
	content, size, err := readOutgoingFile(target)
	if errors.Is(err, fs.ErrNotExist) {
		// Named local exception outgoing-file-absent: ENOENT is the only
		// failure that proves no bytes exist for anyone, so the caller's
		// carrier and status stay unchanged. Every other failure below does
		// not establish that, and is recorded content-free as incomplete.
		return prior, status
	}
	file := ReviewScript{Path: target, Bytes: size}
	if err != nil {
		file.ReadError = outgoingReadError(err)
		file.Truncated = errors.Is(err, errOutgoingFileTooLarge) || errors.Is(err, errOutgoingFileGrownDuringRead)
		return append(prior, file), "incomplete"
	}
	file.Bytes = int64(len(content))
	if !utf8.Valid(content) || bytes.ContainsRune(content, 0) {
		file.ReadError = outgoingFileNotText
		return append(prior, file), "incomplete"
	}
	hash := sha256.Sum256(content)
	file.SHA256 = fmt.Sprintf("%x", hash)
	file.Content = string(content)
	file.Complete = true
	return append(prior, file), "complete"
}

// FitOutgoingFileSnapshot drops outgoing-file content that would push the
// serialized review request past the existing 2 MiB transport bound, which the
// bridge measures after building the whole envelope (server.go read():
// http.MaxBytesReader(w, r.Body, 2<<20), the same ceiling as
// ToolOutputJSONBytes). The entry keeps its path and size, and the incomplete
// status forces the human path: never a silent allow. Scripts captured before
// outgoingFrom keep their existing retention.
func FitOutgoingFileSnapshot(in *ReviewInput, outgoingFrom, envelopeBytes int) {
	if len(in.Scripts) <= outgoingFrom || envelopeBytes <= ToolOutputJSONBytes {
		return
	}
	for i := outgoingFrom; i < len(in.Scripts); i++ {
		if in.Scripts[i].Content == "" {
			continue
		}
		in.Scripts[i].Content, in.Scripts[i].SHA256, in.Scripts[i].Complete = "", "", false
		in.Scripts[i].Truncated, in.Scripts[i].ReadError = true, OutgoingFileOverEnvelope
		in.ScriptCaptureStatus = "incomplete"
	}
}

// readOutgoingFile opens once and inspects the descriptor, so a FIFO or device
// substituted after any path check cannot hang or stream forever. POSIX
// open(2) O_NONBLOCK returns a read-only FIFO open without delay; the opened
// handle is then type-checked before any read (same rule as
// internal/core/discovery/fsroot_unix.go). Symlinks to regular files are
// allowed: the endpoint reads the same path the agent is about to read.
//
// The descriptor's size is returned even when the read is refused, so the
// content-free entry can still report what was refused (plan §6 D2).
func readOutgoingFile(path string) ([]byte, int64, error) {
	f, err := openOutgoingFile(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, info.Size(), errOutgoingFileNonRegular
	}
	if info.Size() > maxReviewScriptBytes {
		return nil, info.Size(), errOutgoingFileTooLarge
	}
	content, err := readOutgoingBytes(f)
	if err != nil {
		return nil, info.Size(), err
	}
	// LimitReader stops at its bound and reports plain EOF, so a file that grew
	// past the limit after the fstat would otherwise be marked complete with a
	// silently omitted tail: https://pkg.go.dev/io#LimitReader
	if int64(len(content)) > maxReviewScriptBytes {
		return nil, info.Size(), errOutgoingFileGrownDuringRead
	}
	return content, info.Size(), nil
}

// readOutgoingBytes bounds the read at one byte past the limit so growth is
// detectable (https://pkg.go.dev/io#LimitReader). It is a variable so the
// growth regression test can grow the file between fstat and read.
var readOutgoingBytes = func(f *os.File) ([]byte, error) {
	return io.ReadAll(io.LimitReader(f, maxReviewScriptBytes+1))
}

var (
	errOutgoingFileTooLarge        = errors.New(outgoingFileOverLimit)
	errOutgoingFileGrownDuringRead = errors.New(outgoingFileGrown)
	errOutgoingFileNonRegular      = errors.New("不是普通文件")
)

// outgoingReadError keeps the OS error class without repeating the path the
// entry already carries (review #24 HIGH 3).
func outgoingReadError(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}
