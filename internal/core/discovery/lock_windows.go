package discovery

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// LockFileEx, dwFlags and Remarks: fail immediately; close/process exit releases
// locks. The one-byte range mirrors internal/core/lock_windows.go and may extend
// beyond EOF (no content is needed).
// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex
func acquireScanLock(file *os.File) error {
	err := windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrScanLocked
	}
	if err != nil {
		return fmt.Errorf("discovery: acquire scan lock: %w", err)
	}
	return nil
}
