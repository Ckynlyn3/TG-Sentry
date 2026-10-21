package discovery

import (
	"errors"
	"os"
	"sync"
)

var (
	ErrScanLocked = errors.New("discovery: scan already running")
	errScanLockIO = errors.New("discovery: scan lock unavailable")
)

// lockError keeps the OS cause for errors.Is/As (e.g. fs.ErrPermission) but never
// exposes its path-bearing text through Error(); same pattern as decodeError in report.go.
type lockError struct{ cause error }

func (e lockError) Error() string        { return errScanLockIO.Error() }
func (e lockError) Unwrap() error        { return e.cause }
func (e lockError) Is(target error) bool { return target == errScanLockIO }

// ScanLock holds a kernel lock, not a lockfile-existence marker. The caller must
// provide a stable path in its private state directory, never an account home.
// Do not unlink the target: another process may already have opened that inode.
// The kernel releases the lock on process exit; no stale-file recovery is needed.
// This follows internal/core/lock_{unix,windows}.go without importing core.
type ScanLock struct {
	file *os.File
	once sync.Once
	err  error
}

func TryScanLock(name string) (*ScanLock, error) {
	// 0600 is the existing private-state file precedent in core; no contents are
	// read or written and an existing target is never truncated.
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, lockError{cause: err}
	}
	if err := acquireScanLock(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &ScanLock{file: file}, nil
}

// Close is idempotent, including concurrent cleanup. Closing the descriptor is
// sufficient on both supported platforms; see the OS helper citations.
func (lock *ScanLock) Close() error {
	lock.once.Do(func() {
		if err := lock.file.Close(); err != nil {
			lock.err = lockError{cause: err}
		}
	})
	return lock.err
}
