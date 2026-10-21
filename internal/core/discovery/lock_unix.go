//go:build darwin || linux

package discovery

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// flock(2), DESCRIPTION: LOCK_NB never waits; the last close releases the lock.
// https://man7.org/linux/man-pages/man2/flock.2.html
func acquireScanLock(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrScanLocked
	}
	if err != nil {
		return fmt.Errorf("discovery: acquire scan lock: %w", err)
	}
	return nil
}
