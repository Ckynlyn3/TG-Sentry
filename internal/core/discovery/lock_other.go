//go:build !darwin && !linux && !windows

package discovery

import "os"

// Match account enumeration's unsupported-platform boundary; do not run a scan
// without an implementation of the required kernel overlap guard.
func acquireScanLock(_ *os.File) error { return ErrUnsupportedPlatform }
