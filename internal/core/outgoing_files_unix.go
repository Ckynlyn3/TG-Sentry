//go:build unix

package core

import (
	"os"
	"syscall"
)

// POSIX open(2), O_NONBLOCK: a read-only FIFO open returns without delay;
// regular files are unaffected. The opened handle is type-checked before any
// read. https://pubs.opengroup.org/onlinepubs/007904875/functions/open.html
func openOutgoingFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
