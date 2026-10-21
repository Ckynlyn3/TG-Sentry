//go:build !unix

package core

import "os"

// Windows has no POSIX FIFO; readOutgoingFile checks the opened handle's type
// (same boundary as internal/core/client_drift_windows.go).
func openOutgoingFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}
