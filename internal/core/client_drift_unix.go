//go:build unix

package core

import (
	"errors"
	"os"
	"syscall"
)

// OpenSSH StrictModes precedent: trust the opened directory's owner, not a precheck.
func validateDriftRoot(root *os.Root) error {
	st, err := root.Stat(".")
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("drift root owner mismatch")
	}
	return nil
}

func openDriftFile(root *os.Root, rel string) (*os.File, error) {
	// POSIX open(2): O_NONBLOCK prevents a FIFO substitution from blocking.
	return root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
