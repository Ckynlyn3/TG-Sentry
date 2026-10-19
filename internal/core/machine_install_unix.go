//go:build unix

package core

import (
	"errors"
	"os"
	"syscall"
)

func init() {
	ValidateMachinePath = func(path string, private bool) error { return validateMachineUnixPath(path, private, 0) }
}

// SEI CERT FIO15-C: a secure directory chain prevents unprivileged substitution.
// Tests substitute only the expected owner for their temporary directories.
func validateMachineUnixPath(path string, private bool, uid uint32) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || (!st.IsDir() && !st.Mode().IsRegular()) {
		return errors.New("machine path must not be a symlink or special file")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uid) {
		return errors.New("machine path has an untrusted owner")
	}
	if st.Mode().Perm()&0022 != 0 && (private || !st.IsDir() || st.Mode()&os.ModeSticky == 0) {
		return errors.New("machine path is writable by non-administrators")
	}
	if private && st.Mode().Perm()&0077 != 0 {
		return errors.New("machine private paths must be accessible only by root")
	}
	return nil
}
