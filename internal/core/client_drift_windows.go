//go:build windows

package core

import (
	"errors"
	"os"
)

func validateDriftRoot(root *os.Root) error {
	st, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("drift root is not a directory")
	}
	// Named Windows boundary (#33/35): owner validation is not evaluated;
	// no unverified ACL/owner assertion is made. os.Root still confines access.
	return nil
}

func openDriftFile(root *os.Root, rel string) (*os.File, error) {
	// Windows has no POSIX FIFO; readDriftFile checks the opened handle's type.
	return root.OpenFile(rel, os.O_RDONLY, 0)
}
