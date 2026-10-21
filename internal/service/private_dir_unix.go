//go:build darwin || linux

package service

import (
	"aegishook/internal/core"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Reuse S1's native validator; do not weaken FIO15-C for a daemon or repair.
// Every existing ancestor is checked before reading private machine state.
func validateDaemonPaths(root string, validate func(string, bool) error) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) == "/" || filepath.Clean(root) != root {
		return errors.New("machine root must be a clean absolute non-root directory")
	}
	if err := validatePublicChain(root, validate); err != nil {
		return err
	}
	return filepath.WalkDir(core.MachinePaths(root).Private, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return validate(path, true)
	})
}

func validatePublicChain(path string, validate func(string, bool) error) error {
	for dir := path; ; dir = filepath.Dir(dir) {
		if err := validate(dir, false); err != nil {
			return err
		}
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() {
			return errors.New("machine ancestor must be a real directory")
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
	}
}
