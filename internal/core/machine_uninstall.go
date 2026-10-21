package core

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Preflight uses the same resource hashes, pending-record shapes and cache trust
// checks as cleanup, but does not remove files or create a missing cache lock.
var machineUninstallPreflight = func(p MachineLayout, m clientManifest) ([]string, error) {
	owned := map[string]bool{p.Private: true, p.Manifest: true, filepath.Join(p.Private, "client.lock"): true}
	adapter := filepath.Join(p.Private, "adapter")
	if clientAdapterDirectoryError(p.Private) != nil {
		return []string{adapter}, nil
	}
	owned[adapter] = true
	for _, name := range []string{"connection.json", "runtime.json", "config.json"} {
		path := filepath.Join(adapter, name)
		if name == "config.json" {
			path = p.Config
		}
		edit, err := clientRegularEdit(path, nil)
		owned[path] = err == nil && edit.existed && m.Resources[name] == digestBytes(edit.before)
	}
	for _, name := range []string{"request.json", "enrolled.json"} {
		path := filepath.Join(p.Private, name)
		edit, err := clientRegularEdit(path, nil)
		owned[path] = err == nil && edit.existed && clientPendingOwned(name, edit.before)
	}
	cachePaths := []string{}
	for _, path := range []string{p.Bundle, policyTrustPath(p.Bundle)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			cachePaths = append(cachePaths, path)
		}
	}
	cacheOwned := len(cachePaths) == 0 || clientPolicyStateOwned(p.Bundle, m.Resources["connection.json"])
	for _, path := range cachePaths {
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > PolicyBundleMaxBytes {
			cacheOwned = false
		}
	}
	lockPath := p.Bundle + ".lock"
	if edit, err := clientRegularEdit(lockPath, nil); err == nil && edit.existed && len(edit.before) == 0 {
		// Cache cleanup uses this same nonblocking lock. Test an existing inode
		// without O_CREATE so a refused uninstall leaves the tree untouched.
		lock, err := os.OpenFile(lockPath, os.O_RDWR, 0600)
		if err == nil {
			owned[lockPath] = lockProcessFile(lock) == nil
			if err := lock.Close(); err != nil {
				return nil, err
			}
		}
		cacheOwned = cacheOwned && owned[lockPath]
	}
	for _, path := range cachePaths {
		owned[path] = cacheOwned
	}
	retained := []string{}
	err := filepath.WalkDir(p.Private, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !owned[path] {
			retained = append(retained, path)
			if entry.IsDir() {
				return filepath.SkipDir
			}
		}
		return nil
	})
	return retained, err
}
