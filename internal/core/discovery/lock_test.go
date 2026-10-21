package discovery

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestScanLockExclusiveAndRelease(t *testing.T) {
	name := filepath.Join(t.TempDir(), "discovery.lock")
	lock, err := TryScanLock(name)
	if err != nil {
		t.Fatal(err)
	}
	if next, err := TryScanLock(name); next != nil || !errors.Is(err, ErrScanLocked) {
		t.Fatalf("held lock: %v %v", next, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal("close must be idempotent", err)
	}
	next, err := TryScanLock(name)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := TryScanLock(name); !errors.Is(err, ErrScanLocked) {
		t.Fatal("old handle removed new lock", err)
	}
}

func TestScanLockFailsClosed(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", filepath.Join(dir, "missing", "lock")} {
		if lock, err := TryScanLock(name); err == nil || lock != nil {
			t.Fatal("invalid path acquired a lock")
		}
	}
}

func TestScanLockKernelReleasesClosedDescriptor(t *testing.T) {
	name := filepath.Join(t.TempDir(), "scan.lock")
	if err := os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := TryScanLock(name)
	if err != nil {
		t.Fatal("persistent lock target must be reusable", err)
	}
	// Closing the descriptor models kernel cleanup on process exit, without an
	// explicit unlock. The persistent pathname must not require stale cleanup.
	if err := lock.file.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := TryScanLock(name)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err := os.Stat(name); err != nil {
		t.Fatal("lock target must remain in place", err)
	}
}

func TestScanLockConcurrentAcquisition(t *testing.T) {
	name := filepath.Join(t.TempDir(), "scan.lock")
	start := make(chan struct{})
	results := make(chan *ScanLock, 2)
	var wg sync.WaitGroup
	// Two contenders are the minimum fixture that can falsify exclusivity.
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			lock, err := TryScanLock(name)
			if err != nil && !errors.Is(err, ErrScanLocked) {
				t.Error(err)
			}
			results <- lock
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for lock := range results {
		if lock != nil {
			winners++
			defer lock.Close()
		}
	}
	if winners != 1 {
		t.Fatalf("got %d lock owners, want one", winners)
	}
}

func TestScanLockErrorOmitsPath(t *testing.T) {
	name := filepath.Join(t.TempDir(), "SENTINEL_account", "missing", "discovery.lock")
	lock, err := TryScanLock(name)
	if lock != nil || err == nil {
		t.Fatalf("missing parent: %v %v", lock, err)
	}
	if strings.Contains(err.Error(), "SENTINEL_account") || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lock error must be static and keep its cause: %q", err)
	}
}
