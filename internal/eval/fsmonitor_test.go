package eval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGitFSMonitorCannotHideSourceDrift(t *testing.T) {
	o, _ := syntheticRun(t)
	source := filepath.Join(o.Root, "code.go")
	if err := os.WriteFile(source, []byte("frozen code\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, o.Root, "add", ".")
	gitTest(t, o.Root, "commit", "-m", "synthetic frozen source")
	gitTest(t, o.Root, "tag", "-f", FreezeTag, "HEAD")
	hook := filepath.Join(o.Root, ".git", "fake-monitor")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nprintf 'fake-token\\0'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	gitTest(t, o.Root, "config", "core.fsmonitor", hook)
	gitTest(t, o.Root, "status", "--porcelain")
	if err := os.WriteFile(source, []byte("different executable source\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := runOnHost(context.Background(), o, "linux", "amd64")
	calls := o.Detector.(*fakeDetector).calls
	if err == nil || calls != 0 {
		t.Fatalf("changed source accepted: err=%v detector_calls=%d", err, calls)
	}
}
