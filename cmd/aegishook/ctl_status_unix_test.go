//go:build darwin && native

package main

import (
	"aegishook/internal/core"
	"aegishook/internal/service"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCtlStatusT9NativeInstalledDaemon(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("NOT RUN: integrated installed-artifact ctl T9 requires the root macOS Gate B release runner")
	}
	root := os.Getenv("TG_SENTRY_NATIVE_MACHINE_ROOT")
	if root == "" {
		t.Skip("NOT RUN: no Gate B installed hash-verified signed artifact was provided")
	}
	// Gate B provides an enrolled fixture. The production binary must speak to
	// the real root daemon, not an injected service.Call implementation.
	for _, require := range []string{"installed", "service", "enrolled", "hooks"} {
		cmd := exec.Command(filepath.Join(core.PackageRoot(), "aegishook"), "ctl", "status", "--machine-dir", root, "--require", require)
		var output bytes.Buffer
		cmd.Stdout = &output
		err := cmd.Run()
		want := service.ExitOK
		if require == "hooks" {
			want = service.ExitHooksUnknown
		} // root without --user
		got := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			got = exit.ExitCode()
		}
		if got != want {
			t.Fatalf("require %s: exit %d want %d", require, got, want)
		}
		var state service.Status
		if json.Unmarshal(output.Bytes(), &state) != nil || state.Loaded != "unknown" {
			t.Fatal("invalid status or falsely claimed loaded hooks")
		}
	}
}
