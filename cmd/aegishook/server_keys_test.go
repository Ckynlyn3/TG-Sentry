package main

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Issue #65 §6: exercise main's real dispatch, the process lock, and disk modes.
func TestServerKeysDispatch(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "aegishook")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	dir := teststore.Dir(t, t.TempDir())
	e, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := serverKeysRecord(t, e)
	oldID := first.Keys[0].KeyID
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	run := func(action string, wantOK bool, extra ...string) string {
		t.Helper()
		args := append([]string{"server", action, "--data-dir", dir}, extra...)
		out, err := exec.Command(binary, args...).CombinedOutput()
		if (err == nil) != wantOK {
			t.Fatalf("%s: success=%v, want %v; output=%s", action, err == nil, wantOK, out)
		}
		return string(out)
	}
	rotated := run("rotate-bundle-key", true)
	e, err = core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	next := serverKeysRecord(t, e)
	if next.Version != 2 || len(next.Keys) != 2 || next.Keys[0].KeyID != oldID {
		t.Fatal("dispatch did not commit overlap record")
	}
	newID := next.Keys[1].KeyID
	for _, action := range []string{"rotate-bundle-key", "retire-bundle-key"} {
		before, err := os.ReadFile(filepath.Join(dir, "bundle-trust.json"))
		if err != nil {
			t.Fatal(err)
		}
		var extra []string
		if action == "retire-bundle-key" {
			extra = []string{"--key-id", oldID}
		}
		out := run(action, false, extra...)
		if !strings.Contains(out, "AegisHook") {
			t.Fatal("locked command did not report process-lock refusal")
		}
		after, err := os.ReadFile(filepath.Join(dir, "bundle-trust.json"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("locked command changed committed trust")
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	run("rotate-bundle-key", false) // overlap requires explicit retirement (§9.2).
	run("retire-bundle-key", false, "--key-id", newID)
	run("retire-bundle-key", false, "--key-id", "unknown")
	retired := run("retire-bundle-key", true, "--key-id", oldID)
	e, err = core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	current := serverKeysRecord(t, e)
	if current.Version != 3 || len(current.Keys) != 1 || current.Keys[0].KeyID != newID {
		t.Fatal("dispatch did not persist retirement")
	}
	for _, check := range []struct {
		output  string
		version int
		ids     []string
	}{
		{rotated, 2, []string{oldID, newID}},
		{retired, 3, []string{oldID, newID}},
	} {
		for _, want := range append(check.ids, fmt.Sprintf("trust-version=%d", check.version), "Next steps:", "Restart") {
			if !strings.Contains(check.output, want) {
				t.Fatalf("output missing %q", want)
			}
		}
	}
	paths, err := filepath.Glob(filepath.Join(dir, "bundle-signing*.key"))
	if err != nil || len(paths) != 2 {
		t.Fatal("rotation must retain predecessor key files")
	}
	for _, path := range append(paths, filepath.Join(dir, "bundle-trust.json"), filepath.Join(dir, "process.lock")) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o, want 0600", filepath.Base(path), info.Mode().Perm())
		}
		if strings.HasSuffix(path, ".key") {
			key, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{string(key), base64.StdEncoding.EncodeToString(key), hex.EncodeToString(key)} {
				if strings.Contains(rotated+retired, secret) {
					t.Fatal("CLI exposed private key bytes")
				}
			}
		}
	}
}

// Port of the independent review's TestReviewCLISecretPathError (issue #65 S6).
func TestReviewCLISecretPathError(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "aegishook")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	for _, fixture := range []struct {
		name string
		file string
	}{
		{"missing-key", "bundle-signing.key"},
		{"unreadable-manifest", "bundle-trust.json"},
		{"initialization-failure", "model.key"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			dir := teststore.Dir(t, t.TempDir())
			e, err := core.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			secretPath := filepath.Join(dir, fixture.file)
			if fixture.file != "model.key" {
				if err := os.Remove(secretPath); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.file != "bundle-signing.key" {
				// A directory is unreadable as a file even under a root Docker user.
				if err := os.Mkdir(secretPath, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, action := range []string{"rotate-bundle-key", "retire-bundle-key"} {
				args := []string{"server", action, "--data-dir", dir}
				if action == "retire-bundle-key" {
					args = append(args, "--key-id", "unknown")
				}
				out, err := exec.Command(binary, args...).CombinedOutput()
				if err == nil {
					t.Fatal("unavailable server state must refuse key management")
				}
				var direct bytes.Buffer
				if err := runServerKeys(args[1:], &direct); !errors.Is(err, errServerKeysUnavailable) {
					t.Fatal("failure must retain the key-management error category")
				}
				for _, secret := range append([]string{secretPath, dir, fixture.file}, strings.FieldsFunc(dir, func(r rune) bool { return r == '/' || r == '\\' })...) {
					if strings.Contains(string(out), secret) {
						t.Error("CLI output exposes a secret path or data-directory segment")
					}
				}
			}
		})
	}
}

func serverKeysRecord(t *testing.T, e *core.Engine) core.TrustRecord {
	t.Helper()
	signed, err := e.BundleTrustRecord(e.BundleTrustVersion())
	if err != nil {
		t.Fatal(err)
	}
	var record core.TrustRecord
	if err := json.Unmarshal(signed.Payload, &record); err != nil {
		t.Fatal(err)
	}
	return record
}
