package core

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// https://cursor.com/docs/hooks.md#configuration-file and
// #per-script-configuration-options: version 1, flat command definitions,
// timeout in seconds, failClosed at each hook (not at document level).
func assertCursorHooks(t *testing.T, data []byte) {
	t.Helper()
	var doc struct {
		Version int                         `json:"version"`
		Hooks   map[string][]map[string]any `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != 1 {
		t.Fatal("invalid Cursor hooks.json", string(data), err)
	}
	if len(doc.Hooks["beforeShellExecution"]) != 0 || len(doc.Hooks["beforeMCPExecution"]) != 0 || len(doc.Hooks["beforeReadFile"]) != 0 {
		t.Fatal("overlapping gates would prevent human approval retries")
	}
	for _, event := range []string{"beforeSubmitPrompt", "preToolUse", "postToolUse", "postToolUseFailure", "afterAgentResponse", "stop", "afterFileEdit", "sessionStart", "sessionEnd"} {
		entries := doc.Hooks[event]
		if len(entries) != 1 || entries[0]["failClosed"] != true || entries[0]["timeout"] != float64(5) || !strings.Contains(entries[0]["command"].(string), "cursor") {
			t.Fatalf("missing native fail-closed hook %s: %+v", event, entries)
		}
		if _, nested := entries[0]["hooks"]; nested {
			t.Fatal("Claude configuration shape used for Cursor")
		}
	}
}

func TestCursorInstallLifecycle(t *testing.T) {
	for _, scope := range []string{"project", "global", "enterprise"} {
		t.Run(scope, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			o := clientFixture(t, "cursor")
			o.Scope = scope
			if scope != "project" {
				o.Project = ""
			}
			r, err := ClientOperation("install", o)
			if err != nil {
				t.Fatal(err)
			}
			if scope == "global" && r.Entry != filepath.Join(home, ".cursor", "hooks.json") {
				t.Fatal("wrong user path", r.Entry)
			}
			if scope == "enterprise" && (!strings.HasPrefix(r.Entry, o.Dir+string(filepath.Separator)) || !strings.Contains(r.Warning, CursorEnterprisePath(runtime.GOOS))) {
				t.Fatal("enterprise deployment must be staged, never written to system paths", r)
			}
			data, err := os.ReadFile(r.Entry)
			if err != nil {
				t.Fatal(err)
			}
			assertCursorHooks(t, data)
			if _, err := ClientOperation("install", o); err != nil {
				t.Fatal("idempotent install", err)
			}
			var doc map[string]any
			json.Unmarshal(data, &doc)
			doc["foreign"] = true
			hooks := doc["hooks"].(map[string]any)
			hooks["preToolUse"] = append(hooks["preToolUse"].([]any), map[string]any{"command": "foreign-hook"})
			if err := AtomicFile(r.Entry, mustJSON(doc), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ClientOperation("uninstall", o); err != nil {
				t.Fatal(err)
			}
			data, err = os.ReadFile(r.Entry)
			if err != nil || !bytes.Contains(data, []byte("foreign-hook")) || !bytes.Contains(data, []byte("foreign")) {
				t.Fatal("foreign configuration lost", string(data), err)
			}
		})
	}
}

func TestCursorEnterprisePaths(t *testing.T) {
	// Vendor Configuration / Enterprise and Team Distribution / MDM Distribution.
	for platform, want := range map[string]string{"darwin": "/Library/Application Support/Cursor/hooks.json", "linux": "/etc/cursor/hooks.json", "windows": `C:\ProgramData\Cursor\hooks.json`} {
		if got := CursorEnterprisePath(platform); got != want {
			t.Fatal(platform, got, want)
		}
	}
}

func TestCursorInstallerRejectsVersionAndPolicyDrift(t *testing.T) {
	o := clientFixture(t, "cursor")
	entry := filepath.Join(o.Project, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(entry), 0700); err != nil {
		t.Fatal(err)
	}
	before := []byte(`{"version":2,"hooks":{}}`)
	if err := os.WriteFile(entry, before, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientOperation("install", o); err == nil {
		t.Fatal("unsupported config version overwritten")
	}
	after, _ := os.ReadFile(entry)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid config modified")
	}
	if err := os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientOperation("install", o); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(entry)
	changed := bytes.ReplaceAll(data, []byte(`"failClosed": true`), []byte(`"failClosed": false`))
	if err := os.WriteFile(entry, changed, 0600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"install", "uninstall"} {
		if _, err := ClientOperation(action, o); err == nil {
			t.Fatal("failure policy drift silently accepted", action)
		}
	}
	if err := os.WriteFile(entry, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientOperation("uninstall", o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entry); !os.IsNotExist(err) {
		t.Fatal("new empty Cursor config not removed", err)
	}
}

func TestCursorInstallerDistributionWrappers(t *testing.T) {
	for _, ext := range []string{"sh", "ps1"} {
		script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "hook."+ext))
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := os.ReadFile(filepath.Join("..", "assets", "hooks."+ext))
		if err != nil || !bytes.Equal(script, embedded) {
			t.Fatal("published wrapper differs from source", ext, err)
		}
		if !bytes.Contains(script, []byte("cursor")) || !bytes.Contains(script, []byte("enterprise")) {
			t.Fatal("wrapper rejects Cursor or staged enterprise scope", ext)
		}
	}
}

func TestCursorShellWrapperAcceptsStagedUninstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX wrapper; Windows wrapper schema is checked separately")
	}
	dir := t.TempDir()
	cmd := exec.Command("bash", "../../scripts/hook.sh", "uninstall", "--agent", "cursor", "--scope", "enterprise", "--client-dir", filepath.Join(dir, "absent"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("Cursor wrapper rejected safe offline uninstall", err, string(output))
	}
}

func TestCursorWrapperRejectsEnterpriseSwitchBeforeBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX wrapper; the PowerShell guard mirrors it")
	}
	dir := t.TempDir()
	clientDir := filepath.Join(dir, "client")
	cmd := exec.Command("bash", "../../scripts/hook.sh", "install", "--agent", "cursor", "--scope", "enterprise", "--switch",
		"--endpoint", "https://review.example", "--client-dir", clientDir, "--binary", filepath.Join(dir, "absent"))
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "--switch") {
		t.Fatal("enterprise --switch was not rejected", err, string(output))
	}
	if _, err := os.Stat(clientDir); !os.IsNotExist(err) {
		t.Fatal("wrapper wrote the client directory before rejecting", err)
	}
	for _, script := range []string{"../../scripts/hook.ps1", "../assets/hooks.ps1"} {
		body, err := os.ReadFile(script)
		if err != nil || !bytes.Contains(body, []byte("$Scope -eq 'enterprise' -and $SwitchScope")) {
			t.Fatal("PowerShell wrapper lacks the enterprise switch guard", script, err)
		}
	}
}

func TestCursorDetectionDoesNotExecuteVendor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX probe fixture")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	program := "#!/bin/sh\nprintf executed > '" + marker + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "cursor"), []byte(program), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	found := false
	for _, agent := range DetectAgents() {
		if agent.ID == "cursor" {
			found = agent.Found && agent.Version == "" && agent.Path != ""
		}
	}
	if !found {
		t.Fatal("Cursor discovery missing or claimed an unmeasured version")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("Cursor version probe executed", err)
	}
}

func TestCursorEnterpriseSwitchRejectsWithoutRemovingActiveHooks(t *testing.T) {
	for _, priorScope := range []string{"global", "project"} {
		t.Run(priorScope, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			o := clientFixture(t, "cursor")
			o.Scope = priorScope
			if priorScope == "global" {
				o.Project = ""
			}
			installed, err := ClientOperation("install", o)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(installed.Entry)
			if err != nil {
				t.Fatal(err)
			}
			o.Scope, o.Project, o.Switch = "enterprise", "", true
			if _, err = ClientOperation("install", o); err == nil || !strings.Contains(err.Error(), "--switch") {
				t.Errorf("enterprise staging must reject --switch up front: %v", err)
			}
			after, err := os.ReadFile(installed.Entry)
			if err != nil || !bytes.Equal(before, after) {
				t.Errorf("active %s hooks changed before managed deployment: %v", priorScope, err)
			}
			if _, err := os.Stat(cursorStagingPath(o.Dir)); !os.IsNotExist(err) {
				t.Errorf("rejected switch still wrote staged hooks: %v", err)
			}
		})
	}
}
