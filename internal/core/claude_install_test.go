package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fakeClaudeVersion(t *testing.T, version string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX version-probe fixture")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	program := "#!/bin/sh\nprintf 'probe\\n' >> '" + calls + "'\n"
	if version == "probe_failure" {
		program += "exit 1\n"
	} else {
		program += "printf '%s\\n' '" + version + "'\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(program), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return calls
}

func claudePreHook(t *testing.T, path string) map[string]any {
	t.Helper()
	doc, _, _, err := loadHookDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	return doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
}

func TestClaudeInstallFailurePolicy(t *testing.T) {
	for _, installer := range []string{"engine", "client"} {
		for _, tc := range []struct {
			version string
			block   bool
		}{
			{"2.1.294 (Claude Code)", false}, {"2.1.295 (Claude Code)", true},
			{"2.1.296 (Claude Code)", true}, {"2.2.0 (Claude Code)", true}, {"3.0.0 (Claude Code)", true},
			{"1.9.999 (Claude Code)", false}, {"2.1.295-beta.1 (Claude Code)", false},
			{"unknown", false}, {"probe_failure", false},
		} {
			t.Run(installer+"/"+tc.version, func(t *testing.T) {
				calls := fakeClaudeVersion(t, tc.version)
				o := clientFixture(t, "claude")
				var installed Installation
				var path string
				var uninstall, reinstall func() error
				if installer == "engine" {
					e := engine(t)
					if err := os.MkdirAll(filepath.Join(e.Dir, "adapter"), 0700); err != nil {
						t.Fatal(err)
					}
					if err := e.PrepareIntegrations([]byte("fixture"), o.Binary); err != nil {
						t.Fatal(err)
					}
					var err error
					installed, err = e.InstallAgent(testActorContext(), "claude", "project", o.Project, "")
					if err != nil {
						t.Fatal(err)
					}
					path = installed.Entry
					uninstall = func() error { return e.Uninstall(testActorContext(), installed.ID) }
					reinstall = func() error {
						_, err := e.InstallAgent(testActorContext(), "claude", "project", o.Project, "")
						return err
					}
					audits, err := e.Audits()
					if err != nil {
						t.Fatal(err)
					}
					warned := false
					for _, a := range audits {
						if a.Action == "hook.install" && strings.Contains(a.Detail, "onFailure omitted") {
							warned = true
						}
					}
					if warned == tc.block {
						t.Fatal("missing or incorrect installation warning", audits)
					}
					if !e.agentEntryOK(installed) {
						t.Fatal("snapshot does not match installed hook")
					}
				} else {
					r, err := ClientOperation("install", o)
					if err != nil {
						t.Fatal(err)
					}
					path = r.Entry
					if (r.Warning != "") == tc.block {
						t.Fatal("missing or incorrect installation warning", r.Warning)
					}
					reinstall = func() error { _, err := ClientOperation("install", o); return err }
					b, err := os.ReadFile(filepath.Join(o.Dir, "client.json"))
					if err != nil {
						t.Fatal(err)
					}
					var manifest clientManifest
					if err = json.Unmarshal(b, &manifest); err != nil {
						t.Fatal(err)
					}
					installed = manifest.Entries[0].Installation
					uninstall = func() error { _, err := ClientOperation("uninstall", o); return err }
				}
				h := claudePreHook(t, path)
				if h["timeout"] != float64(5) {
					t.Fatal("wrong seconds budget", h)
				}
				if tc.block && h["onFailure"] != "block" {
					t.Fatal("missing host failure protection", h)
				}
				if !tc.block {
					if _, ok := h["onFailure"]; ok {
						t.Fatal("unsupported failure field", h)
					}
				}
				if installed.ManagedContent == "" {
					t.Fatal("missing exact owned PreToolUse snapshot")
				}
				b, err := os.ReadFile(calls)
				if err != nil || strings.Count(string(b), "probe") != 1 {
					t.Fatal("version not probed once", string(b), err)
				}
				// Reinstall/drift/uninstall use the snapshot, never the current CLI version.
				t.Setenv("PATH", t.TempDir())
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = reinstall(); err != nil {
					t.Fatal("idempotent install after version change", err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("reinstall changed hook", err)
				}
				if err = uninstall(); err != nil {
					t.Fatal("uninstall after version change", err)
				}
			})
		}
	}
}

func TestClaudeHookSnapshotDetectsFailurePolicyDrift(t *testing.T) {
	fakeClaudeVersion(t, "2.1.295 (Claude Code)")
	e := engine(t)
	if err := os.MkdirAll(filepath.Join(e.Dir, "adapter"), 0700); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	if err := e.PrepareIntegrations([]byte("fixture"), filepath.Join(project, "aegis")); err != nil {
		t.Fatal(err)
	}
	i, err := e.InstallAgent(testActorContext(), "claude", "project", project, "")
	if err != nil {
		t.Fatal(err)
	}
	doc, _, _, err := loadHookDocument(i.Entry)
	if err != nil {
		t.Fatal(err)
	}
	h := doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	delete(h, "onFailure")
	modified := mustJSON(doc)
	if err = os.WriteFile(i.Entry, modified, 0600); err != nil {
		t.Fatal(err)
	}
	if e.agentEntryOK(i) {
		t.Fatal("removed onFailure was not detected")
	}
	if err = e.Uninstall(testActorContext(), i.ID); err == nil {
		t.Fatal("modified owned entry removed")
	}
	after, err := os.ReadFile(i.Entry)
	if err != nil || !bytes.Equal(after, modified) {
		t.Fatal("modified settings changed", err)
	}
}

func TestClaudeVersionProbeInheritedPipesBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX version-probe wrapper")
	}
	for _, wait := range []bool{false, true} {
		t.Run(map[bool]string{false: "wrapper_exits", true: "wrapper_waits"}[wait], func(t *testing.T) {
			dir := t.TempDir()
			pidPath := filepath.Join(dir, "child.pid")
			// Outlast the existing 3-second probe plus the same pipe-drain budget.
			program := "#!/bin/sh\n/bin/sleep 9 &\nprintf '%s' $! > '" + pidPath + "'\nprintf '2.1.295 (Claude Code)\\n'\n"
			if wait {
				program += "wait\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(program), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			t.Cleanup(func() {
				b, err := os.ReadFile(pidPath)
				if err != nil {
					t.Error(err)
					return
				}
				pid, err := strconv.Atoi(string(b))
				if err != nil {
					t.Error(err)
					return
				}
				if p, err := os.FindProcess(pid); err == nil {
					p.Kill()
				}
			})
			start := time.Now()
			i, warning := prepareClaudeHook(Installation{Agent: "claude", ManagedCommand: "fixture"})
			elapsed := time.Since(start)
			t.Logf("probe returned after %s", elapsed)
			// Local test scheduling allowance: 1 second beyond timeout + WaitDelay.
			if elapsed >= 7*time.Second {
				t.Fatalf("version probe exceeded timeout plus pipe-drain budget: %s", elapsed)
			}
			if warning == "" || strings.Contains(i.ManagedContent, "onFailure") {
				t.Fatal("incomplete probe confirmed failure blocking", warning, i.ManagedContent)
			}
		})
	}
}
