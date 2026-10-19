package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexInstallNativeBudgetAndSnapshot(t *testing.T) {
	for _, installer := range []string{"client", "engine"} {
		t.Run(installer, func(t *testing.T) {
			o := clientFixture(t, "codex")
			var path string
			var uninstall func() error
			if installer == "client" {
				r, err := ClientOperation("install", o)
				if err != nil {
					t.Fatal(err)
				}
				path = r.Entry
				uninstall = func() error { _, err := ClientOperation("uninstall", o); return err }
			} else {
				e := engine(t)
				if err := os.MkdirAll(filepath.Join(e.Dir, "adapter"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := e.PrepareIntegrations([]byte("fixture"), o.Binary); err != nil {
					t.Fatal(err)
				}
				i, err := e.InstallAgent(testActorContext(), "codex", "project", o.Project, "")
				if err != nil {
					t.Fatal(err)
				}
				path = i.Entry
				uninstall = func() error { return e.Uninstall(testActorContext(), i.ID) }
				if !e.agentEntryOK(i) {
					t.Fatal("owned snapshot not recognized")
				}
			}
			if filepath.Base(path) != "hooks.json" {
				t.Fatal(path)
			}
			doc, _, mode, err := loadHookDocument(path)
			if err != nil {
				t.Fatal(err)
			}
			hooks := doc["hooks"].(map[string]any)
			if _, ok := hooks["PostToolUseFailure"]; ok {
				t.Fatal("undocumented Codex event")
			}
			for _, event := range hookEvents("codex") {
				h := hooks[event].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
				want := float64(5) // AgentSentry command-hook precedent, ENDPOINT-RUNTIME §4.
				if event == "SessionEnd" {
					want = 3
				} // Codex documented maximum.
				if h["timeout"] != want {
					t.Fatalf("%s timeout = %v; want %v", event, h["timeout"], want)
				}
			}
			// Reuse the installer's exact JSON merge/uninstall, preserving unrelated hooks.
			doc["foreign"] = true
			hooks["PreToolUse"] = append(hooks["PreToolUse"].([]any), map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "echo foreign"}}})
			if err := AtomicFile(path, mustJSON(doc), mode); err != nil {
				t.Fatal(err)
			}
			if err := uninstall(); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(b, []byte("echo foreign")) || !bytes.Contains(b, []byte("foreign")) {
				t.Fatal(string(b), err)
			}
		})
	}
}

func TestCodexTOMLGenerators(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "program with space's")
	connection := filepath.Join(t.TempDir(), "connection.json")
	for _, managed := range []bool{false, true} {
		out, err := CodexHookTOML(binary, connection, managed)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "allow_managed_hooks_only = true") != managed || strings.Contains(out, "[features]\nhooks = true") != managed {
			t.Fatal(out)
		}
		if strings.Contains(out, "managed_dir = ") != managed {
			t.Fatal("requirements need an absolute existing managed directory", out)
		}
		for _, event := range hookEvents("codex") {
			if !strings.Contains(out, "[[hooks."+event+"]]\n") || !strings.Contains(out, "[[hooks."+event+".hooks]]\n") {
				t.Fatal(out)
			}
		}
		if !strings.Contains(out, "timeout = 5") || strings.Contains(out, "PostToolUseFailure") || strings.Contains(out, "onFailure") {
			t.Fatal(out)
		}
		// JSON basic strings are the TOML basic-string subset emitted by this generator.
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "command = ") {
				var command string
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "command = ")), &command); err != nil || !strings.Contains(command, "hook --agent codex --connection") {
					t.Fatal(line, err)
				}
			}
		}
	}
	for _, paths := range [][2]string{{"relative", connection}, {binary, "relative"}, {binary + "\x00", connection}, {binary, connection + string([]byte{0xff})}} {
		if _, err := CodexHookTOML(paths[0], paths[1], true); err == nil {
			t.Fatal("invalid path accepted", paths)
		}
	}
}

func TestCodexLegacyHookSnapshotUnchanged(t *testing.T) {
	i := Installation{Agent: "codex", ManagedCommand: "fixture"}
	if h := hookGroup(i, "PreToolUse")["hooks"].([]any)[0].(map[string]any); h["timeout"] != 86520 {
		t.Fatal("legacy ownership changed", h)
	}
	prepared := prepareCodexHook(i)
	if h := hookGroup(prepared, "PreToolUse")["hooks"].([]any)[0].(map[string]any); h["timeout"] != float64(5) {
		t.Fatal(h)
	}
	prepared.ManagedContent = "invalid"
	if len(hookGroup(prepared, "PreToolUse")) != 0 {
		t.Fatal("invalid snapshot accepted")
	}
}
