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

// Fixtures reuse the installer's snapshotted groups, including Codex's legacy path.
func driftFixture(t *testing.T, agent string) (string, clientEntry) {
	t.Helper()
	home := t.TempDir()
	o := ClientOptions{Dir: filepath.Join(home, ".aegishook-client"), Binary: filepath.Join(home, "runner"), Agent: agent, Scope: "project", Project: home}
	if agent == "codex-legacy" {
		o.Agent = "codex"
	}
	entry, err := clientTarget(o)
	if err != nil {
		t.Fatal(err)
	}
	if agent == "claude" {
		entry.ManagedContent = string(mustJSON(hookGroup(entry.Installation, "PreToolUse")))
	}
	if agent == "codex" {
		entry.Installation = prepareCodexHook(entry.Installation)
	}
	writeDriftManifest(t, home, []clientEntry{entry})
	writeDriftTarget(t, entry)
	return home, entry
}

func writeDriftManifest(t *testing.T, home string, entries []clientEntry) {
	t.Helper()
	driftWrite(t, filepath.Join(home, ".aegishook-client", "client.json"), mustJSON(clientManifest{Format: 1, NodeID: strings.Repeat("a", 32), Entries: entries}))
}

func driftWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeDriftTarget(t *testing.T, entry clientEntry) {
	t.Helper()
	if entry.Agent == "pi" {
		mustHaveSymlink(t)
		if err := os.MkdirAll(filepath.Dir(entry.Entry), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(entry.ManagedContent, entry.Entry); err != nil {
			t.Fatal(err)
		}
		return
	}
	if entry.Agent == "opencode" {
		driftWrite(t, entry.Entry, []byte(entry.ManagedContent))
		return
	}
	hooks := map[string]any{}
	for _, event := range hookEvents(entry.Agent) {
		hooks[event] = []any{hookGroup(entry.Installation, event)}
	}
	doc := map[string]any{"hooks": hooks}
	if entry.Agent == "cursor" {
		doc["version"] = 1
	}
	driftWrite(t, entry.Entry, mustJSON(doc))
}

func assertDrift(t *testing.T, home string, want OwnerState) DriftReport {
	t.Helper()
	report, err := ClientDrift(home)
	if err != nil || report.Manifest != ManifestOK || len(report.Entries) != 1 || report.Entries[0].OwnerState != want {
		t.Fatalf("manifest=%s entry count=%d; want ownerState=%s; err=%v", report.Manifest, len(report.Entries), want, err)
	}
	return report
}

func TestClientDriftGroups(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "codex-legacy", "cursor", "grok"} {
		for _, change := range []string{"exact", "remove", "matcher", "timeout", "replace", "mixed", "mixed-missing", "foreign", "malformed", "version"} {
			t.Run(agent+"/"+change, func(t *testing.T) {
				home, entry := driftFixture(t, agent)
				data, err := os.ReadFile(entry.Entry)
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				hooks := doc["hooks"].(map[string]any)
				events := hookEvents(entry.Agent)
				event := events[0]
				group := hooks[event].([]any)[0].(map[string]any)
				want := OwnedExact
				switch change {
				case "remove":
					delete(hooks, event)
					want = OwnerMissing
				case "matcher", "mixed", "mixed-missing":
					group["matcher"] = "Read"
					want = OwnedModified
					if change != "matcher" {
						hooks[event] = append(hooks[event].([]any), hookGroup(entry.Installation, event))
					}
					if change == "mixed-missing" {
						delete(hooks, events[1])
					}
				case "timeout":
					if entry.Agent != "cursor" {
						group = group["hooks"].([]any)[0].(map[string]any)
					}
					group["timeout"] = 42
					want = OwnedModified
				case "replace":
					if entry.Agent != "cursor" {
						group = group["hooks"].([]any)[0].(map[string]any)
					}
					group["command"] = "foreign-replacement"
					delete(group, "commandWindows")
					want = OwnerMissing
				case "foreign":
					hooks[event] = append(hooks[event].([]any), map[string]any{"command": "foreign-not-owned"})
				case "version":
					if entry.Agent == "cursor" {
						doc["version"] = 2
						want = OwnedModified
					}
				}
				data = mustJSON(doc)
				if change == "malformed" {
					data = []byte("not-json")
					want = OwnerUnreadable
				}
				driftWrite(t, entry.Entry, data)
				assertDrift(t, home, want)
				after, err := os.ReadFile(entry.Entry)
				if err != nil || !bytes.Equal(data, after) {
					t.Fatal("detection changed target")
				}
			})
		}
	}
}

func TestClientDriftWrapperAndPi(t *testing.T) {
	for _, agent := range []string{"opencode", "pi"} {
		for _, change := range []string{"exact", "modified", "file-missing", "directory", "foreign-link"} {
			t.Run(agent+"/"+change, func(t *testing.T) {
				home, entry := driftFixture(t, agent)
				want := OwnedExact
				if change != "exact" {
					if err := os.Remove(entry.Entry); err != nil {
						t.Fatal(err)
					}
				}
				switch change {
				case "modified":
					driftWrite(t, entry.Entry, []byte("foreign-wrapper-fixture"))
					want = OwnedModified
				case "file-missing":
					want = OwnerFileMissing
				case "directory":
					if err := os.Mkdir(entry.Entry, 0700); err != nil {
						t.Fatal(err)
					}
					want = OwnerUnreadable
				case "foreign-link":
					mustHaveSymlink(t)
					if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), entry.Entry); err != nil {
						t.Fatal(err)
					}
					want = OwnerUnreadable
					if agent == "pi" {
						want = OwnedModified
					}
				}
				assertDrift(t, home, want)
			})
		}
	}
}

func TestClientDriftManifestOutcomes(t *testing.T) {
	for _, state := range []string{"absent", "malformed", "format", "node", "directory", "fifo", "symlink", "permission", "empty"} {
		t.Run(state, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".aegishook-client", "client.json")
			want := ManifestInvalid
			switch state {
			case "absent":
				want = ManifestAbsent
			case "malformed":
				driftWrite(t, path, []byte("not-json"))
			case "format":
				driftWrite(t, path, []byte(`{"format":2}`))
			case "node":
				driftWrite(t, path, []byte(`{"format":1}`))
			case "empty":
				writeDriftManifest(t, home, nil)
				want = ManifestOK
			case "directory":
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
				want = ManifestUnreadable
			case "fifo":
				driftFIFO(t, path)
				want = ManifestUnreadable
			case "symlink":
				mustHaveSymlink(t)
				outside := filepath.Join(t.TempDir(), "outside")
				driftWrite(t, outside, []byte("outside-manifest-fixture"))
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
				want = ManifestUnreadable
			case "permission":
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("POSIX permission-denied fixture requires an unprivileged Unix user")
				}
				writeDriftManifest(t, home, nil)
				if err := os.Chmod(path, 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0600) })
				want = ManifestUnreadable
			}
			report, err := ClientDrift(home)
			if err != nil || report.Manifest != want || len(report.Entries) != 0 || ClientHooksConfigured(home) {
				t.Fatalf("manifest=%s; want=%s; err=%v", report.Manifest, want, err)
			}
		})
	}
}

func driftFIFO(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows filesystem namespace has no POSIX FIFO; Lstat and handle Stat cover special targets")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("mkfifo", path).Run(); err != nil {
		t.Fatal(err)
	}
}

func TestClientDriftConfinedTargets(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "cursor", "grok", "opencode", "pi"} {
		for _, change := range []string{"fifo", "directory", "file-missing", "parent-escape", "leaf-link", "project-missing"} {
			t.Run(agent+"/"+change, func(t *testing.T) {
				home, entry := driftFixture(t, agent)
				if err := os.Remove(entry.Entry); err != nil {
					t.Fatal(err)
				}
				want := OwnerUnreadable
				switch change {
				case "fifo":
					driftFIFO(t, entry.Entry)
				case "directory":
					if err := os.Mkdir(entry.Entry, 0700); err != nil {
						t.Fatal(err)
					}
				case "file-missing":
					want = OwnerFileMissing
				case "parent-escape":
					mustHaveSymlink(t)
					outside := t.TempDir()
					foreign := entry
					foreign.Entry = filepath.Join(outside, filepath.Base(entry.Entry))
					writeDriftTarget(t, foreign)
					// The outside fixture is exact. Reading it would incorrectly report exact.
					if err := os.RemoveAll(filepath.Dir(entry.Entry)); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, filepath.Dir(entry.Entry)); err != nil {
						t.Fatal(err)
					}
				case "leaf-link":
					mustHaveSymlink(t)
					if err := os.Symlink(filepath.Join(home, "inside"), entry.Entry); err != nil {
						t.Fatal(err)
					}
					if agent == "pi" {
						want = OwnedModified
					}
				case "project-missing":
					entry.Project = filepath.Join(home, "absent-project")
					entry.Entry = filepath.Join(entry.Project, "."+agent, filepath.Base(entry.Entry))
					writeDriftManifest(t, home, []clientEntry{entry})
				}
				assertDrift(t, home, want)
			})
		}
	}
}

func TestClientDriftCustomRootsAndEnterprise(t *testing.T) {
	for _, agent := range []string{"opencode", "pi"} {
		t.Run(agent, func(t *testing.T) {
			home, entry := driftFixture(t, agent)
			entry.Scope, entry.Project = "global", ""
			part := "plugins"
			if agent == "pi" {
				part = "extensions"
			}
			entry.Entry = filepath.Join(t.TempDir(), part, filepath.Base(entry.Entry))
			writeDriftTarget(t, entry)
			writeDriftManifest(t, home, []clientEntry{entry})
			assertDrift(t, home, OwnedExact)
			entry.Entry = filepath.Join(filepath.Dir(entry.Entry), "wrong-suffix")
			writeDriftManifest(t, home, []clientEntry{entry})
			assertDrift(t, home, OwnerUnreadable)
		})
	}
	home, entry := driftFixture(t, "cursor")
	entry.Scope = "enterprise"
	writeDriftManifest(t, home, []clientEntry{entry})
	assertDrift(t, home, OwnerNotEvaluated)
	if ClientHooksConfigured(home) {
		t.Fatal("enterprise-only staging is not configured")
	}
	_, evaluated := driftFixture(t, "claude")
	writeDriftManifest(t, home, []clientEntry{entry, evaluated})
	if !ClientHooksConfigured(home) {
		t.Fatal("enterprise staging must not veto an exact evaluated entry")
	}
}

func TestClientDriftReportOnlyMetadata(t *testing.T) {
	home, entry := driftFixture(t, "opencode")
	report := assertDrift(t, home, OwnedExact)
	data := mustJSON(report)
	if bytes.Contains(data, []byte(entry.ManagedContent)) || bytes.Contains(data, []byte(entry.ManagedCommand)) || bytes.Contains(data, []byte("digest")) {
		t.Fatal("report contains fixture content or digest")
	}
	var output struct{ Entries []map[string]any }
	if err := json.Unmarshal(data, &output); err != nil || len(output.Entries) != 1 || len(output.Entries[0]) != 4 {
		t.Fatal("entry report must contain exactly four metadata fields")
	}
	for _, key := range []string{"agent", "scope", "entry", "ownerState"} {
		if _, ok := output.Entries[0][key]; !ok {
			t.Fatal("missing report field", key)
		}
	}
}

func TestClientDriftHomeAndEntryValidation(t *testing.T) {
	for _, home := range []string{"relative-home", filepath.Join(t.TempDir(), "missing")} {
		report, err := ClientDrift(home)
		if err != nil || report.Manifest != ManifestUnreadable {
			t.Fatal("unavailable home was trusted")
		}
	}
	for _, change := range []string{"global", "scope", "agent", "relative-entry", "outside-entry", "relative-project", "bad-snapshot", "no-command", "no-hooks", "bad-hooks", "bad-event", "extra-event", "in-root-parent"} {
		t.Run(change, func(t *testing.T) {
			home, entry := driftFixture(t, "codex")
			want := OwnerUnreadable
			switch change {
			case "global":
				entry.Scope, entry.Project = "global", ""
				want = OwnedExact
			case "scope":
				entry.Scope = "unsupported"
			case "agent":
				entry.Agent = "unsupported"
			case "relative-entry":
				entry.Entry = "relative"
			case "outside-entry":
				entry.Entry = filepath.Join(t.TempDir(), "hooks.json")
			case "relative-project":
				entry.Project = "relative"
			case "bad-snapshot":
				entry.ManagedContent = "invalid"
			case "no-command":
				entry.ManagedCommand = ""
			case "no-hooks":
				driftWrite(t, entry.Entry, []byte(`{}`))
				want = OwnerMissing
			case "bad-hooks":
				driftWrite(t, entry.Entry, []byte(`{"hooks":[]}`))
			case "bad-event":
				driftWrite(t, entry.Entry, []byte(`{"hooks":{"SessionStart":{}}}`))
			case "extra-event":
				data, err := os.ReadFile(entry.Entry)
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				doc["hooks"].(map[string]any)["UnknownEvent"] = false
				driftWrite(t, entry.Entry, mustJSON(doc))
			case "in-root-parent":
				mustHaveSymlink(t)
				old := filepath.Dir(entry.Entry)
				if err := os.Rename(old, old+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(old)+"-moved", old); err != nil {
					t.Fatal(err)
				}
				want = OwnedExact
			}
			writeDriftManifest(t, home, []clientEntry{entry})
			assertDrift(t, home, want)
			if ClientHooksConfigured(home) != (want == OwnedExact) {
				t.Fatal("configured mapping does not match evaluated state")
			}
		})
	}
}

func TestClientDriftManifestParentEscape(t *testing.T) {
	mustHaveSymlink(t)
	home := t.TempDir()
	outside := t.TempDir()
	// Valid outside manifest: following it would produce ok instead of unreadable.
	driftWrite(t, filepath.Join(outside, "client.json"), mustJSON(clientManifest{Format: 1, NodeID: strings.Repeat("a", 32)}))
	if err := os.Symlink(outside, filepath.Join(home, ".aegishook-client")); err != nil {
		t.Fatal(err)
	}
	report, err := ClientDrift(home)
	if err != nil || report.Manifest != ManifestUnreadable || len(report.Entries) != 0 {
		t.Fatal("manifest parent escaped home")
	}
}

func TestClientDriftTargetPermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX permission-denied fixture requires an unprivileged Unix user")
	}
	home, entry := driftFixture(t, "claude")
	if err := os.Chmod(entry.Entry, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(entry.Entry, 0600) })
	assertDrift(t, home, OwnerUnreadable)
}

func TestClientDriftRejectDuplicateMembers(t *testing.T) {
	for _, addition := range []string{
		`"entries":[{}]`,
		`"format":2,"format":1`,
		`"ENTRIES":[{}]`,
		`"format":1`,
		`"ignored":{"nested":[{"key":false,"key":true}]}`,
		`"ignored":{"nested":[{"key":false,"KEY":true}]}`,
		`"ignored":{"K":false,"K":true}`,
	} {
		home, _ := driftFixture(t, "claude")
		path := filepath.Join(home, ".aegishook-client", "client.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = append(append(data[:len(data)-1], ','), []byte(addition+"}")...)
		driftWrite(t, path, data)
		report, err := ClientDrift(home)
		if err != nil || report.Manifest != ManifestInvalid || len(report.Entries) != 0 || ClientHooksConfigured(home) {
			t.Errorf("duplicate member accepted: manifest=%s; entries=%d; err=%v", report.Manifest, len(report.Entries), err)
		}
	}
}

func TestClientDriftManifestSizeBoundary(t *testing.T) {
	home, _ := driftFixture(t, "claude")
	path := filepath.Join(home, ".aegishook-client", "client.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// #38/41 plan §11 R7 and server.go read(): the approved 2 MiB local budget.
	data = append(data, bytes.Repeat([]byte(" "), PolicyBundleMaxBytes-len(data))...)
	for _, extra := range []int{0, 1} {
		driftWrite(t, path, append(data, bytes.Repeat([]byte(" "), extra)...))
		report, err := ClientDrift(home)
		want := ManifestOK
		if extra != 0 {
			want = ManifestInvalid
		}
		if err != nil || report.Manifest != want || (extra != 0 && len(report.Entries) != 0) {
			t.Errorf("manifest size cap+%d: manifest=%s; want=%s; err=%v", extra, report.Manifest, want, err)
		}
		if ClientHooksConfigured(home) != (extra == 0) {
			t.Errorf("manifest size cap+%d: incorrect configured result", extra)
		}
	}
}

func TestClientDriftHookSizeBoundary(t *testing.T) {
	home, entry := driftFixture(t, "claude")
	data, err := os.ReadFile(entry.Entry)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, bytes.Repeat([]byte(" "), PolicyBundleMaxBytes-len(data))...)
	for _, extra := range []int{0, 1} {
		driftWrite(t, entry.Entry, append(data, bytes.Repeat([]byte(" "), extra)...))
		report, err := ClientDrift(home)
		want := "owned_exact"
		if extra != 0 {
			want = "unreadable"
		}
		if err != nil || report.Manifest != ManifestOK || len(report.Entries) != 1 || string(report.Entries[0].OwnerState) != want {
			t.Errorf("hook size cap+%d: expected ownerState=%s; err=%v", extra, want, err)
		}
		if ClientHooksConfigured(home) != (extra == 0) {
			t.Errorf("hook size cap+%d: incorrect configured result", extra)
		}
	}
}

func TestClientDriftJSONTokenBoundaries(t *testing.T) {
	for _, data := range []string{
		`{"nested":[{"key":true},{"key":false}]}`,
		`{"ignored":1e400}`,
	} {
		if !validDriftJSON([]byte(data)) {
			t.Fatal("unique object rejected")
		}
	}
	for _, data := range []string{
		``, `{"key"`, `{"key":`, `{"key":true`, `{"key":[]`,
		`[`, `[null,]`, `{"key":true,}`, `{} {}`, `[] true`,
	} {
		if validDriftJSON([]byte(data)) {
			t.Fatal("invalid JSON accepted")
		}
	}
}

func TestClientDriftJSONUsesStandardNestingBound(t *testing.T) {
	// One beyond Go encoding/json/scanner.go's maxNestingDepth, not a new limit.
	data := []byte(strings.Repeat("[", 10001) + strings.Repeat("]", 10001))
	if validDriftJSON(data) {
		t.Fatal("JSON deeper than the standard decoder bound accepted")
	}
}
