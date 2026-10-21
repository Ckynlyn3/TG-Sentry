package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repairFixture(t *testing.T, agent string) (string, clientEntry) {
	t.Helper()
	home, entry := driftFixture(t, agent)
	dir := filepath.Join(home, ".aegishook-client")
	data, err := os.ReadFile(filepath.Join(dir, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest clientManifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Resources = map[string]string{"index.ts": "saved-resource-digest"}
	manifest.Entries[0].CreatedFile = true
	manifest.Entries[0].CreatedDirs = []string{filepath.Dir(entry.Entry)}
	driftWrite(t, filepath.Join(dir, "client.json"), mustJSON(manifest))
	driftWrite(t, filepath.Join(dir, "adapter", "connection.json"), mustJSON(ClientConnection{NodeID: manifest.NodeID, Token: strings.Repeat("b", 64), Endpoint: "https://review.example"}))
	return home, entry
}

func TestClientRepairMissingAndIdempotent(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "codex-legacy", "cursor", "grok", "opencode", "pi"} {
		changes := []string{"file-missing", "missing", "replacement"}
		if agent == "opencode" || agent == "pi" {
			changes = []string{"file-missing"}
		}
		for _, change := range changes {
			t.Run(agent+"/"+change, func(t *testing.T) {
				home, entry := repairFixture(t, agent)
				if change == "file-missing" {
					if err := os.Remove(entry.Entry); err != nil {
						t.Fatal(err)
					}
				} else {
					var doc map[string]any
					data, _ := os.ReadFile(entry.Entry)
					if err := json.Unmarshal(data, &doc); err != nil {
						t.Fatal(err)
					}
					hooks := doc["hooks"].(map[string]any)
					delete(hooks, hookEvents(entry.Agent)[0])
					if change == "replacement" {
						hooks[hookEvents(entry.Agent)[0]] = []any{map[string]any{"command": "echo foreign-replacement"}}
					}
					event := hookEvents(entry.Agent)[1]
					hooks[event] = append(hooks[event].([]any), map[string]any{"command": "echo foreign-sibling"})
					doc["foreign"] = "untouched"
					driftWrite(t, entry.Entry, mustJSON(doc))
				}
				manifestPath := filepath.Join(home, ".aegishook-client", "client.json")
				connPath := filepath.Join(home, ".aegishook-client", "adapter", "connection.json")
				manifest, _ := os.ReadFile(manifestPath)
				conn, _ := os.ReadFile(connPath)
				result, err := ClientRepair(home)
				if err != nil || result.Action != "repair" || result.Remaining != 1 || len(result.Retained) != 0 {
					t.Fatalf("repair=%+v err=%v", result, err)
				}
				assertDrift(t, home, OwnedExact)
				if change != "file-missing" {
					data, _ := os.ReadFile(entry.Entry)
					if !bytes.Contains(data, []byte("echo foreign-sibling")) || !bytes.Contains(data, []byte("untouched")) || change == "replacement" && !bytes.Contains(data, []byte("echo foreign-replacement")) {
						t.Fatal("foreign hook lost")
					}
				}
				before, _ := os.ReadFile(entry.Entry)
				if _, err = ClientRepair(home); err != nil {
					t.Fatal(err)
				}
				after, _ := os.ReadFile(entry.Entry)
				if !bytes.Equal(before, after) {
					t.Fatal("second repair rewrote target")
				}
				gotManifest, _ := os.ReadFile(manifestPath)
				gotConn, _ := os.ReadFile(connPath)
				if !bytes.Equal(manifest, gotManifest) || !bytes.Equal(conn, gotConn) {
					t.Fatal("manifest/enrollment snapshot changed")
				}
			})
		}
	}
}

func TestClientRepairRetainsModifiedAndUnreadable(t *testing.T) {
	for _, change := range []string{"modified", "mixed", "unreadable", "root-missing", "enterprise", "symlink-parent"} {
		t.Run(change, func(t *testing.T) {
			home, entry := repairFixture(t, "claude")
			switch change {
			case "modified", "mixed":
				data, _ := os.ReadFile(entry.Entry)
				var doc map[string]any
				json.Unmarshal(data, &doc)
				hooks := doc["hooks"].(map[string]any)
				event := hookEvents(entry.Agent)[0]
				group := hooks[event].([]any)[0].(map[string]any)
				group["matcher"] = "changed"
				if change == "mixed" {
					hooks[event] = append(hooks[event].([]any), hookGroup(entry.Installation, event))
					delete(hooks, hookEvents(entry.Agent)[1])
				}
				driftWrite(t, entry.Entry, mustJSON(doc))
			case "unreadable":
				driftWrite(t, entry.Entry, []byte("not JSON"))
			case "root-missing":
				entry.Project = filepath.Join(home, "missing-project")
				entry.Entry = filepath.Join(entry.Project, ".claude", "settings.json")
				writeDriftManifest(t, home, []clientEntry{entry})
			case "enterprise":
				entry.Agent = "cursor"
				entry.Scope = "enterprise"
				writeDriftManifest(t, home, []clientEntry{entry})
			case "symlink-parent":
				mustHaveSymlink(t)
				if err := os.RemoveAll(filepath.Dir(entry.Entry)); err != nil {
					t.Fatal(err)
				}
				outside := t.TempDir()
				driftWrite(t, filepath.Join(outside, "settings.json"), []byte("outside-fixture"))
				if err := os.Symlink(outside, filepath.Dir(entry.Entry)); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(entry.Entry)
			result, err := ClientRepair(home)
			if err != nil || len(result.Retained) != 1 || result.Retained[0] != entry.Entry || result.Warning == "" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			after, _ := os.ReadFile(entry.Entry)
			if !bytes.Equal(before, after) {
				t.Fatal("refused target overwritten")
			}
		})
	}
}

func TestClientRepairRequiresSavedEnrollment(t *testing.T) {
	for _, change := range []string{"absent-manifest", "invalid-manifest", "absent-connection", "invalid-connection", "identity-mismatch", "invalid-trust", "enrolled-fallback"} {
		t.Run(change, func(t *testing.T) {
			home, entry := repairFixture(t, "claude")
			dir := filepath.Join(home, ".aegishook-client")
			connPath := filepath.Join(dir, "adapter", "connection.json")
			switch change {
			case "absent-manifest":
				os.Remove(filepath.Join(dir, "client.json"))
			case "invalid-manifest":
				driftWrite(t, filepath.Join(dir, "client.json"), []byte("{}"))
			case "absent-connection":
				os.Remove(connPath)
			case "invalid-connection":
				driftWrite(t, connPath, []byte("{}"))
			case "identity-mismatch":
				driftWrite(t, connPath, mustJSON(ClientConnection{NodeID: strings.Repeat("c", 32), Token: strings.Repeat("b", 64), Endpoint: "https://review.example"}))
			case "invalid-trust":
				driftWrite(t, connPath, mustJSON(ClientConnection{NodeID: strings.Repeat("a", 32), Token: strings.Repeat("b", 64), Endpoint: "https://review.example", BundleTrust: &SignedTrustRecord{}}))
			case "enrolled-fallback":
				if err := os.Rename(connPath, filepath.Join(dir, "enrolled.json")); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(entry.Entry); err != nil {
				t.Fatal(err)
			}
			_, err := ClientRepair(home)
			if change == "enrolled-fallback" {
				if err != nil {
					t.Fatal(err)
				}
				assertDrift(t, home, OwnedExact)
				return
			}
			if err == nil {
				t.Fatal("missing/invalid enrollment accepted")
			}
			if _, err := os.Stat(entry.Entry); !os.IsNotExist(err) {
				t.Fatal("hook written before enrollment validation")
			}
		})
	}
}

func TestClientRepairEditRevalidatesOwnership(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "opencode", "pi"} {
		t.Run(agent, func(t *testing.T) {
			home, entry := repairFixture(t, agent)
			root, err := openDriftRoot(home)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			rel, _ := filepath.Rel(home, entry.Entry)
			edit, err := clientRepairEdit(root, rel, entry)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkConfinedClientEdit(edit, false); err != nil {
				t.Fatal(err)
			}
			if _, err := clientRepairEdit(root, "../escape", entry); err == nil {
				t.Fatal("unconfined path accepted")
			}
			if err := os.Remove(entry.Entry); err != nil {
				t.Fatal(err)
			}
			driftWrite(t, entry.Entry, []byte("foreign-data"))
			if _, err := clientRepairEdit(root, rel, entry); err == nil {
				t.Fatal("foreign replacement accepted")
			}
			if err := checkConfinedClientEdit(edit, false); err == nil {
				t.Fatal("changed snapshot accepted")
			}
			if agent == "pi" {
				if err := os.Remove(entry.Entry); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("foreign-target", entry.Entry); err != nil {
					t.Fatal(err)
				}
				if _, err := clientRepairEdit(root, rel, entry); err == nil {
					t.Fatal("foreign Pi link accepted")
				}
			}
			if err := os.Remove(entry.Entry); err != nil {
				t.Fatal(err)
			}
			entry.ManagedContent = ""
			entry.ManagedCommand = ""
			if _, err := clientRepairEdit(root, rel, entry); err == nil {
				t.Fatal("empty ownership accepted")
			}
		})
	}
}

func TestClientRepairCustomRootsAndDirectoryRollback(t *testing.T) {
	for _, agent := range []string{"pi", "opencode"} {
		t.Run(agent, func(t *testing.T) {
			home, entry := repairFixture(t, agent)
			custom := t.TempDir()
			entry.Scope = "global"
			entry.Project = ""
			suffix := filepath.Join("plugins", "aegishook.js")
			if agent == "pi" {
				suffix = filepath.Join("extensions", "aegishook.ts")
			}
			entry.Entry = filepath.Join(custom, suffix)
			writeDriftManifest(t, home, []clientEntry{entry})
			if _, err := ClientRepair(home); err != nil {
				t.Fatal(err)
			}
			assertDrift(t, home, OwnedExact)
		})
	}
	home := t.TempDir()
	root, err := openDriftRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	first := clientEdit{root: root, path: filepath.Join("new-parent", "nested", "hook"), after: []byte("managed"), mode: 0600}
	second := clientEdit{root: root, path: "conflict", after: []byte("managed"), mode: 0600}
	driftWrite(t, filepath.Join(home, "conflict"), []byte("user"))
	if err := applyClientRepairEdits([]clientEdit{first, second}); err == nil {
		t.Fatal("conflict accepted")
	}
	if _, err := os.Stat(filepath.Join(home, "new-parent")); !os.IsNotExist(err) {
		t.Fatal("created directories not rolled back")
	}
}

func TestClientRepairConfinedRecheckAndRollback(t *testing.T) {
	for _, change := range []string{"parent-substitution", "edited-target"} {
		t.Run(change, func(t *testing.T) {
			mustHaveSymlink(t)
			home, entry := repairFixture(t, "claude")
			root, err := openDriftRoot(home)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			rel, _ := filepath.Rel(home, entry.Entry)
			driftWrite(t, entry.Entry, []byte("{}"))
			edit, err := clientRepairEdit(root, rel, entry)
			if err != nil {
				t.Fatal(err)
			}
			first := clientEdit{path: "first-created", after: []byte("first"), mode: 0600, root: root}
			if change == "parent-substitution" {
				outside := t.TempDir()
				driftWrite(t, filepath.Join(outside, "settings.json"), []byte("outside-fixture"))
				if err := os.Rename(filepath.Dir(entry.Entry), filepath.Dir(entry.Entry)+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Dir(entry.Entry)); err != nil {
					t.Fatal(err)
				}
			} else {
				driftWrite(t, entry.Entry, []byte("user-edit"))
			}
			before, _ := os.ReadFile(entry.Entry)
			if err := applyClientRepairEdits([]clientEdit{first, edit}); err == nil {
				t.Fatal("race accepted")
			}
			if _, err := os.Stat(filepath.Join(home, "first-created")); !os.IsNotExist(err) {
				t.Fatal("earlier edit not rolled back")
			}
			after, _ := os.ReadFile(entry.Entry)
			if !bytes.Equal(before, after) {
				t.Fatal("racing user edit/outside target changed")
			}
		})
	}
}

func TestClientRepairLockAndManifestBoundaries(t *testing.T) {
	for _, change := range []string{"locked", "lock-directory", "lock-symlink", "manifest-symlink", "relative-home", "missing-home"} {
		t.Run(change, func(t *testing.T) {
			home, entry := repairFixture(t, "claude")
			dir := filepath.Join(home, ".aegishook-client")
			lockPath := filepath.Join(dir, "client.lock")
			switch change {
			case "locked":
				file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := lockProcessFile(file); err != nil {
					t.Fatal(err)
				}
			case "lock-directory":
				if err := os.Mkdir(lockPath, 0700); err != nil {
					t.Fatal(err)
				}
			case "lock-symlink":
				mustHaveSymlink(t)
				outside := filepath.Join(t.TempDir(), "lock")
				driftWrite(t, outside, []byte("outside"))
				if err := os.Symlink(outside, lockPath); err != nil {
					t.Fatal(err)
				}
			case "manifest-symlink":
				mustHaveSymlink(t)
				path := filepath.Join(dir, "client.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "manifest")
				driftWrite(t, outside, data)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "relative-home":
				home = "relative"
			case "missing-home":
				home = filepath.Join(home, "absent")
			}
			if err := os.Remove(entry.Entry); err != nil {
				t.Fatal(err)
			}
			if _, err := ClientRepair(home); err == nil {
				t.Fatal("unsafe repair accepted")
			}
			if _, err := os.Stat(entry.Entry); !os.IsNotExist(err) {
				t.Fatal("target written despite refused boundary")
			}
		})
	}
}

func TestClientRepairRefusesExpandedDocumentBeforeTransaction(t *testing.T) {
	home, first := repairFixture(t, "claude")
	second := first
	second.Entry = filepath.Join(filepath.Dir(first.Entry), "settings-secondary.json")
	// Derive the fixture size from the existing parse budget: compact array values
	// fit, while the installer's existing indented encoding exceeds that budget.
	values := bytes.TrimSuffix(bytes.Repeat([]byte("0,"), clientDriftMaxBytes/4), []byte(","))
	compact := append([]byte(`{"foreign":[`), values...)
	compact = append(compact, []byte("]}")...)
	var doc map[string]any
	if err := json.Unmarshal(compact, &doc); err != nil {
		t.Fatal(err)
	}
	expanded, _, _, err := mergeHookDocument(second.Installation, true, doc, compact, 0600)
	if err != nil || len(compact) > clientDriftMaxBytes || len(expanded) <= clientDriftMaxBytes {
		t.Fatalf("fixture does not cross the existing budget: input=%d output=%d err=%v", len(compact), len(expanded), err)
	}
	driftWrite(t, first.Entry, []byte("{}"))
	driftWrite(t, second.Entry, compact)
	manifestPath := filepath.Join(home, ".aegishook-client", "client.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest clientManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	// The repeated first entry deterministically causes a late expected-byte
	// conflict in the unfixed transaction, exercising rollback after both writes.
	manifest.Entries = []clientEntry{first, second, first}
	driftWrite(t, manifestPath, mustJSON(manifest))
	paths := []string{first.Entry, second.Entry, manifestPath, filepath.Join(home, ".aegishook-client", "adapter", "connection.json")}
	originals := make(map[string][]byte)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		originals[path] = data
	}
	result, err := ClientRepair(home)
	if err != nil || len(result.Retained) != 1 || result.Retained[0] != second.Entry || result.Warning == "" || result.Remaining != len(manifest.Entries) {
		t.Errorf("oversized generated document was not refused before commit: result=%+v err=%v", result, err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, originals[path]) {
			t.Errorf("original bytes changed at %s: err=%v", path, err)
		}
	}
}
