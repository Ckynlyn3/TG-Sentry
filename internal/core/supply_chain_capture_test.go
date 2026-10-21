package core

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"aegishook/internal/core/discovery"
)

// S2 capture -> contract binding. discovery cannot import core (core imports
// discovery at discovery_client.go), so the step that turns a captured
// membership into a trusted SupplyChainSubject is proved here, where the
// subject contract lives.
func TestCapturedSkillBindsToSupplyChainSubject(t *testing.T) {
	home := t.TempDir()
	root, state, reason := discovery.OpenHome(home, strconv.Itoa(os.Getuid()))
	if state != discovery.HomeReadable || reason != "" || root == nil {
		t.Fatalf("OpenHome = %v %q", state, reason)
	}
	t.Cleanup(func() { _ = root.Close() })
	skillRoot := ".claude/skills/example"
	for rel, data := range map[string]string{"SKILL.md": "# example\n", "scripts/run.sh": "echo run\n"} {
		path := filepath.Join(home, filepath.FromSlash(skillRoot+"/"+rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	capture := func() SupplyChainSubject {
		t.Helper()
		captured, reason := root.CaptureSkill(context.Background(), skillRoot)
		if reason != "" {
			t.Fatalf("CaptureSkill reason = %q", reason)
		}
		t.Cleanup(func() { _ = os.RemoveAll(captured.Dir) })
		subject, err := NewSupplyChainSubject(captured.Files)
		if err != nil {
			t.Fatalf("NewSupplyChainSubject(%v) = %v", captured.Files, err)
		}
		if !reflect.DeepEqual(subject.Files, captured.Files) {
			t.Fatalf("subject.Files = %v, want the captured membership %v", subject.Files, captured.Files)
		}
		return subject
	}
	before := capture()
	// A changed sibling invalidates the subject even though SKILL.md did not
	// change (supply_chain.go:60-65).
	path := filepath.Join(home, filepath.FromSlash(skillRoot+"/scripts/run.sh"))
	if err := os.WriteFile(path, []byte("echo changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := capture()
	if after.Files["SKILL.md"] != before.Files["SKILL.md"] {
		t.Fatalf("SKILL.md hash changed: %v %v", before.Files, after.Files)
	}
	if after.Files["scripts/run.sh"] == before.Files["scripts/run.sh"] || after.Digest == before.Digest {
		t.Fatalf("sibling change did not change the subject: %v %v", before, after)
	}
}

// LF/CR cannot enter the subject's newline-delimited membership serialization.
// Capture must reject them before it can return apparently bindable membership.
func TestCapturedSkillRejectsUnbindableSubjectNames(t *testing.T) {
	for _, name := range []string{"line\nbreak", "carriage\rreturn"} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			home := t.TempDir()
			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			root, state, reason := discovery.OpenHome(home, strconv.Itoa(os.Getuid()))
			if state != discovery.HomeReadable || reason != "" || root == nil {
				t.Fatalf("OpenHome = %v %q", state, reason)
			}
			t.Cleanup(func() { _ = root.Close() })
			skill := filepath.Join(home, "skill")
			if err := os.Mkdir(skill, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, member := range []string{"SKILL.md", name} {
				if err := os.WriteFile(filepath.Join(skill, member), []byte("inert\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			captured, reason := root.CaptureSkill(context.Background(), "skill")
			if captured.Dir != "" {
				t.Cleanup(func() { _ = os.RemoveAll(captured.Dir) })
			}
			if _, err := NewSupplyChainSubject(captured.Files); err == nil {
				t.Fatal("rejected capture constructed a subject")
			}
			if reason != discovery.ReasonEscapedRoot || captured.Dir != "" || captured.Files != nil {
				t.Fatalf("capture-to-subject boundary accepted %q: %+v %q", name, captured, reason)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("rejected capture left %d snapshot entries: %v", len(entries), err)
			}
		})
	}
}
