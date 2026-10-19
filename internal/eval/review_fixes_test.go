package eval

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPinnedAgentDojoConversionSemantics(t *testing.T) {
	data := `{"injections":{},"messages":[{"role":"tool","error":null,"content":[{"type":"text","content":"FAKE first"},{"type":"thinking","content":"FAKE thought","id":null},{"type":"redacted_thinking","content":null},{"type":"text","content":""},{"type":"text","content":"FAKE last"}]}]}`
	rows, err := Adapt(strings.NewReader(data), Dataset{Name: "AgentDojo"}, LockedFile{Variant: "clean"})
	if err != nil || len(rows) != 1 || rows[0].Input.Text != "FAKE first\nFAKE thought\n\nFAKE last" {
		t.Fatal("pinned conversion semantics", err)
	}
	for _, blocks := range []string{`"FAKE legacy string"`, `[{"type":"unknown","content":"FAKE"}]`, `[{"type":"text"}]`, `[{"type":"text","content":17}]`} {
		data = `{"messages":[{"role":"tool","content":` + blocks + `}]}`
		if _, err = Adapt(strings.NewReader(data), Dataset{Name: "AgentDojo"}, LockedFile{Variant: "clean"}); err == nil {
			t.Fatal("invalid content accepted")
		}
	}
}

func TestGitIndexFlagsRefusedByBothChecks(t *testing.T) {
	for _, flag := range []string{"--assume-unchanged", "--skip-worktree"} {
		t.Run(flag, func(t *testing.T) {
			o, _ := syntheticRun(t)
			gitTest(t, o.Root, "update-index", flag, "eval/manifest.json")
			if _, err := CheckGit(o.Root); err == nil {
				t.Fatal("index flag accepted")
			}
			if err := checkDocument(o.Root, o.Manifest, "eval/manifest.json"); err == nil {
				t.Fatal("document index flag accepted")
			}
		})
	}
}

func TestGitRepositoryOverridesCannotRedirectValidation(t *testing.T) {
	o, _ := syntheticRun(t)
	other, _ := syntheticRun(t)
	// Change a tracked document only in the other synthetic repository, so a
	// redirected git show would disagree with the real root's on-disk bytes.
	os.WriteFile(other.Manifest, []byte(`{"fake":"other repository"}`), 0600)
	gitTest(t, other.Root, "add", ".")
	gitTest(t, other.Root, "commit", "-m", "synthetic other document")
	for _, key := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_SHALLOW_FILE", "GIT_GRAFT_FILE", "GIT_CONFIG_COUNT"} {
		t.Run(key, func(t *testing.T) {
			value := "nonexistent-synthetic-override"
			switch key {
			case "GIT_DIR", "GIT_COMMON_DIR":
				value = filepath.Join(other.Root, ".git")
			case "GIT_WORK_TREE":
				value = other.Root
			case "GIT_INDEX_FILE":
				value = filepath.Join(other.Root, ".git/index")
			case "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES":
				value = filepath.Join(other.Root, ".git/objects")
			case "GIT_CONFIG_COUNT":
				value = "1"
			}
			t.Setenv(key, value)
			if _, err := CheckGit(o.Root); err != nil {
				t.Fatal("override affected clean bound root", key, err)
			}
			if err := checkDocument(o.Root, o.Manifest, "eval/manifest.json"); err != nil {
				t.Fatal("override affected bound document", key, err)
			}
		})
	}
}

func TestUnavailableDecisionSentinelAbsentFromEveryOutput(t *testing.T) {
	const sentinel = "SYNTHETIC INPUT SENTINEL MUST NOT LEAK"
	detector := &fakeDetector{result: Result{Unavailable: true, Reason: "timeout", Decision: sentinel}}
	observation, err := observe(context.Background(), Dataset{Name: "NotInject"}, Item{ID: "opaque", Input: Input{Text: sentinel}}, testConfig(), nil, detector)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the output boundary independently as well as observe, including
	// callers which supply observations directly to WriteReports.
	for _, row := range []Observation{observation, {Item: Item{ID: "opaque"}, Result: Result{Unavailable: true, Reason: "timeout", Decision: sentinel}}} {
		out := filepath.Join(t.TempDir(), "out")
		if err := WriteReports(out, Report{}, []Observation{row}); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"items.jsonl", "report.json", "report.md"} {
			b, err := os.ReadFile(filepath.Join(out, name))
			if err != nil || strings.Contains(string(b), sentinel) {
				t.Fatal("sentinel in output", name, err)
			}
		}
	}
}

func TestUnsupportedFullPathManifestRejectedBeforeCalls(t *testing.T) {
	o, _ := syntheticRun(t)
	var m Manifest
	if err := Load(o.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	m.Sets[0].Mode = "full-path"
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "no admissible dataset supplies native review input (gap)") {
		t.Fatal("missing explicit mode gap", err)
	}
	writeJSONTest(t, o.Manifest, m)
	gitTest(t, o.Root, "add", ".")
	gitTest(t, o.Root, "commit", "-m", "synthetic unsupported mode")
	gitTest(t, o.Root, "tag", "-f", FreezeTag, "HEAD")
	if _, err := runOnHost(context.Background(), o, "linux", "amd64"); err == nil || !strings.Contains(err.Error(), "no admissible dataset supplies native review input (gap)") {
		t.Fatal("preflight did not reject unsupported mode", err)
	}
	if o.Detector.(*fakeDetector).calls != 0 {
		t.Fatal("detector called before mode refusal")
	}
}

func countGuardRun(t *testing.T, name string, n int) RunOptions {
	t.Helper()
	o, c := syntheticRun(t)
	var m Manifest
	var lock Lock
	if err := Load(o.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	if err := Load(o.Lock, &lock); err != nil {
		t.Fatal(err)
	}
	m.Sets[0].Name = name
	if name == "CPAD" {
		m.Sets[0].FieldMap = &FieldMap{Format: "json", Text: "prompt", Label: true, Category: m.Sets[0].Category, Surface: "prompt"}
	}
	c.TagMapping = map[string][]string{name: {"1"}}
	writeJSONTest(t, o.Manifest, m)
	writeJSONTest(t, o.Config, c)
	gitTest(t, o.Root, "add", ".")
	gitTest(t, o.Root, "commit", "--allow-empty", "-m", "synthetic count guard documents")
	gitTest(t, o.Root, "tag", "-f", FreezeTag, "HEAD")
	rows := make([]map[string]string, n)
	for i := range rows {
		rows[i] = map[string]string{"prompt": "FAKE repeated synthetic count-only record"}
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(o.SealedDir, lock.Files[0].Path)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	lock.Files[0].Dataset = name
	lock.Files[0].SHA256, lock.Files[0].Bytes, err = HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lock.ManifestSHA256, _, err = HashFile(o.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	lock.ConfigSHA256, _, err = HashFile(o.Config)
	if err != nil {
		t.Fatal(err)
	}
	lock.TreeHash, err = VerifyFiles(o.SealedDir, lock.Files)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONTest(t, o.Lock, lock)
	gitTest(t, o.Root, "add", ".")
	gitTest(t, o.Root, "commit", "-m", "synthetic count guard lock")
	return o
}
func TestExactScoringCountsBeforeAnyDetectorCall(t *testing.T) {
	// Approved plan §1 table: NotInject 339, CPAD 10,050. These generated rows
	// repeat one obviously fake phrase; no benchmark record is used.
	for _, tc := range []struct {
		name     string
		expected int
	}{{"NotInject", 339}, {"CPAD", 10050}} {
		for _, n := range []int{tc.expected - 1, tc.expected + 1} {
			t.Run(tc.name+strconv.Itoa(n), func(t *testing.T) {
				o := countGuardRun(t, tc.name, n)
				if _, err := runOnHost(context.Background(), o, "linux", "amd64"); err == nil || !strings.Contains(err.Error(), "scoring-unit count mismatch") {
					t.Fatal("exact count not enforced", err)
				}
				if o.Detector.(*fakeDetector).calls != 0 {
					t.Fatal("detector called before count guard")
				}
			})
		}
	}
}

func TestPinnedAgentDojoEmptyContentSemantics(t *testing.T) {
	for _, raw := range []string{`[]`, `[{"type":"text","content":""}]`, `[{"type":"text","content":null}]`} {
		text, err := agentDojoText(json.RawMessage(raw))
		if err != nil || text != "" {
			t.Fatal("upstream empty join semantics", err)
		}
	}
}
