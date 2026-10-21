package eval

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewAgentDojoPinnedContentBlocks(t *testing.T) {
	// Synthetic content, structural shape from pinned agentdojo/types.py.
	data := `{"injections":{},"attack_type":null,"injection_task_id":null,"messages":[{"role":"tool","content":[{"type":"text","content":"SYNTHETIC CLEAN TOOL RESULT"}],"error":null}]}`
	rows, err := Adapt(strings.NewReader(data), Dataset{Name: "AgentDojo"}, LockedFile{Variant: "clean"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("pinned native content blocks rejected: %v", err)
	}
}

func TestReviewGitHiddenTrackedDrift(t *testing.T) {
	root := t.TempDir()
	gitTest(t, root, "init")
	path := filepath.Join(root, "code.go")
	if err := os.WriteFile(path, []byte("frozen"), 0600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "synthetic frozen code")
	gitTest(t, root, "tag", FreezeTag)
	gitTest(t, root, "update-index", "--assume-unchanged", "code.go")
	if err := os.WriteFile(path, []byte("different executable source"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckGit(root); err == nil {
		t.Fatal("changed tracked source accepted with assume-unchanged")
	}
}

func TestReviewGitEnvironmentHidesDirtyTree(t *testing.T) {
	o, _ := syntheticRun(t)
	clean := t.TempDir()
	if err := os.Mkdir(filepath.Join(clean, "eval"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "manifest.lock.json", "config.frozen.json"} {
		b, err := os.ReadFile(filepath.Join(o.Root, "eval", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(clean, "eval", name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(o.Root, "dirty.go"), []byte("SYNTHETIC DIRTY SOURCE"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_WORK_TREE", clean)
	if _, err := runOnHost(context.Background(), o, "linux", "amd64"); err == nil {
		t.Fatal("entire run accepted dirty real root with redirected Git worktree")
	}
}

func TestReviewUnavailableDecisionCannotEchoText(t *testing.T) {
	const text = "SYNTHETIC INPUT TEXT MUST NEVER BE SERIALIZED"
	d := &fakeDetector{result: Result{Unavailable: true, Reason: "timeout", Decision: text}}
	obs, err := observe(context.Background(), Dataset{Name: "NotInject"}, Item{ID: "opaque", Input: Input{Text: text}}, testConfig(), nil, d)
	if err != nil {
		return
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := WriteReports(out, Report{}, []Observation{obs}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "items.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), text) {
		t.Fatal("unavailable detector decision leaked input text")
	}
}

func TestReviewIndependentWilsonVectors(t *testing.T) {
	// Independently solve score-test quadratic endpoints: (k-n*p)^2=z^2*n*p*(1-p).
	// Published second example is 5/25 => Wilson approximately [0.089,0.391].
	const z = 1.959963984540054
	for _, v := range [][2]int{{20, 50}, {5, 25}, {0, 10}, {10, 10}} {
		k, n := float64(v[0]), float64(v[1])
		a := n*n + z*z*n
		b := -2*k*n - z*z*n
		cc := k * k
		disc := math.Sqrt(b*b - 4*a*cc)
		lo := (-b - disc) / (2 * a)
		hi := (-b + disc) / (2 * a)
		got := Proportion(v[0], v[1])
		if math.Abs(*got.Lower-lo) > 1e-12 || math.Abs(*got.Upper-hi) > 1e-12 {
			t.Fatal("Wilson mismatch", v)
		}
		t.Logf("Wilson %d/%d [%.9f, %.9f]", v[0], v[1], lo, hi)
	}
}
