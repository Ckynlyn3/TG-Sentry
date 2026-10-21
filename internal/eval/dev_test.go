package eval

import (
	"aegishook/internal/core"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
)

func devDatasetTest() Dataset {
	return Dataset{Name: "PII-dev", SourceURL: "synthetic-only", Revision: "dev", AdmissibilityReason: "GenerateDev only; not acceptance", SplitUse: "dev", Mode: "full-path", Category: "category::prompt-attack", LanguageMetadataLevel: "item", Synthetic: &Synthetic{Generator: "GenerateDev", DevSeed: "dev"}}
}

func TestDevFullPathStillRejectedByManifest(t *testing.T) {
	s := devDatasetTest()
	if err := (Manifest{Version: SchemaVersion, Sets: []Dataset{s}}).Validate(); err == nil || !strings.Contains(err.Error(), "no admissible dataset supplies native review input (gap)") {
		t.Fatal("production manifest guard admitted generated dev full-path", err)
	}
	for _, name := range []string{"split", "identity", "synthetic", "seed", "generator", "files", "fetch"} {
		t.Run(name, func(t *testing.T) {
			s := devDatasetTest()
			switch name {
			case "split":
				s.SplitUse = "held_out"
			case "identity":
				s.Name = "other"
			case "synthetic":
				s.Synthetic = nil
			case "seed":
				s.Synthetic.DevSeed = "not-dev"
			case "generator":
				s.Synthetic.Generator = "other"
			case "files":
				s.Files = []PendingFile{{Path: "must-not-open"}}
			case "fetch":
				s.Fetch = []Fetch{{URLOrPath: "must-not-fetch"}}
			}
			if err := (Manifest{Version: SchemaVersion, Sets: []Dataset{s}}).Validate(); err == nil || !strings.Contains(err.Error(), "no admissible dataset supplies native review input (gap)") {
				t.Fatal("non-generated full-path admitted", err)
			}
		})
	}
}

func devRunTest(t *testing.T) DevOptions {
	t.Helper()
	root := t.TempDir()
	gitTest(t, root, "init")
	os.WriteFile(filepath.Join(root, "source"), []byte("synthetic source"), 0600)
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "synthetic non-freeze development")
	// Deliberately dirty, untagged source. Only RunDev may accept it.
	config := filepath.Join(root, "dev-config.json")
	writeJSONTest(t, config, testConfig())
	return DevOptions{Root: root, Config: config, Out: filepath.Join(root, "out")}
}

func TestRunDevUsesOnlyGeneratedNativeReviews(t *testing.T) {
	o := devRunTest(t)
	if _, err := CheckGit(o.Root); err == nil {
		t.Fatal("frozen gate accepted dirty dev source")
	}
	// No manifest, lock or data directory exists. A successful run cannot have
	// opened any of them, and RunDev has no field with which to select one.
	rep, err := RunDev(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DevOnly || rep.Tag != "dev-only" || rep.HEAD != gitTest(t, o.Root, "rev-parse", "HEAD") || len(rep.Thresholds) != 0 || len(rep.Groups) != 2 || rep.WarmupN != 0 {
		t.Fatalf("incorrect dev provenance: %+v", rep)
	}
	want := GenerateDev()
	if rep.Digests["fixtures"] != Digest(want) {
		t.Fatal("fixture identity not bound to GenerateDev")
	}
	for _, group := range rep.Groups {
		if group.NScored != len(want)/len(rep.Groups) || group.NUnavailable != 0 || group.ReviewPaths["rule"] != group.NScored || group.Counts.TN != group.NScored {
			t.Fatalf("native review path missing: %+v", group)
		}
	}
	for _, name := range []string{"report.json", "report.md", "items.jsonl"} {
		b, err := os.ReadFile(filepath.Join(o.Out, name))
		if err != nil || strings.Contains(string(b), want[0].Text) {
			t.Fatal("report missing or leaked fixture text", name, err)
		}
		if name == "report.md" && !strings.Contains(string(b), "DEV-ONLY") {
			t.Fatal("Markdown missing dev-only warning")
		}
		if name != "items.jsonl" && !strings.Contains(string(b), "evaluation requires a clean git tree") {
			t.Fatal("dev report omitted dirty-tree diagnostic", name)
		}
	}
	b, _ := os.ReadFile(filepath.Join(o.Out, "items.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != len(want) {
		t.Fatal("not every generated record reached the report")
	}
	ids := map[string]bool{}
	for _, line := range lines {
		var record itemRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil || record.Decision != "approve" || record.ReviewPath != "rule" || record.Label {
			t.Fatal("not a terminal benign prompt review", err)
		}
		ids[record.ID] = true
	}
	for _, row := range want {
		if !ids[row.ID] {
			t.Fatal("source fixture identity lost")
		}
	}
	if _, err := RunDev(t.Context(), o); err == nil {
		t.Fatal("output reuse accepted")
	}
}

func TestRunDevEnabledPromptAttack(t *testing.T) {
	o := devRunTest(t)
	c := testConfig()
	c.Settings.Model.ProcessingClass = core.ModelProcessingSelfHosted
	c.Settings.Model.BaseURL = "http://127.0.0.1"
	c.Settings.Model.Model = "synthetic-dev-classifier"
	c.Settings.Model.Tested = true
	for i := range c.Rules {
		if c.Rules[i].Matcher == "prompt-attack" {
			c.Rules[i].Enabled = true
		}
	}
	c.RulesSHA256 = Digest(c.Rules)
	writeJSONTest(t, o.Config, c)
	previous := http.DefaultTransport
	http.DefaultTransport = promptAttackDevTransport{}
	defer func() { http.DefaultTransport = previous }()
	synctest.Test(t, func(t *testing.T) {
		rep, err := RunDev(t.Context(), o)
		if err != nil {
			t.Fatal(err)
		}
		for _, group := range rep.Groups {
			if group.NUnavailable != 0 || group.NScored == 0 || group.Counts.TN != group.NScored {
				t.Fatalf("enabled integrated detector incomplete: %+v", group)
			}
		}
	})
}

func TestRunDevWithoutGit(t *testing.T) {
	o := devRunTest(t)
	o.Root = t.TempDir()
	rep, err := RunDev(t.Context(), o)
	if err != nil || rep.HEAD != "unknown" || !rep.DevOnly {
		t.Fatal("dev mode must not depend on git", rep.HEAD, err)
	}
	b, err := json.Marshal(rep)
	if err != nil || !strings.Contains(string(b), "cannot verify evaluation index flags") {
		t.Fatal("unknown git state diagnostic missing", err)
	}
}

func TestRunDevGitCheckDiagnostics(t *testing.T) {
	for _, name := range []string{"clean-untagged", "frozen"} {
		t.Run(name, func(t *testing.T) {
			o := devRunTest(t)
			gitTest(t, o.Root, "add", ".")
			gitTest(t, o.Root, "commit", "-m", "synthetic clean dev configuration")
			if name == "frozen" {
				gitTest(t, o.Root, "tag", FreezeTag)
			}
			want := "PASS"
			if _, err := CheckGit(o.Root); err != nil {
				want = err.Error()
			}
			rep, err := RunDev(t.Context(), o)
			if err != nil {
				t.Fatal("git check must be diagnostic only", err)
			}
			b, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(b, &fields); err != nil || fields["dev_git_check"] != want {
				t.Fatal("CheckGit result not surfaced", fields["dev_git_check"], want, err)
			}
		})
	}
}

func TestRunDevRefusesInvalidInputs(t *testing.T) {
	for _, name := range []string{"missing-config", "invalid-config", "malformed-config", "threshold", "digest", "database", "cancelled", "missing-out-parent"} {
		t.Run(name, func(t *testing.T) {
			o := devRunTest(t)
			c := testConfig()
			ctx := t.Context()
			switch name {
			case "missing-config":
				o.Config = filepath.Join(o.Root, "missing")
			case "invalid-config":
				c.RulesSHA256 = "invalid"
			case "threshold":
				c.Thresholds = []Threshold{{ID: "dev-must-not-evaluate", Metric: "recall", ReportOnly: true, Source: "synthetic"}}
			case "digest":
				c.Digests = map[string]string{"unobserved": strings.Repeat("a", 64)}
			case "database":
				t.Setenv("TG_SENTRY_DATABASE_URL", "must-not-open")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing-out-parent":
				o.Out = filepath.Join(o.Root, "missing", "out")
			}
			if name != "missing-config" {
				writeJSONTest(t, o.Config, c)
			}
			if name == "malformed-config" {
				os.WriteFile(o.Config, []byte("{invalid"), 0600)
			}
			if _, err := RunDev(ctx, o); err == nil {
				t.Fatal("invalid dev input admitted")
			}
		})
	}
}

func TestGeneratedDevReviewProjection(t *testing.T) {
	rows := GenerateDev()
	items := devReviewItems(rows)
	if len(items) != len(rows) {
		t.Fatal("missing generated reviews")
	}
	for i, item := range items {
		if item.ID != rows[i].ID || item.Seed != "dev" || item.Positive || item.Input.Language != rows[i].Language || item.Input.Text != rows[i].Text || item.Review == nil || item.Review.ToolName != "prompt_turn" || item.Review.UserMessage != rows[i].Text || len(item.Review.Arguments) != 0 {
			t.Fatal("native projection differs from generated fixture", i)
		}
	}
	// Input rows and native review arguments must not alias mutable state.
	items[0].Review.Arguments["sentinel"] = true
	if len(items[1].Review.Arguments) != 0 || items[0].Review.InstanceID != "" || items[0].Review.CallID != "" {
		t.Fatal("ReviewInput identity must be supplied by FullPath")
	}
}
