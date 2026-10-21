package eval

import (
	"aegishook/internal/core"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig() FrozenConfig {
	rules := core.BuiltinRules()
	return FrozenConfig{Version: 1, Settings: core.Settings{Mode: "human", Prompt: core.DefaultPrompt, Version: 1, ApprovalSeconds: 10, ModelSeconds: 1, Model: core.ModelConfig{Protocol: "openai"}}, Rules: rules, RulesSHA256: Digest(rules), CatalogSHA256: Digest(rules), GOMAXPROCS: 4, CPUCount: 4, HostClass: "synthetic-test", PollIntervalMS: 5}
}
func TestFullPathUsesIsolatedStoreAndStoredVerdict(t *testing.T) {
	c := testConfig()
	e, cleanup, err := OpenIsolated(c, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	item := Item{ID: "fake", Review: &core.ReviewInput{ToolName: "Read", Arguments: map[string]any{"file_path": "README.md"}}}
	got, err := FullPath(context.Background(), e, item, time.Millisecond)
	if err != nil || got.ReviewPath != "rule" || got.Decision != "approve" || got.UnavailableReason != "" {
		t.Fatal(got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	item.Review = &core.ReviewInput{ToolName: "FAKE_UNKNOWN_TOOL", Arguments: map[string]any{"fake": "synthetic"}}
	got, err = FullPath(ctx, e, item, time.Millisecond)
	if err != nil || got.UnavailableReason != "deadline" {
		t.Fatal(got, err)
	}
	t.Setenv("TG_SENTRY_DATABASE_URL", "do-not-open")
	if _, _, err := OpenIsolated(c, t.TempDir()); err == nil {
		t.Fatal("production database env accepted")
	}
}
func TestAwaitStoredAsyncModelAndErrors(t *testing.T) {
	// Fake ReviewReader exercises asynchronous transitions without external models.
	reads := 0
	start := time.Now()
	r := core.Review{ID: "fake", Decision: "pending", ReviewPath: "model", Deadline: start.Add(time.Second)}
	got, err := waitReview(context.Background(), r, time.Millisecond, func(string) (core.Review, error) {
		reads++
		if reads == 2 {
			r.Decision = "reject"
			r.RuleID = "E_MODEL"
		}
		return r, nil
	})
	if err != nil || got.Decision != "reject" || reads != 2 || got.ReviewPath != "model" {
		t.Fatal(got, reads, err)
	}
	_, err = waitReview(context.Background(), r, time.Millisecond, func(string) (core.Review, error) { return r, errors.New("FAKE sensitive content") })
	if err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("store error lost or leaked")
	}
}
func TestMetricsExcludeUnavailableAndSeparateLanguages(t *testing.T) {
	c := testConfig()
	c.TagMapping = map[string][]string{"fake": {"1"}}
	set := Dataset{Name: "fake", Category: "category::prompt-attack"}
	rows := []Observation{
		{Item: Item{ID: "one", Positive: true, Input: Input{Language: "EN"}}, Result: Result{Decision: "alert", Findings: []Finding{{Category: set.Category, Tag: "1"}}}, LatencyMS: 1},
		{Item: Item{ID: "two", Input: Input{Language: "EN"}}, Result: Result{Decision: "reject"}, LatencyMS: 2},
		{Item: Item{ID: "three", Positive: true, Input: Input{Language: "EN"}}, Result: Result{Unavailable: true, Reason: "E_MODEL"}, LatencyMS: 3},
		{Item: Item{ID: "four", Input: Input{Language: "ZH"}}, Result: Result{Decision: "monitor"}, LatencyMS: 4},
	}
	groups := Summarize(set, rows, c)
	if len(groups) != 2 || groups[0].NScored != 2 || groups[0].NUnavailable != 1 || groups[0].Counts.TP != 1 || groups[0].Counts.TN != 1 || *groups[0].BenignBlockRate.Value != 1 {
		t.Fatalf("%+v", groups)
	}
	if groups[1].Language != "ZH" || *groups[1].BenignBlockRate.Value != 0 {
		t.Fatal(groups)
	}
	dir := filepath.Join(t.TempDir(), "report")
	rep := Report{Groups: groups}
	if err := WriteReports(dir, rep, rows); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "report.md", "items.jsonl"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil || strings.Contains(string(b), "Text") {
			t.Fatal(name, e)
		}
	}
	if WriteReports(dir, rep, rows) == nil {
		t.Fatal("report overwrite permitted")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "items.jsonl"))
	var record map[string]any
	if json.Unmarshal([]byte(strings.Split(string(b), "\n")[0]), &record) != nil || len(record) != 7 {
		t.Fatal(string(b))
	}
}
