package main

import (
	"aegishook/internal/core"
	"aegishook/internal/eval"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEvalDevOnlyOptions(t *testing.T) {
	var out bytes.Buffer
	o, err := parseOptions([]string{"eval", "--dev-only", "--config", "dev-config.json", "--out", "new-results"}, &out)
	if err != nil || !o.evalDevOnly || o.evalManifest != "" || o.evalLock != "" || o.evalSealed != "" || o.evalConfig != "dev-config.json" {
		t.Fatal("dev-only did not isolate the frozen inputs", o, err)
	}
	for _, flag := range []string{"--manifest", "--lock", "--sealed-dir"} {
		if _, err := parseOptions([]string{"eval", "--dev-only", flag, "must-not-open", "--config", "dev-config.json", "--out", "new-results"}, &out); err == nil {
			t.Fatal("dev-only accepted an external dataset selector", flag)
		}
	}
	o, err = parseOptions([]string{"eval", "--dev-only", "--out", "new-results"}, &out)
	if err != nil || o.evalConfig != "" {
		t.Fatal("dev-only inherited the frozen configuration", o, err)
	}
	if err := runEval(t.Context(), o); err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatal("dev-only must require explicit dev configuration", err)
	}
	if err := runEval(t.Context(), options{evalDevOnly: true, evalConfig: "missing", evalOut: "missing", evalSealed: "must-not-open"}); err == nil {
		t.Fatal("direct dev-only invocation accepted dataset paths")
	}
	if err := runEval(t.Context(), options{evalDevOnly: true, evalConfig: "missing", evalOut: "missing"}); err == nil {
		t.Fatal("missing dev config accepted")
	}
}

func TestEvalDevOnlyRun(t *testing.T) {
	// Same explicit synthetic configuration as internal/eval/runner_test.go.
	rules := core.BuiltinRules()
	c := eval.FrozenConfig{Version: 1, Settings: core.Settings{Mode: "human", Prompt: core.DefaultPrompt, Version: 1, ApprovalSeconds: 10, ModelSeconds: 1, Model: core.ModelConfig{Protocol: "openai"}}, Rules: rules, RulesSHA256: eval.Digest(rules), CatalogSHA256: eval.Digest(rules), GOMAXPROCS: runtime.GOMAXPROCS(0), CPUCount: runtime.NumCPU(), HostClass: "synthetic-test", PollIntervalMS: 5}
	dir := t.TempDir()
	config := filepath.Join(dir, "dev-config.json")
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, payload, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "reports")
	if err := runEval(t.Context(), options{evalDevOnly: true, evalConfig: config, evalOut: out}); err != nil {
		t.Fatal("CLI did not dispatch to dev-only native reviews", err)
	}
	var rep eval.Report
	if err := eval.Load(filepath.Join(out, "report.json"), &rep); err != nil || !rep.DevOnly || len(rep.Thresholds) != 0 {
		t.Fatal("CLI reported an acceptance verdict", err)
	}
}

func TestEvalOptions(t *testing.T) {
	for _, args := range [][]string{{"eval", "-h"}, {"eval", "--manifest", "missing", "--lock", "missing", "--config", "missing", "--out", "missing"}} {
		var out bytes.Buffer
		o, err := parseOptions(args, &out)
		if len(args) == 2 {
			if err == nil || !strings.Contains(out.String(), "manifest") {
				t.Fatal(err, out.String())
			}
			continue
		}
		if err != nil || o.command != "eval" || o.evalManifest != "missing" {
			t.Fatal(o, err)
		}
	}
	if err := runEval(context.Background(), options{command: "eval"}); err == nil {
		t.Fatal("missing eval paths accepted")
	}
}
