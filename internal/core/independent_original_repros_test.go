package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIndependentOriginalReview20CustomLogOnlyAfterA7(t *testing.T) {
	e := engine(t)
	const private = "synthetic-private-review20"
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_PRIVATE", Name: "Private", Matcher: "keywords", Pattern: private, Field: "value", Enabled: true, Decision: "approve", Categories: []string{SensitiveInfoCategory}}); err != nil {
		t.Fatal(err)
	}
	r, err := e.Submit(input("custom-log", "read", map[string]any{"value": private}))
	if err != nil {
		t.Fatal(err)
	}
	if r.SensitiveInfo == nil || len(r.SensitiveInfo.Findings) == 0 {
		t.Errorf("configured matching log-only rule produced no finding; winner=%s", r.RuleID)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), private) {
		t.Error("configured private keyword retained in review")
	}
	page, err := e.RiskEvents(0, "", RiskEventFilter{Category: SensitiveInfoCategory})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) == 0 {
		t.Error("no sensitive-info risk event for matching log-only rule")
	}
}

func TestIndependentOriginalReview20RetainedMetadata(t *testing.T) {
	e := engine(t)
	card := syntheticCard()
	if err := e.Register(Instance{ID: "metadata-instance", SessionID: card, Cwd: t.TempDir(), HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_PRIVATE", Name: "Private", Matcher: "keywords", Pattern: "synthetic-private-review20", Field: "value", Enabled: true, Decision: "alert", Categories: []string{SensitiveInfoCategory}}); err != nil {
		t.Fatal(err)
	}
	r, err := e.Submit(ReviewInput{InstanceID: "metadata-instance", CallID: "metadata-call", ToolName: "read", Arguments: map[string]any{"value": "synthetic-private-review20"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.SessionID == card {
		t.Error("raw checksum-valid PAN retained as Review.SessionID despite sensitive hit")
	}
}

func TestIndependentOriginalReview20DelimitedPANIdentifier(t *testing.T) {
	for _, prefix := range []string{"session-", "U_"} {
		identifier := prefix + syntheticCard()
		if eventIdentifier(identifier) == identifier {
			t.Errorf("checksum-valid PAN retained with public identifier prefix %q", prefix)
		}
	}
}

func TestIndependentOriginalReview20InactiveRuleSnapshot(t *testing.T) {
	e := engine(t)
	const private = "synthetic-private-review20"
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_PRIVATE", Name: "Private", Matcher: "keywords", Pattern: private, Field: "value", Tool: "write", Enabled: true, Decision: "alert", Categories: []string{SensitiveInfoCategory}}); err != nil {
		t.Fatal(err)
	}
	r, err := e.Submit(input("inactive-rule", "read", map[string]any{"value": "safe"}))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), private) {
		t.Error("private keyword copied to unrelated review snapshot")
	}
}
