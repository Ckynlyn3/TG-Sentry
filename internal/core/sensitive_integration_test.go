package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSensitiveReviewUnavailableAndDenyOverride(t *testing.T) {
	for _, tc := range []struct{ name, decision, rule string }{
		{"no-service", "reject", "E_BTPII"},
		{"deterministic-deny", "reject", "U_DENY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := engine(t)
			if err := e.SaveRule(testActorContext(), Rule{ID: "R_PII_EMAIL", Name: "Email", Enabled: true, Matcher: "btpii", Pattern: "email", Decision: "alert"}); err != nil {
				t.Fatal(err)
			}
			if tc.name == "deterministic-deny" {
				if err := e.SaveRule(testActorContext(), Rule{ID: "U_DENY", Name: "Deny", Enabled: true, Matcher: "contains", Pattern: "fake", Decision: "reject"}); err != nil {
					t.Fatal(err)
				}
			}
			r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: tc.name, ToolName: "read", Arguments: map[string]any{"value": "fake@example.invalid"}})
			if err != nil || r.Decision != tc.decision || r.RuleID != tc.rule || r.SensitiveInfo == nil {
				t.Fatal(r, err)
			}
			if tc.name == "no-service" && !r.SensitiveInfo.Unavailable {
				t.Fatal("unavailable not marked")
			}
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "fake@example.invalid") {
				t.Fatal("unavailable snapshot retained PII")
			}
			replay, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: tc.name, ToolName: "read", Arguments: map[string]any{"value": "fake@example.invalid"}})
			if err != nil || replay.ID != r.ID {
				t.Fatal(replay, err)
			}
			page, err := e.RiskEvents(0, "", RiskEventFilter{Category: SensitiveInfoCategory})
			if err != nil || len(page.Items) != 0 {
				t.Fatal("operational failure became a PII finding", page, err)
			}
		})
	}
}
func TestSensitiveCustomRulesRetainNoMatchedValues(t *testing.T) {
	for _, matcher := range []string{"keywords", "regex", "contains"} {
		t.Run(matcher, func(t *testing.T) {
			e := engine(t)
			pattern := "synthetic-private"
			if matcher == "keywords" {
				pattern = "synthetic-private\nother-synthetic"
			}
			if err := e.SaveRule(testActorContext(), Rule{ID: "U_PII", Name: "Custom private", Matcher: matcher, Pattern: pattern, Decision: "alert", Enabled: true, Categories: []string{SensitiveInfoCategory}, Field: "value"}); err != nil {
				t.Fatal(err)
			}
			r, err := e.Submit(ReviewInput{InstanceID: "instance", CallID: matcher, ToolName: "read", Arguments: map[string]any{"value": "synthetic-private"}})
			if err != nil || r.Decision != "approve" || r.RuleID != "U_PII" {
				t.Fatal(r, err)
			}
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "synthetic-private") {
				t.Fatal("matched custom value retained in snapshot")
			}
			if err := e.Result(r.ID, "instance", "succeeded", "synthetic-private"); err != nil {
				t.Fatal(err)
			}
			saved, err := e.Review(r.ID)
			if err != nil || saved.Result != "[REDACTED]" {
				t.Fatal(saved, err)
			}
			page, err := e.RiskEvents(0, "", RiskEventFilter{Category: SensitiveInfoCategory})
			if err != nil || len(page.Items) != 1 {
				t.Fatal(page, err)
			}
			schemas := pinnedEventSchemas(t)
			if err := validateEventWire(schemas, wireEvent(t, page.Items[0])); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestSensitiveRulesConfigurationAndSnapshots(t *testing.T) {
	e := engine(t)
	for _, rule := range []Rule{
		{ID: "U_BAD", Name: "Invalid", Matcher: "keywords", Pattern: "fake", Decision: "reject"},
		{ID: "U_BAD", Name: "Invalid", Matcher: "contains", Pattern: "fake", Decision: "redact"},
		{ID: "R_PII_EMAIL", Name: "Invalid", Matcher: "btpii", Pattern: "wrong", Decision: "reject"},
		{ID: "R_PII_EMAIL", Name: "Invalid", Matcher: "btpii", Pattern: "email", Field: "value", Decision: "reject"},
	} {
		if e.SaveRule(testActorContext(), rule) == nil {
			t.Fatal("invalid sensitive rule accepted", rule)
		}
	}
	settings := e.Config()
	settings.BTPII.Language = "unsupported"
	if e.SaveSettings(testActorContext(), settings, nil) == nil {
		t.Fatal("invalid BTPII settings accepted")
	}
	settings.BTPII = BTPIIConfig{Endpoint: "https://example.invalid", Language: "zh"}
	if err := e.SaveSettings(testActorContext(), settings, nil); err != nil {
		t.Fatal(err)
	}
	// The existing compiled template and signed-bundle structures carry detector
	// rules unchanged; neither workload token nor token-file path enters bundles.
	rules := sensitiveInfoRules()
	rules[2].Enabled = true
	state := ProtectionState{Templates: []ProtectionTemplate{{ID: "synthetic", Revision: 1}}, Definitions: map[string][]Rule{"synthetic": {rules[2]}}, Policies: []ProtectionPolicy{{ID: "bound", TemplateIDs: []string{"synthetic"}, Scope: PolicyScope{Type: "all"}}}}
	compiled, err := compileProtection(state, rules, nil, "")
	if err != nil || len(compiled) == 0 {
		t.Fatal(compiled, err)
	}
	found := false
	for _, r := range compiled {
		if r.SourceRuleID == "R_PII_EMAIL" {
			found = true
		}
	}
	if !found {
		t.Fatal("template lost BTPII matcher")
	}
	if actionDecision("redact") != "redact" || decisionStrength("redact") != decisionStrength("alert") {
		t.Fatal("redaction action strength")
	}
}
func TestSensitiveCleanAndDisabledRules(t *testing.T) {
	cfg := fakeBTPII(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) })
	rules := sensitiveInfoRules()
	rules[2].Enabled = true
	in := ReviewInput{ToolName: "read", Arguments: map[string]any{"value": "safe"}}
	before := &Decision{Decision: "approve", RuleID: "A7"}
	decision, result := reviewSensitive(in, rules, cfg, before)
	if decision != before || result == nil || len(result.Findings) != 0 || result.Unavailable {
		t.Fatal(decision, result)
	}
	rules[2].Tool = "other"
	decision, result = reviewSensitive(in, rules, cfg, before)
	if result != nil || decision != before {
		t.Fatal(decision, result)
	}
	if sensitiveIdentifier("") != "" {
		t.Fatal("optional identifier not empty")
	}
	result2, err := (SensitiveDetector{Rules: []Rule{}}).Detect(context.Background(), SensitiveInput{Text: "fake"})
	if err != nil || result2.Unavailable || len(result2.Findings) != 0 {
		t.Fatal(result2, err)
	}
}
