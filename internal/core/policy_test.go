package core

import (
	"context"
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"aegishook/internal/secrets"
)

// Same named local fixture seed and alphabet as secrets/fixture_test.go:
// deterministic, never provisioned, and assembled only in memory.
func policySecretCandidate() string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rng := rand.New(rand.NewSource(22))
	var text strings.Builder
	text.WriteString("ghp_")
	for range 36 { // Frozen Gitleaks github-pat length.
		text.WriteByte(alphabet[rng.Intn(len(alphabet))])
	}
	return text.String()
}

func TestSecretBuiltinRules(t *testing.T) {
	want := []string{"aws-access-token", "github-pat", "github-fine-grained-pat", "gitlab-pat", "openai-api-key", "anthropic-api-key", "anthropic-admin-api-key", "private-key", "jwt"}
	seen := map[string]bool{}
	for _, r := range BuiltinRules() {
		if r.Matcher != "secret" {
			continue
		}
		if !r.Builtin || !r.Enabled || r.Decision != "reject" || r.Target != "arguments" || !reflect.DeepEqual(r.Categories, []string{SensitiveInfoCategory}) {
			t.Fatalf("invalid secret builtin metadata: %s", r.ID)
		}
		if seen[r.Pattern] || !hasExact(r.Pattern, want...) {
			t.Fatalf("unexpected or duplicate secret entity: %s", r.Pattern)
		}
		seen[r.Pattern] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("secret manifest has %d entries; want %d", len(seen), len(want))
	}
}

// Exercise the public runtime entry, including template source identity.
func evaluateSecretModel(in ReviewInput, rules []Rule) *Decision {
	return Evaluate(in, rules)
}

func TestSecretRuleDispatchAndTemplateSource(t *testing.T) {
	candidate := policySecretCandidate()
	var source Rule
	for _, r := range BuiltinRules() {
		if r.Matcher == "secret" && r.Pattern == "github-pat" {
			source = r
		}
	}
	if source.ID == "" {
		t.Fatal("github secret builtin missing")
	}
	state := ProtectionState{
		Templates:   []ProtectionTemplate{{ID: "fixture", Revision: 1}},
		Policies:    []ProtectionPolicy{{Scope: PolicyScope{Type: "all"}, TemplateIDs: []string{"fixture"}}},
		Definitions: map[string][]Rule{"fixture": {source}},
	}
	compiled, err := compileProtection(state, nil, nil, "")
	if err != nil || len(compiled) != 1 || compiled[0].SourceRuleID != source.ID {
		t.Fatal("template did not preserve detector provenance")
	}
	// Deliberately stale Pattern cannot redirect a compiled detector: source ID wins.
	compiled[0].Pattern = "jwt"
	for _, r := range []Rule{source, compiled[0]} {
		for _, args := range []map[string]any{{"text": candidate}, {candidate: "innocuous"}, {"nested": []any{map[string]any{"text": candidate}}}} {
			d := evaluateSecretModel(ReviewInput{ToolName: "fixture", Arguments: args}, []Rule{r})
			if d == nil || d.RuleID != r.ID || d.Decision != "reject" || strings.Contains(d.Comment, candidate) {
				t.Fatal("secret rule failed value-free dispatch")
			}
		}
		if d := evaluateSecretModel(ReviewInput{ToolName: "fixture", Arguments: map[string]any{"text": "clean"}}, []Rule{r}); d != nil {
			t.Fatal("clean content matched a secret rule")
		}
	}
	for _, change := range []func(*Rule){
		func(r *Rule) { r.Enabled = false },
		func(r *Rule) { r.Tool = "another-tool" },
		func(r *Rule) { r.Builtin = false },
		func(r *Rule) { r.ID = "U_SECRET" },
		func(r *Rule) { r.SourceRuleID = "unknown" },
	} {
		r := source
		change(&r)
		if d := evaluateSecretModel(ReviewInput{ToolName: "fixture", Arguments: map[string]any{"text": candidate}}, []Rule{r}); d != nil {
			t.Fatal("inactive or untrusted secret rule matched")
		}
	}
}

func TestSecretRuleCRUDValidation(t *testing.T) {
	e := engine(t)
	candidate := policySecretCandidate()
	original := Rule{ID: "U_SECRET", Name: "fixture", Matcher: "contains", Pattern: "fixture", Decision: "alert", Enabled: true}
	if err := e.SaveRule(testActorContext(), original); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"U_NEW_SECRET", "U_SECRET", "R1"} {
		r := Rule{ID: id, Name: "fixture", Matcher: "secret", Pattern: candidate, Decision: "alert", Enabled: true}
		if err := e.SaveRule(testActorContext(), r); err == nil || err.Error() != "invalid secret rule" {
			t.Fatal("CRUD did not return static secret validation error")
		}
	}
	for _, r := range BuiltinRules() {
		if r.Matcher != "secret" {
			continue
		}
		if err := e.SaveRule(testActorContext(), r); err != nil {
			t.Fatalf("cannot save secret builtin %s: %v", r.ID, err)
		}
		for _, change := range []func(*Rule){
			func(r *Rule) { r.Pattern = "unknown" },
			func(r *Rule) {
				r.Pattern = "jwt"
				if r.ID == "R_SECRET_JWT" {
					r.Pattern = "github-pat"
				}
			},
			func(r *Rule) { r.Target = "toolName" },
			func(r *Rule) { r.Field = "text" },
		} {
			invalid := r
			change(&invalid)
			if err := e.SaveRule(testActorContext(), invalid); err == nil || err.Error() != "invalid secret rule" {
				t.Fatal("accepted invalid builtin secret definition")
			}
		}
	}
	if saved := ruleByID(t, e, original.ID); saved.Matcher != original.Matcher || saved.Pattern != original.Pattern {
		t.Fatal("rejected update changed persisted custom rule")
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(audits)
	if err != nil || strings.Contains(string(data), candidate) {
		t.Fatal("rejected secret CRUD leaked candidate into audit")
	}
}

func TestSecretRuleOrderingAndFailClosed(t *testing.T) {
	candidate := policySecretCandidate()
	var secret Rule
	for _, r := range BuiltinRules() {
		if r.Matcher == "secret" && r.Pattern == "github-pat" {
			secret = r
			secret.Decision = "alert" // Persisted S3 default must normalize to deny.
		}
	}
	allow := Rule{ID: "U_ALLOW", Name: "fixture", Matcher: "contains", Pattern: "", Enabled: true, Decision: "approve", Priority: 999}
	deny := allow
	deny.ID, deny.Decision = "U_DENY", "reject"
	in := ReviewInput{ToolName: "fixture", Arguments: map[string]any{"text": candidate}}
	for _, tc := range []struct {
		rules []Rule
		want  string
	}{
		{[]Rule{allow, secret}, secret.ID},
		{[]Rule{secret, allow, deny}, deny.ID},
	} {
		d := evaluateSecretModel(in, tc.rules)
		if d == nil || d.RuleID != tc.want {
			t.Fatal("secret changed deny/alert/approve ordering")
		}
	}
	in.ToolName, in.Arguments["command"] = "bash", "echo '"
	if d := evaluateSecretModel(in, []Rule{secret, allow}); d == nil || d.RuleID != secret.ID {
		t.Fatal("stored alert downgraded secret deny on parse failure")
	}
	secret.Decision = "reject"
	if d := evaluateSecretModel(in, []Rule{secret, allow}); d == nil || d.RuleID != secret.ID {
		t.Fatal("explicit secret deny did not survive parse failure")
	}
	in = ReviewInput{ToolName: "fixture", Arguments: map[string]any{"text": string([]byte{0xff})}}
	if d := evaluateSecretModel(in, []Rule{secret, allow}); d == nil || d.RuleID != "E_SECRET_SCAN" {
		t.Fatal("interrupted secret scan was reported as clean")
	}
	if d := evaluateSecretModel(in, []Rule{secret, deny}); d == nil || d.RuleID != deny.ID {
		t.Fatal("explicit deny did not survive unavailable secret scan")
	}
}

func TestSecretActiveProductionEntrypoints(t *testing.T) {
	candidate := policySecretCandidate()
	for _, r := range secretRules() {
		if r.Pattern != "github-pat" {
			continue
		}
		for _, stored := range []string{"approve", "alert", "redact", "reject"} {
			r.Decision = stored
			for _, args := range []map[string]any{{"text": candidate}, {candidate: "benign"}, {"text": string([]byte{0xff})}} {
				in := ReviewInput{ToolName: "fixture", Arguments: args}
				want := r.ID
				if args["text"] == string([]byte{0xff}) {
					want = "E_SECRET_SCAN"
				}
				for _, d := range []*Decision{Evaluate(in, []Rule{r}), PolicyBundleDeny(PolicyBundle{Rules: []Rule{r}}, in, "")} {
					if d == nil || d.Decision != "reject" || d.RuleID != want {
						t.Fatal("secret runtime entry did not deny")
					}
				}
				d, result := reviewSensitiveContext(context.Background(), in, []Rule{r}, BTPIIConfig{}, nil)
				if d == nil || d.Decision != "reject" || result == nil {
					t.Fatal("secret did not activate private denial")
				}
			}
		}
	}
}

func TestSecretActiveSnapshotProjection(t *testing.T) {
	benign := Rule{ID: "U_CONTROL", Name: "Benign control", Message: "Keep audit message", Pattern: "never-match", Matcher: "contains", Target: "arguments", Decision: "reject", Enabled: true}
	for _, enabled := range []bool{true, false} {
		secret := secretRules()[0]
		secret.Enabled = enabled
		rules := []Rule{benign, secret}
		before, _ := json.Marshal(rules)
		got := sensitiveRuleSnapshot(rules, false)
		if len(got) != 2 || !reflect.DeepEqual(got[0], benign) || got[1].ID != secret.ID || got[1].Pattern != "[REDACTED]" {
			t.Fatal("secret definition missing or not private in audit snapshot")
		}
		after, _ := json.Marshal(rules)
		if string(before) != string(after) {
			t.Fatal("snapshot mutated caller-owned rules")
		}
	}
}

func TestSecretActiveWithSensitiveReview(t *testing.T) {
	var secret Rule
	for _, r := range secretRules() {
		if r.Pattern == "github-pat" {
			secret = r
		}
	}
	benign := Rule{ID: "U_SENSITIVE", Matcher: "contains", Pattern: "never-match", Enabled: true, Categories: []string{SensitiveInfoCategory}}
	d, result := reviewSensitiveContext(context.Background(), ReviewInput{ToolName: "fixture", Arguments: map[string]any{"text": policySecretCandidate()}}, []Rule{secret, benign}, BTPIIConfig{}, nil)
	if d == nil || d.Decision != "reject" || result == nil || len(result.Findings) != 1 || result.Findings[0].RuleID != secret.ID {
		t.Fatal("secret finding missing beside active sensitive review")
	}
}

func TestSecretRulesCleanTextLeavesSensitiveReviewInactive(t *testing.T) {
	in := ReviewInput{ToolName: "fixture", Arguments: map[string]any{"text": "clean"}}
	decision := &Decision{Decision: "reject", RuleID: "fixture"}
	got, sensitive := reviewSensitiveContext(context.Background(), in, BuiltinRules(), BTPIIConfig{}, decision)
	if got != decision || sensitive != nil {
		t.Fatal("enabled secret catalog activated sensitive review without a finding")
	}
}

func TestSecretSerializedFindingHasOnlyLocation(t *testing.T) {
	candidate := policySecretCandidate()
	findings, status := secrets.ScanTree(context.Background(), map[string]any{candidate: candidate}, "tool_input")
	if status != secrets.Complete || len(findings) != 2 {
		t.Fatal("synthetic fixture did not exercise key and value locations")
	}
	for _, finding := range findings {
		b, err := json.Marshal(finding)
		if err != nil || strings.Contains(string(b), candidate) {
			t.Fatal("serialized finding retained candidate")
		}
		var fields map[string]any
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		for field := range fields {
			if !hasExact(field, "entity_type", "surface", "kind", "field_digest", "span") {
				t.Fatalf("unexpected location field: %s", field)
			}
		}
	}
}
