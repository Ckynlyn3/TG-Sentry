package core

import (
	"context"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
)

// Recipes ported from internal/secrets/fixture_test.go: frozen Gitleaks widths,
// issue-22 deterministic seed, never provisioned and never printed on failure.
func runtimeSecretCandidate(entity string) string {
	const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rng := rand.New(rand.NewSource(22))
	text := func(alphabet string, n int) string {
		var b strings.Builder
		for range n {
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return b.String()
	}
	switch entity {
	case "aws-access-token":
		return "AKIA" + text("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
	case "github-pat":
		return "ghp_" + text(alnum, 36)
	case "github-fine-grained-pat":
		return "github_pat_" + text(alnum+"_", 82)
	case "gitlab-pat":
		return "glpat-" + text(alnum+"_-", 20)
	case "openai-api-key":
		return "sk-proj-" + text(alnum+"_-", 58) + "T3BlbkFJ" + text(alnum+"_-", 58)
	case "anthropic-api-key":
		return "sk-ant-api03-" + text(alnum+"_-", 93) + "AA"
	case "anthropic-admin-api-key":
		return "sk-ant-admin01-" + text(alnum+"_-", 93) + "AA"
	case "private-key":
		return "-----BEGIN PRIVATE KEY-----\n" + text(alnum, 64) + "\n-----END PRIVATE KEY-----"
	case "jwt":
		return "ey" + text(alnum, 17) + ".ey" + text(alnum, 17) + "." + text(alnum+"_-", 10)
	}
	panic("unknown fixture recipe")
}

func assertSecretAbsent(t *testing.T, candidate string, values ...any) {
	t.Helper()
	for _, value := range values {
		raw, err := json.Marshal(value)
		// JSON escapes multiline PEM; check both representations without emitting either.
		quoted, _ := json.Marshal(candidate)
		if err != nil || strings.Contains(string(raw), candidate) || strings.Contains(string(raw), string(quoted[1:len(quoted)-1])) {
			t.Fatal("secret material escaped privacy projection")
		}
	}
}

func TestSecretRuntimeNineRules(t *testing.T) {
	for _, rule := range secretRules() {
		t.Run(rule.ID, func(t *testing.T) {
			candidate := runtimeSecretCandidate(rule.Pattern)
			for _, args := range []map[string]any{{"text": candidate}, {candidate: "benign"}, {"nested": []any{map[string]any{"text": "prefix 😀 " + candidate}}}} {
				d := Evaluate(ReviewInput{ToolName: "Read", Arguments: args}, []Rule{rule})
				if d == nil || d.Decision != "reject" || d.RuleID != rule.ID {
					t.Fatal("secret not denied on normal evaluation path")
				}
				assertSecretAbsent(t, candidate, d)
			}
			if d := Evaluate(ReviewInput{ToolName: "Read", Arguments: map[string]any{"text": "benign"}}, []Rule{rule}); d != nil {
				t.Fatal("benign control rejected")
			}
		})
	}
}

func TestSecretSubmitPrivacyAndResult(t *testing.T) {
	e := engine(t)
	for _, rule := range secretRules() {
		t.Run(rule.ID, func(t *testing.T) {
			candidate := runtimeSecretCandidate(rule.Pattern)
			// An existing allow must not hide a secret deny.
			r, err := e.Submit(input(ID(), "Read", map[string]any{"text": candidate}))
			if err != nil || r.Decision != "reject" || r.Execution != "not_executed" || r.SensitiveInfo == nil || len(r.SensitiveInfo.Findings) == 0 {
				t.Fatal("Submit did not block and project secret")
			}
			assertSecretAbsent(t, candidate, r)
			clean, err := e.Submit(input(ID(), "Read", map[string]any{"text": "benign"}))
			if err != nil || clean.Decision != "approve" || clean.SensitiveInfo != nil {
				t.Fatal("benign control did not pass")
			}
			if err := e.Result(clean.ID, "instance", "succeeded", candidate); err != nil {
				t.Fatal(err)
			}
			saved, err := e.Review(clean.ID)
			if err != nil || saved.Decision != "reject" || saved.Execution != "succeeded" || saved.Result != "[REDACTED]" || saved.SensitiveInfo == nil {
				t.Fatal("result finding not rejected privately with honest execution state")
			}
			if err := e.Result(clean.ID, "instance", "succeeded", candidate); err != nil {
				t.Fatal("result retry lost idempotence")
			}
			exported, err := e.ExportCalls()
			if err != nil {
				t.Fatal(err)
			}
			audits, err := e.Audits()
			if err != nil {
				t.Fatal(err)
			}
			assertSecretAbsent(t, candidate, saved, audits, json.RawMessage(exported))
			for _, kind := range []string{"tg.sentry.audit.v1", "tg.sentry.risk.v1"} {
				if err := e.StreamEvents(context.Background(), kind, EventExportFilter{}, func(raw json.RawMessage) error { assertSecretAbsent(t, candidate, raw); return nil }); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSecretRequestSurfacesAndScope(t *testing.T) {
	candidate := policySecretCandidate()
	for _, in := range []ReviewInput{
		{ToolName: candidate, Arguments: map[string]any{}},
		{ToolName: "Read", Arguments: map[string]any{}, UserMessage: candidate},
		{ToolName: "Read", Arguments: map[string]any{}, Context: candidate},
		{ToolName: "Read", Arguments: map[string]any{}, Scripts: []ReviewScript{{Path: "fixture", Content: candidate}}},
	} {
		d, result := reviewSensitiveContext(context.Background(), in, secretRules(), BTPIIConfig{}, nil)
		if d == nil || d.Decision != "reject" || result == nil || len(result.Findings) == 0 {
			t.Fatal("request surface bypassed secret denial")
		}
		assertSecretAbsent(t, candidate, d, result)
	}
	for _, mutate := range []func(*Rule){func(r *Rule) { r.Enabled = false }, func(r *Rule) { r.Tool = "other" }, func(r *Rule) { r.Builtin = false }} {
		rules := secretRules()
		for i := range rules {
			mutate(&rules[i])
		}
		d, result := reviewSensitiveContext(context.Background(), input(ID(), "Read", map[string]any{"text": candidate}), rules, BTPIIConfig{}, nil)
		if d != nil || result != nil {
			t.Fatal("inactive/untrusted rule caused finding")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, result := reviewSensitiveContext(ctx, input(ID(), "Read", map[string]any{"text": candidate}), secretRules(), BTPIIConfig{}, nil)
	if d == nil || d.RuleID != "E_SECRET_SCAN" || result == nil || !result.Unavailable {
		t.Fatal("cancelled secret scan did not fail closed")
	}
}

func TestSecretFreeTextRedactionAndDenyOverlap(t *testing.T) {
	candidate := policySecretCandidate()
	if RedactText(candidate) != "[REDACTED]" || eventIdentifier(candidate) == candidate {
		t.Fatal("bare secret retained in comment or identifier")
	}
	deny := Rule{ID: "U_DENY", Name: candidate, Message: candidate, Matcher: "contains", Pattern: "", Enabled: true, Decision: "reject"}
	d := Evaluate(input(ID(), "Read", map[string]any{"text": candidate}), append(secretRules(), deny))
	if d == nil || d.Decision != "reject" {
		t.Fatal("overlap lost deny")
	}
	assertSecretAbsent(t, candidate, d)
}

func TestSecretStoredScopeAndResultObservation(t *testing.T) {
	e := engine(t)
	candidate := policySecretCandidate()
	var secret Rule
	for _, r := range secretRules() {
		if r.Pattern == "github-pat" {
			secret = r
		}
	}
	secret.Decision, secret.Tool = "approve", "Read"
	// Simulate the persisted S3 row, bypassing CRUD normalization deliberately.
	if err := e.put("rules", secret.ID, secret); err != nil {
		t.Fatal(err)
	}
	saved := ruleByID(t, e, secret.ID)
	if saved.Decision != "reject" || saved.Tool != "Read" || !saved.Enabled {
		t.Fatal("legacy load changed enablement/scope or retained allowing secret action")
	}
	secret.Enabled = false
	if got := normalizeRule(secret); got.Enabled || got.Tool != "Read" || got.Decision != "reject" {
		t.Fatal("disabled scope was not preserved")
	}
	// A log-only custom finding omits the original tool name before Result.
	custom := Rule{ID: "U_PRIVATE", Name: "fixture", Matcher: "contains", Pattern: "private-fixture", Decision: "alert", Enabled: true, Categories: []string{SensitiveInfoCategory}}
	if err := e.SaveRule(testActorContext(), custom); err != nil {
		t.Fatal(err)
	}
	r, err := e.Submit(input(ID(), "Read", map[string]any{"text": "private-fixture"}))
	if err != nil || r.Decision != "approve" || r.ToolName == "Read" {
		t.Fatal("omitted-tool fixture not exercised")
	}
	originalTool, originalCall := r.ToolName, r.CallID
	if err := e.Result(r.ID, "instance", "succeeded", candidate); err != nil {
		t.Fatal(err)
	}
	r, err = e.Review(r.ID)
	if err != nil || r.Decision != "reject" || r.RuleID != secret.ID {
		t.Fatal("result scope lost after tool omission")
	}
	if r.ToolName != originalTool || r.CallID != originalCall {
		t.Fatal("output omission broke existing input/result correlation")
	}
	event, ok := riskReviewEvent(r, "", "review.result")
	if !ok || event.Data.ActionID != 3 || event.Data.DispositionID != 17 {
		t.Fatal("output finding did not use observed/logged event semantics")
	}
	assertSecretAbsent(t, candidate, r, event)
}

func TestSecretOriginalSourceDenyOverlapPrivacy(t *testing.T) {
	e := engine(t)
	for _, secret := range secretRules() {
		t.Run(secret.ID, func(t *testing.T) {
			candidate := runtimeSecretCandidate(secret.Pattern)
			// Existing policy_test priority precedent: this unrelated deny wins.
			// A Name-only candidate is followed by a formatted closing parenthesis,
			// not an upstream token delimiter. Output re-matching cannot protect it.
			deny := Rule{ID: "U_OVERLAP", Name: candidate, Matcher: "contains", Pattern: "public-fixture", Enabled: true, Decision: "reject", Priority: 999}
			if err := e.SaveRule(testActorContext(), deny); err != nil {
				t.Fatal(err)
			}
			for _, broken := range []bool{false, true} {
				args := map[string]any{"operation": "public-fixture", "text": candidate}
				if broken {
					args["invalid"] = string([]byte{0xff})
				}
				in := input(ID(), "Read", args)
				d := Evaluate(in, append(secretRules(), deny))
				if d == nil || d.Decision != "reject" || d.RuleID != deny.ID {
					t.Fatal("source privacy changed winning deny")
				}
				assertSecretAbsent(t, candidate, d)
				r, err := e.Submit(in)
				if err != nil || r.Decision != "reject" || r.RuleID != deny.ID {
					t.Fatal("overlap Submit changed winning deny")
				}
				stored, err := e.Review(r.ID)
				if err != nil {
					t.Fatal(err)
				}
				audits, err := e.Audits()
				if err != nil {
					t.Fatal(err)
				}
				assertSecretAbsent(t, candidate, r, stored, audits)
			}
		})
	}
}

func TestSecretRuleEchoMetadataPrivacy(t *testing.T) {
	e := engine(t)
	for _, rule := range secretRules() {
		t.Run(rule.ID, func(t *testing.T) {
			candidate := runtimeSecretCandidate(rule.Pattern)
			// A dotted JWT Field is a real nested path, not an unmatchable key.
			var value any = "public-fixture"
			parts := strings.Split(candidate, ".")
			for i := len(parts) - 1; i >= 0; i-- {
				value = map[string]any{parts[i]: value}
			}
			deny := Rule{ID: "U_METADATA", Name: "Metadata fixture", Matcher: "contains", Pattern: "public-fixture", Field: candidate, Tool: candidate, Enabled: true, Decision: "reject", Priority: 999}
			if err := e.SaveRule(testActorContext(), deny); err != nil {
				t.Fatal(err)
			}
			in := input(ID(), candidate, value.(map[string]any))
			d := Evaluate(in, append(secretRules(), deny))
			if d == nil || d.Decision != "reject" || d.RuleID != deny.ID {
				t.Fatal("metadata privacy changed winning deny")
			}
			r, err := e.Submit(in)
			if err != nil || r.Decision != "reject" || r.RuleID != deny.ID {
				t.Fatal("metadata fixture did not retain winning deny")
			}
			stored, err := e.Review(r.ID)
			if err != nil {
				t.Fatal(err)
			}
			exported, err := e.ExportCalls()
			if err != nil {
				t.Fatal(err)
			}
			assertSecretAbsent(t, candidate, d, r, stored, json.RawMessage(exported), ProjectReviewContent([]Review{stored}, true), ProjectReviewContent([]Review{stored}, false))
			for _, snapshot := range stored.Rules {
				if snapshot.ID == deny.ID && (snapshot.Tool != sensitiveIdentifier(candidate) || snapshot.Field != sensitiveIdentifier(candidate)) {
					t.Fatal("rule echo did not use correlation-safe omission")
				}
			}
			if original := ruleByID(t, e, deny.ID); original.Tool != candidate || original.Field != candidate {
				t.Fatal("snapshot privacy mutated configured rule scope")
			}
		})
	}
}

func TestSecretScriptSHA256Privacy(t *testing.T) {
	e := engine(t)
	for _, rule := range secretRules() {
		t.Run(rule.ID, func(t *testing.T) {
			candidate := runtimeSecretCandidate(rule.Pattern)
			in := input(ID(), "Read", map[string]any{"text": "benign"})
			in.Scripts = []ReviewScript{{Path: "fixture", SHA256: candidate, Complete: true}}
			d := Evaluate(in, secretRules())
			if d == nil || d.Decision != "reject" || d.RuleID != rule.ID {
				t.Fatal("caller SHA256 escaped source secret scan")
			}
			r, err := e.Submit(in)
			if err != nil || r.Decision != "reject" || r.RuleID != rule.ID || r.SensitiveInfo == nil {
				t.Fatal("script SHA256 secret did not reject")
			}
			stored, err := e.Review(r.ID)
			if err != nil {
				t.Fatal(err)
			}
			exported, err := e.ExportCalls()
			if err != nil {
				t.Fatal(err)
			}
			assertSecretAbsent(t, candidate, d, r, stored, json.RawMessage(exported), ProjectReviewContent([]Review{stored}, true), ProjectReviewContent([]Review{stored}, false))
		})
	}
}
