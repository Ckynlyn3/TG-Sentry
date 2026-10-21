package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIndependentMetadataSecretCanaries(t *testing.T) {
	e := engine(t)
	const canary = "Bearer synthetic-secret-canary"
	if RedactText(canary) == canary {
		t.Fatal("invalid redaction measuring fixture")
	}
	if err := e.Register(Instance{ID: "private-session", SessionID: canary, Cwd: t.TempDir(), HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_PRIVATE", Name: "fixture", Enabled: true, Decision: "reject", Pattern: ".*"}); err != nil {
		t.Fatal(err)
	}
	_, err := e.Submit(ReviewInput{InstanceID: "private-session", CallID: canary, ToolName: canary, Arguments: map[string]any{"password": "synthetic-secret-canary"}})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range audits {
		for _, event := range a.Events {
			b, _ := json.Marshal(event)
			if strings.Contains(string(b), "synthetic-secret-canary") {
				t.Errorf("metadata event persisted detected-secret canary: %s", b)
			}
		}
	}
}

func TestIndependentValidatorRejectsPrivacyAndTypeViolations(t *testing.T) {
	schemas := pinnedEventSchemas(t)
	e := engine(t)
	_, err := e.Submit(input("schema-probe", "Bash", map[string]any{"command": "redis-cli FLUSHALL"}))
	if err != nil {
		t.Fatal(err)
	}
	page, err := e.RiskEvents(1, "", RiskEventFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Fatal(err, page)
	}
	for _, name := range []string{"extension-object", "raw-message", "invented-source", "raw-actor-name"} {
		t.Run(name, func(t *testing.T) {
			wire := wireEvent(t, page.Items[0])
			data := wire["data"].(map[string]any)
			switch name {
			case "extension-object":
				data["unmapped"].(map[string]any)["tg_sentry"].(map[string]any)["tool_call_id"] = map[string]any{"password": "raw-secret-canary"}
			case "raw-message":
				data["message"] = "Bearer raw-secret-canary"
			case "invented-source":
				wire["source"] = "/endpoints/forged"
			case "raw-actor-name":
				data["actor"].(map[string]any)["app_name"] = "Bearer raw-secret-canary"
			}
			if err := validateEventWire(schemas, wire); err == nil {
				t.Errorf("invalid wire accepted: %s", name)
			}
		})
	}
}

func TestIndependentModelDoesNotClaimDisabledDeterministicRule(t *testing.T) {
	e := engine(t)
	rules, err := e.Rules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == "R1" {
			r.Enabled = false
			r.Severity = "critical"
			r.Categories = []string{"category::supply-chain"}
			if err = e.SaveRule(testActorContext(), r); err != nil {
				t.Fatal(err)
			}
		}
	}
	r, err := e.Submit(input("model-probe", "fixture_tool", map[string]any{"command": "opaque"}))
	if err != nil || r.Decision != "pending" {
		t.Fatal(err, r)
	}
	r.NeedsHuman = false
	r.Mode = "model"
	r.ReviewPath = "model"
	if err = e.put("reviews", r.ID, r); err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"decision":"reject","comment":"实际操作：fixture；成功后的后果：fixture；命中规则：R1"}`}}}})
	}))
	defer up.Close()
	s := e.Settings
	s.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, BaseURL: up.URL, Model: "fixture", Tested: true}
	e.modelReview(r, s)
	stored, err := e.Review(r.ID)
	if err != nil || stored.Decision != "reject" || stored.ModelVerdict == nil {
		t.Fatal(stored, err)
	}
	page, err := e.RiskEvents(1, "", RiskEventFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Fatal(page, err)
	}
	event := page.Items[0]
	if event.Data.SeverityID != 0 || len(event.Data.FindingInfo.Types) > 0 || event.Data.FindingInfo.Analytic == nil || event.Data.FindingInfo.Analytic.TypeID != 4 || event.Data.FindingInfo.Analytic.UID == "R1" {
		t.Fatalf("model finding borrowed disabled deterministic rule metadata: %+v", event.Data)
	}
}

func TestIndependentPostCommitNotificationAndCommitFailure(t *testing.T) {
	e := engine(t)
	notified := 0
	e.Notify = func() {
		notified++
		if _, err := e.Audits(); err != nil {
			t.Error(err)
		}
	}
	if _, err := e.Submit(input("committed", "Read", map[string]any{"path": "fixture"})); err != nil {
		t.Fatal(err)
	}
	if notified != 1 {
		t.Fatal("successful commit did not notify", notified)
	}
	rejectAudit(t, e)
	r, err := e.Submit(input("rejected-audit", "Read", map[string]any{"path": "fixture"}))
	if err == nil || r.Decision != "reject" || r.Execution != "not_executed" || notified != 1 {
		t.Fatal("audit failure or notify failed closed invariant", r, err, notified)
	}
}

func TestEventIdentifierBoundariesAndCorrelation(t *testing.T) {
	// Identifier suffix ceiling is the existing SaveRule 64-byte precedent.
	for _, tc := range []struct {
		value    string
		preserve bool
	}{
		{"call_ABC-123.example~id", true}, {strings.Repeat("x", 64), true},
		{strings.Repeat("x", 65), false}, {"Bearer synthetic-correlation-secret", false},
		{"line\nbreak", false}, {"/private/customer/path", false}, {"prompt fragment", false},
	} {
		got := eventIdentifier(tc.value)
		if (got == tc.value) != tc.preserve || !eventIdentifierPattern.MatchString(got) || eventIdentifier(tc.value) != got || (tc.preserve && eventIdentifier(got) != got) || RedactText(got) != got {
			t.Fatal("unsafe or unstable identifier projection")
		}
		if !tc.preserve && !strings.HasPrefix(got, "sha256:") {
			t.Fatal("unsafe identifier not digested")
		}
	}
	if eventIdentifier("") != "" {
		t.Fatal("invented absent identifier")
	}
	// A caller-supplied digest literal must not alias the value it digests.
	if aliased := eventIdentifier("Bearer one-secret"); eventIdentifier(aliased) == aliased {
		t.Fatal("caller-supplied sha256 literal aliases a generated digest")
	}
	if eventIdentifier("Bearer one-secret") == eventIdentifier("Bearer other-secret") {
		t.Fatal("redaction collapsed distinct correlation IDs")
	}
	e := engine(t)
	const canary = "Bearer synthetic-correlation-secret"
	if err := e.Register(Instance{ID: "private", SessionID: canary, Cwd: t.TempDir(), HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_PRIVATE_ALERT", Name: "fixture", Enabled: true, Decision: "alert", Pattern: ".*"}); err != nil {
		t.Fatal(err)
	}
	review, err := e.Submit(ReviewInput{InstanceID: "private", CallID: canary, ToolName: canary, Arguments: map[string]any{"password": "fixture"}})
	if err != nil || review.Decision != "approve" {
		t.Fatal("fixture setup failed", err)
	}
	if err = e.Result(review.ID, "private", "succeeded", "fixture"); err != nil {
		t.Fatal(err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	schemas := pinnedEventSchemas(t)
	count := 0
	for _, audit := range audits {
		for _, event := range audit.Events {
			count++
			if err := validateEventWire(schemas, wireEvent(t, event)); err != nil {
				t.Fatal(err)
			}
			if event.Data.Metadata.CorrelationUID != eventIdentifier(canary) {
				t.Fatal("session correlation changed")
			}
			if event.Type == "tg.sentry.audit.v1" {
				if event.Data.API.Operation != eventIdentifier(canary) || event.Data.API.Request.UID != eventIdentifier(canary) {
					t.Fatal("request/result correlation changed")
				}
			} else if event.Data.Unmapped.TGSentry.ToolCallID != eventIdentifier(canary) {
				t.Fatal("finding/call correlation changed")
			}
		}
	}
	if count != 3 {
		t.Fatal("missing request/result/finding", count)
	}
}

func TestEventValidatorRejectsExtensionAndIdentityMutations(t *testing.T) {
	schemas := pinnedEventSchemas(t)
	e := engine(t)
	if _, err := e.Submit(input("validator-boundaries", "Bash", map[string]any{"command": "redis-cli FLUSHALL"})); err != nil {
		t.Fatal(err)
	}
	page, err := e.RiskEvents(1, "", RiskEventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{nil, 3.0, []any{"fixture"}, map[string]any{"password": "fixture"}, "Bearer fixture-secret", "unsafe identifier", strings.Repeat("x", 65)} {
		wire := wireEvent(t, page.Items[0])
		wire["data"].(map[string]any)["unmapped"].(map[string]any)["tg_sentry"].(map[string]any)["tool_call_id"] = value
		if validateEventWire(schemas, wire) == nil {
			t.Fatal("invalid extension value accepted")
		}
	}
	wire := wireEvent(t, page.Items[0])
	data := wire["data"].(map[string]any)
	data["src_endpoint"] = map[string]any{"uid": "invented"}
	if validateEventWire(schemas, wire) == nil {
		t.Fatal("unenrolled endpoint invented")
	}
	// An enrolled source must agree with both the protected-agent and endpoint.
	code, err := e.CreateEnrollment(testActorContext(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Register(Instance{ID: "remote-boundaries", NodeID: connection.NodeID, Agent: "claude", Platform: "linux", SessionID: "fixture", Cwd: "/work", HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Submit(ReviewInput{InstanceID: "remote-boundaries", CallID: "call", ToolName: "Read", Arguments: map[string]any{"path": "fixture"}}); err != nil {
		t.Fatal(err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		for _, event := range audit.Events {
			if event.Data.Actor.AppUID == "" {
				continue
			}
			wire = wireEvent(t, event)
			wire["source"] = "/endpoints/forged"
			if validateEventWire(schemas, wire) == nil {
				t.Fatal("enrolled source mismatch accepted")
			}
			wire = wireEvent(t, event)
			wire["data"].(map[string]any)["src_endpoint"].(map[string]any)["uid"] = "forged"
			if validateEventWire(schemas, wire) == nil {
				t.Fatal("enrolled endpoint mismatch accepted")
			}
		}
	}
}

func TestModelAnalyticIdentityDoesNotBorrowRuleMetadata(t *testing.T) {
	now := time.Now()
	r := Review{ID: "fixture", Agent: "claude", SessionID: "session", ReviewPath: "model", Decision: "reject", RuleID: "R1", DecidedAt: &now, ModelVerdict: &Decision{Decision: "reject", RuleID: "R1"}, Rules: []Rule{{ID: "R1", Enabled: true, Severity: "critical", Categories: []string{"category::supply-chain"}}}}
	schemas := pinnedEventSchemas(t)
	for _, name := range []string{"", "observed-model", "Bearer synthetic-model-secret"} {
		candidate := r
		candidate.ModelName = name
		event, ok := riskReviewEvent(candidate, "", "review.model")
		if !ok || event.Data.SeverityID != 0 || len(event.Data.FindingInfo.Types) != 0 {
			t.Fatal("model inherited deterministic classification")
		}
		analytic := event.Data.FindingInfo.Analytic
		if analytic == nil || analytic.TypeID != 4 || analytic.UID != eventIdentifier(name) {
			t.Fatal("incorrect model analytic")
		}
		if err := validateEventWire(schemas, wireEvent(t, event)); err != nil {
			t.Fatal(err)
		}
	}
	// A disabled snapshot is never an observed deterministic hit.
	r.ReviewPath = "rule"
	r.ModelVerdict = nil
	r.Rules[0].Enabled = false
	event, ok := riskReviewEvent(r, "", "review.submit")
	if !ok || event.Data.FindingInfo.Analytic != nil || event.Data.SeverityID != 0 {
		t.Fatal("disabled rule attributed")
	}
}
