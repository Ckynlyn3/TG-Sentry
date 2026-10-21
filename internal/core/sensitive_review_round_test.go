package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Ported from the independent #20 review's synthetic repros.
func TestReview20CustomLogOnlyAfterA7(t *testing.T) {
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
	if len(page.Items) != 1 {
		t.Fatal("expected one sensitive-info risk event for matching log-only rule")
	}
	if page.Items[0].Data.FindingInfo.Analytic.UID != "U_PRIVATE" || page.Items[0].Data.ActionID != 3 {
		t.Fatal("observation attributed to winner or claimed blocking")
	}
	if err := validateEventWire(pinnedEventSchemas(t), wireEvent(t, page.Items[0])); err != nil {
		t.Fatal(err)
	}
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_DENY", Name: "Deny", Matcher: "contains", Pattern: private, Enabled: true, Decision: "reject"}); err != nil {
		t.Fatal(err)
	}
	denied, err := e.Submit(input("custom-denied", "read", map[string]any{"value": private}))
	if err != nil || denied.Decision != "reject" || denied.RuleID != "U_DENY" {
		t.Fatal("deny overridden", err)
	}
	page, err = e.RiskEvents(0, "", RiskEventFilter{Category: SensitiveInfoCategory})
	if err != nil || len(page.Items) != 2 {
		t.Fatal("denied call hid custom finding", err)
	}
}

func TestReview20IndependentCustomMatchSemantics(t *testing.T) {
	for _, winner := range []string{"approve", "reject"} {
		t.Run(winner, func(t *testing.T) {
			in := ReviewInput{ToolName: "read", Arguments: map[string]any{"nested": map[string]any{"value": "synthetic-private"}, "elsewhere": "synthetic-other"}}
			base := Rule{Enabled: true, Matcher: "keywords", Pattern: "synthetic-private", Field: "nested.value", Tool: "read", Categories: []string{SensitiveInfoCategory}, Decision: "approve"}
			rules := []Rule{}
			for _, tc := range []struct {
				id, matcher, field, target, tool, pattern string
				enabled                                   bool
			}{
				{"U_FIELD", "keywords", "nested.value", "arguments", "read", "synthetic-private", true},
				{"U_REGEX", "regex", "nested.value", "arguments", "read", "synthetic-private", true},
				{"U_TOOL", "contains", "ignored", "toolName", "read", "read", true},
				{"U_WHOLE", "contains", "", "arguments", "read", "synthetic-other", true},
				{"U_MISSING", "keywords", "missing", "arguments", "read", "synthetic-private", true},
				{"U_WRONG_FIELD", "keywords", "elsewhere", "arguments", "read", "synthetic-private", true},
				{"U_WRONG_TOOL", "keywords", "nested.value", "arguments", "write", "synthetic-private", true},
				{"U_DISABLED", "keywords", "nested.value", "arguments", "read", "synthetic-private", false},
			} {
				r := base
				r.ID, r.Matcher, r.Field, r.Target, r.Tool, r.Pattern, r.Enabled = tc.id, tc.matcher, tc.field, tc.target, tc.tool, tc.pattern, tc.enabled
				rules = append(rules, r)
			}
			before := &Decision{Decision: winner, RuleID: "winner"}
			decision, result := reviewSensitive(in, rules, BTPIIConfig{}, before)
			if decision != before || result == nil || len(result.Findings) != 4 {
				t.Fatal("independent findings or deny precedence lost")
			}
			for _, f := range result.Findings {
				if !hasExact(f.RuleID, "U_FIELD", "U_REGEX", "U_TOOL", "U_WHOLE") {
					t.Error("inapplicable rule reported")
				}
			}
		})
	}
}

func TestReview20RetainedMetadata(t *testing.T) {
	e := engine(t)
	card := syntheticCard()
	reserved := Instance{ID: sensitiveIdentifier(card), SessionID: "safe", Cwd: t.TempDir(), HookVersion: Version}
	if e.Register(reserved) == nil {
		t.Fatal("caller occupied reserved digest namespace")
	}
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

func TestReview20CallerMetadataWithoutDetector(t *testing.T) {
	e := engine(t)
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_ALLOW", Name: "Allow", Enabled: true, Matcher: "regex", Pattern: ".*", Decision: "approve"}); err != nil {
		t.Fatal(err)
	}
	in := input("call-"+syntheticCard(), "tool-"+syntheticCard(), map[string]any{"value": "safe"})
	in.ScriptCaptureStatus = "capture-" + syntheticCard()
	r, err := e.Submit(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), syntheticCard()) {
		t.Error("caller metadata echoed into review")
	}
}

func TestReview20InstanceIdentityLifecycle(t *testing.T) {
	for _, instanceID := range []string{"ordinary-instance", "instance-" + syntheticCard()} {
		t.Run(strings.Split(instanceID, "-")[0], func(t *testing.T) {
			e := engine(t)
			instance := Instance{ID: instanceID, SessionID: "session-" + syntheticCard(), Cwd: t.TempDir(), HookVersion: Version}
			if err := e.Register(instance); err != nil {
				t.Fatal(err)
			}
			if err := e.Register(instance); err != nil {
				t.Fatal("re-registration", err)
			}
			if err := e.Heartbeat(instanceID, "running"); err != nil {
				t.Fatal(err)
			}
			if !e.ClientOwnsInstance("", instanceID) {
				t.Fatal("instance ownership lost")
			}
			in := ReviewInput{InstanceID: instanceID, CallID: "call-" + syntheticCard(), ToolName: "read", Arguments: map[string]any{"path": "safe"}}
			r, err := e.Submit(in)
			if err != nil {
				t.Fatal(err)
			}
			key := sha256.Sum256([]byte(instanceID + "\x00" + in.CallID))
			if r.ID != hex.EncodeToString(key[:]) {
				t.Error("native bridge correlation key changed")
			}
			replay, err := e.Submit(in)
			if err != nil || replay.ID != r.ID {
				t.Fatal("idempotent submit", err)
			}
			if err := e.Result(r.ID, instanceID, "succeeded", "safe"); err != nil {
				t.Fatal(err)
			}
			in.CallID, in.ToolName = "pending", "tool-"+syntheticCard()
			pending, err := e.Submit(in)
			if err != nil || pending.Decision != "pending" {
				t.Fatal("pending review", err)
			}
			e.Expire()
			saved, err := e.Review(pending.ID)
			if err != nil || saved.Decision != "pending" {
				t.Fatal("online instance expired", err)
			}
			if err := e.Disconnect(instanceID); err != nil {
				t.Fatal(err)
			}
			saved, err = e.Review(pending.ID)
			if err != nil || saved.RuleID != "E_SESSION" {
				t.Fatal("pending cancellation", err)
			}
			page, err := e.ReviewsPage(1, 20, ReviewFilter{SessionID: instance.SessionID})
			if err != nil || page.Total != 2 {
				t.Fatal("raw session filter lost correlation", err)
			}
			tx, err := e.beginTenant()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			rows, err := tx.Query("SELECT id,payload FROM records WHERE tenant_id=$1", eventTenant())
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var id, payload string
				if err := rows.Scan(&id, &payload); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(id+payload, syntheticCard()) {
					t.Error("private identifier persisted")
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if instanceID == "ordinary-instance" && r.InstanceID != instanceID {
				t.Fatal("ordinary instance changed")
			}
		})
	}
}

func TestReview20DelimitedPANIdentifier(t *testing.T) {
	for _, identifier := range []string{syntheticCard(), "session-" + syntheticCard(), "U_" + syntheticCard(), "session-" + syntheticCard() + "-suffix", "U_" + syntheticCard() + "x", "U_" + syntheticID(), "U_" + strings.ToLower(syntheticID())} {
		if eventIdentifier(identifier) == identifier {
			t.Error("checksum-valid private identifier retained")
		}
	}
	for _, identifier := range []string{"ordinary-session-123", "U_123", "U_" + syntheticCard()[:15] + "9", "a" + syntheticCard() + "f", syntheticCard() + "abcdef", "abcdef" + syntheticCard()} {
		if eventIdentifier(identifier) != identifier {
			t.Error("ordinary or invalid-checksum identifier changed")
		}
	}
}

func TestReview20InactiveRuleSnapshot(t *testing.T) {
	e := engine(t)
	const private = "synthetic-private-review20"
	for _, rule := range []Rule{
		{ID: "U_PRIVATE", Name: "Private", Matcher: "keywords", Pattern: private, Field: "value", Tool: "write", Enabled: true, Decision: "alert", Categories: []string{SensitiveInfoCategory}},
		{ID: "U_DISABLED", Name: private, Message: private, Matcher: "regex", Pattern: private, Enabled: false, Decision: "approve", Categories: []string{SensitiveInfoCategory}},
	} {
		if err := e.SaveRule(testActorContext(), rule); err != nil {
			t.Fatal(err)
		}
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
