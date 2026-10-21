package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlockAlertEventsAcrossAgents(t *testing.T) {
	schemas := pinnedEventSchemas(t)
	for _, agent := range []string{"claude", "openclaw"} {
		for _, tc := range []struct {
			action, decision        string
			actionID, dispositionID int
		}{
			{"reject", "reject", 0, 0}, // Policy denial is not confirmed prevention.
			{"alert", "approve", 3, 19},
		} {
			t.Run(agent+"/"+tc.action, func(t *testing.T) {
				e := engine(t)
				if err := e.Register(Instance{ID: agent, Agent: agent, SessionID: "session", Cwd: t.TempDir(), HookVersion: Version}); err != nil {
					t.Fatal(err)
				}
				if err := e.SaveRule(testActorContext(), Rule{ID: "U_ACTION", Name: "Fixture", Enabled: true, Decision: tc.action, Tool: "fixture", Pattern: "risk"}); err != nil {
					t.Fatal(err)
				}
				r, err := e.Submit(ReviewInput{InstanceID: agent, CallID: "action", ToolName: "fixture", Arguments: map[string]any{"value": "risk"}})
				if err != nil || r.Decision != tc.decision || r.ReviewPath != "rule" || r.Agent != agent {
					t.Fatal(r, err)
				}
				page, err := e.RiskEvents(0, "", RiskEventFilter{})
				if err != nil || len(page.Items) != 1 {
					t.Fatal(page, err)
				}
				event := page.Items[0]
				if event.Data.ActionID != tc.actionID || event.Data.DispositionID != tc.dispositionID || event.Data.FindingInfo.UID != r.ID {
					t.Fatalf("%s: action/disposition = %d/%d, want %d/%d", agent, event.Data.ActionID, event.Data.DispositionID, tc.actionID, tc.dispositionID)
				}
				if err := validateEventWire(schemas, wireEvent(t, event)); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Failure policies apply only to unresolved reviews, never a terminal policy deny.
// Exercise stale model completions too: normal Submit must not start the judge.
func TestExplicitDenySurvivesFailures(t *testing.T) {
	for _, agent := range []string{"claude", "openclaw"} {
		for _, failure := range []string{"model_error", "model_timeout", "model_invalid", "late_model_allow", "approval_timeout", "session_disconnect", "human_allow", "audit_failure", "alert_and_allow"} {
			t.Run(agent+"/"+failure, func(t *testing.T) {
				e := engine(t)
				if err := e.Register(Instance{ID: agent, Agent: agent, SessionID: "session", Cwd: t.TempDir(), HookVersion: Version}); err != nil {
					t.Fatal(err)
				}
				for _, rule := range []Rule{
					{ID: "U_DENY", Name: "Fixture deny", Enabled: true, Decision: "reject", Tool: "fixture", Pattern: "risk"},
					{ID: "U_ALERT", Name: "Fixture alert", Enabled: true, Decision: "alert", Tool: "fixture", Pattern: "risk", Priority: 1000},
					{ID: "U_ALLOW", Name: "Fixture allow", Enabled: true, Decision: "approve", Tool: "fixture", Pattern: "risk", Priority: 1000},
				} {
					if err := e.SaveRule(testActorContext(), rule); err != nil {
						t.Fatal(err)
					}
				}
				var requests atomic.Int32
				original := http.DefaultTransport
				t.Cleanup(func() { http.DefaultTransport = original })
				http.DefaultTransport = reviewRoundTrip(func(*http.Request) (*http.Response, error) {
					requests.Add(1)
					switch failure {
					case "model_error":
						return nil, errors.New("fixture judge failure")
					case "model_timeout":
						return nil, context.DeadlineExceeded
					case "model_invalid":
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{"))}, nil
					default:
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"{\"decision\":\"approve\",\"comment\":\"实际操作：fixture；成功后的后果：fixture；命中规则：D1\"}"}}]}`))}, nil
					}
				})
				e.mu.Lock()
				e.Settings.Mode = "model"
				if failure == "human_allow" {
					e.Settings.Mode = "human"
				}
				e.Settings.Model = ModelConfig{ProcessingClass: ModelProcessingSelfHosted, Protocol: "openai", BaseURL: "https://fixture.invalid", Model: "fixture", Tested: true}
				s := e.Settings
				e.mu.Unlock()
				if failure == "audit_failure" {
					rejectAudit(t, e)
				}
				in := ReviewInput{InstanceID: agent, CallID: "denied", ToolName: "fixture", Arguments: map[string]any{"value": "risk"}, ScriptCaptureStatus: "incomplete"}
				r, err := e.Submit(in)
				if (err != nil) != (failure == "audit_failure") || r.Decision != "reject" || r.Execution != "not_executed" || r.RuleID != "U_DENY" || r.NeedsHuman || requests.Load() != 0 {
					t.Fatal("explicit deny did not terminate before fallback", r, err, requests.Load())
				}
				if failure == "audit_failure" {
					if _, err := e.Review(r.ID); err == nil {
						t.Fatal("failed audit committed a review")
					}
					return
				}
				switch failure {
				case "model_error", "model_timeout", "model_invalid", "late_model_allow":
					e.modelReview(r, s)
					if requests.Load() != 1 {
						t.Fatal("judge failure/completion was not exercised", requests.Load())
					}
					usage, err := e.Usage()
					if err != nil || len(usage) != 1 || usage[0].Failed != (failure != "late_model_allow") {
						t.Fatal("judge fixture did not produce the intended outcome", usage, err)
					}
				case "approval_timeout":
					e.mu.Lock()
					e.clock = func() time.Time { return r.Deadline.Add(time.Second) }
					e.mu.Unlock()
					e.Expire()
				case "session_disconnect":
					if err := e.Disconnect(agent); err != nil {
						t.Fatal(err)
					}
				case "human_allow":
					if _, err := e.Decide(testActorContext(), r.ID, r.Digest, "approve", "fixture"); err == nil {
						t.Fatal("human approval overrode deny")
					}
				}
				stored, err := e.Review(r.ID)
				if err != nil || stored.Decision != "reject" || stored.RuleID != "U_DENY" || stored.Execution != "not_executed" || stored.ModelVerdict != nil {
					t.Fatal("failure replaced explicit deny", stored, err)
				}
				if err := e.Result(r.ID, agent, "succeeded", "fixture"); err == nil {
					t.Fatal("denied execution accepted")
				}
				page, err := e.RiskEvents(0, "", RiskEventFilter{})
				if err != nil || len(page.Items) != 1 || page.Items[0].Data.ActionID != 0 || page.Items[0].Data.DispositionID != 0 {
					t.Fatal("deny finding changed or duplicated", page, err)
				}
			})
		}
	}
}
