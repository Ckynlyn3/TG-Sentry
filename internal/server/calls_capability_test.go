package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"testing/fstest"
	"time"
)

func TestCallsContentCapabilityBothShapes(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	legacy := "synthetic legacy context"
	now := time.Now().UTC()
	retained := core.Review{
		ID: "retained", Agent: "claude", ReviewInput: core.ReviewInput{InstanceID: "instance", CallID: "call", ToolName: "read", Arguments: map[string]any{"value": "synthetic arguments"}, UserMessage: "synthetic user message", Context: "synthetic context", ScriptCaptureStatus: "complete", Scripts: []core.ReviewScript{{Path: "safe.sh", Content: "synthetic script source", SHA256: "fixture", Bytes: 23, Complete: true}}},
		ModelContext: &legacy, ModelInput: json.RawMessage(`{"value":"synthetic model input"}`), ModelInputDigest: "digest", ModelName: "fixture-model", SessionID: "session", Cwd: "/fixture", Digest: "digest", Mode: "human", ReviewPath: "rule", Version: 1, Prompt: "fixture policy", Rules: []core.Rule{}, Scopes: []core.Scope{}, Decision: "approve", RuleID: "A7", Comment: "safe read", Execution: "succeeded", Result: "synthetic result", CreatedAt: now, DecidedAt: &now, Deadline: now, ModelVerdict: &core.Decision{Decision: "approve"},
	}
	clean := retained
	clean.ID, clean.SensitiveInfo, clean.Result = "clean-sensitive", &core.SensitiveResult{}, "[REDACTED]"
	omitted := clean
	omitted.ID, omitted.SensitiveInfo = "omitted", &core.SensitiveResult{Findings: []core.SensitiveFinding{{Category: core.SensitiveInfoCategory}}}
	omitted.Arguments, omitted.UserMessage, omitted.Context, omitted.Scripts = map[string]any{"content": "[REDACTED]"}, "[REDACTED]", "[REDACTED]", nil
	pending := omitted
	pending.ID, pending.Decision, pending.Execution, pending.Result = "pending", "pending", "not_executed", ""
	awaiting := clean
	awaiting.ID, awaiting.Execution, awaiting.Result = "awaiting", "awaiting_execution", ""
	for _, review := range []core.Review{retained, clean, omitted, pending, awaiting} {
		payload, err := json.Marshal(review)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('default','reviews',$1,$2)", review.ID, string(payload)); err != nil {
			t.Fatal(err)
		}
	}
	s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	wantStates := map[string][2]string{
		"retained": {"captured", "captured"}, "clean-sensitive": {"captured", "policy_omitted"}, "omitted": {"policy_omitted", "policy_omitted"}, "pending": {"policy_omitted", "not_yet_available"}, "awaiting": {"captured", "not_yet_available"},
	}
	for _, query := range []string{"", "?page=1&size=20"} {
		t.Run("shape"+query, func(t *testing.T) {
			request := func() map[string]map[string]any {
				t.Helper()
				r := httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/calls"+query, nil)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal("calls request failed", w.Code)
				}
				var items []map[string]any
				if query == "" {
					if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
						t.Fatal(err)
					}
				} else {
					var page struct {
						Items                               []map[string]any `json:"items"`
						Total, Page, PageSize, PendingTotal int
					}
					if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
						t.Fatal(err)
					}
					if page.Total != 5 || page.Page != 1 || page.PageSize != 20 {
						t.Fatal("page metadata changed")
					}
					items = page.Items
				}
				if len(items) != len(wantStates) {
					t.Fatal("missing review fixtures")
				}
				out := map[string]map[string]any{}
				for _, item := range items {
					out[item["id"].(string)] = item
				}
				return out
			}
			s.contentAllowedOverride = nil
			allowed := request()
			for id, states := range wantStates {
				if allowed[id]["inputState"] != states[0] || allowed[id]["outputState"] != states[1] {
					t.Errorf("incorrect allowed content states for %s", id)
				}
			}
			for _, key := range []string{"argumentsObj", "userMessage", "context", "result", "modelContext"} {
				if _, ok := allowed["retained"][key]; !ok {
					t.Errorf("console default stripped %s", key)
				}
			}
			s.contentAllowedOverride = func(*http.Request) bool { return false }
			restricted := request()
			for id, item := range restricted {
				if item["inputState"] != "permission_restricted" || item["outputState"] != "permission_restricted" {
					t.Errorf("permission did not override states for %s", id)
				}
				for _, key := range []string{"argumentsObj", "userMessage", "context", "result", "modelContext", "modelInput"} {
					if _, exposed := item[key]; exposed {
						t.Errorf("restricted response includes %s", key)
					}
				}
				if scripts, ok := item["scriptFiles"].([]any); ok {
					for _, script := range scripts {
						if _, exposed := script.(map[string]any)["content"]; exposed {
							t.Error("restricted script content exposed")
						}
					}
				}
				// Apart from the five excluded fields and states, preserve the list metadata.
				want := allowed[id]
				for _, key := range []string{"argumentsObj", "userMessage", "context", "result", "modelContext"} {
					delete(want, key)
				}
				want["inputState"], want["outputState"] = "permission_restricted", "permission_restricted"
				if !reflect.DeepEqual(item, want) {
					t.Errorf("restricted metadata differs for %s", id)
				}
			}
		})
	}
}

func TestCallsContentCapabilityDoesNotAuthorizeOtherCallers(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	code, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	device, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	for _, contentAllowed := range []bool{false, true} {
		s.contentAllowedOverride = func(*http.Request) bool { return contentAllowed }
		h := s.Handler()
		for _, query := range []string{"", "?page=1"} {
			for _, tc := range []struct {
				auth   string
				status int
			}{{"", 401}, {"Bearer fixture-hook", 403}, {"Bearer " + device.Token, 403}} {
				r := httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/calls"+query, nil)
				r.Header.Set("Authorization", tc.auth)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != tc.status {
					t.Errorf("caller denial: status=%d want=%d", w.Code, tc.status)
				}
			}
		}
	}
}
