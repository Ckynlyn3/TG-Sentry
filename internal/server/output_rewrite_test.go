package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestToolOutputTransformHTTP(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "output", Agent: "claude", SessionID: "output", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	got := h.call("POST", "/api/v1/reviews", core.ReviewInput{InstanceID: "output", CallID: "call", ToolName: "Read", Arguments: map[string]any{"file_path": "README.md"}}, 200, "fixture-hook")
	id := got["id"].(string)
	rule := core.Rule{ID: "U_OUTPUT", Name: "Output fixture", Matcher: "contains", Pattern: "private-fixture", Decision: "redact", Enabled: true, Target: "arguments", Tool: "Read", Categories: []string{core.SensitiveInfoCategory}}
	if err := h.engine.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
		t.Fatal(err)
	}
	// Isolate this policy from the enabled baseline credential-block rules.
	rules, err := h.engine.Rules()
	if err != nil {
		t.Fatal(err)
	}
	for _, saved := range rules {
		if saved.Matcher == "secret" {
			saved.Enabled = false
			if err := h.engine.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), saved); err != nil {
				t.Fatal(err)
			}
		}
	}
	path := "/api/v1/reviews/" + id + "/transform-tool-output"
	for _, terminal := range []bool{false, true} {
		if terminal {
			ack := h.call("POST", "/api/v1/reviews/"+id+"/result", map[string]string{"instanceId": "output", "state": "succeeded", "result": "benign"}, 200, "fixture-hook")
			if !reflect.DeepEqual(ack, map[string]any{"ok": true}) {
				t.Fatal("terminal acknowledgement changed")
			}
		}
		before, _ := h.engine.Review(id)
		reply := h.call("POST", path, map[string]string{"operation": "transform_tool_output", "text": "😀 private-fixture"}, 200, "fixture-hook")
		if !reflect.DeepEqual(reply, map[string]any{"outcome": "rewritten", "text": "😀 [CUSTOM]"}) {
			t.Fatal("wrong transform response")
		}
		after, _ := h.engine.Review(id)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("transformation mutated terminal state")
		}
	}
	for _, action := range []string{"redact", "alert", "approve"} {
		rule.Decision = action
		if err := h.engine.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
			t.Fatal(err)
		}
		for _, body := range []string{`{"operation":"transform_tool_output","text":"private-fixture","action":"approve"}`, `{"operation":"transform_tool_output","text":"private-fixture"} {}`, `{"operation":"transform_tool_output","text":"\ud800"}`, `{"operation":"transform_tool_output","text":""}` + strings.Repeat(" ", core.ToolOutputJSONBytes)} {
			req, _ := http.NewRequest("POST", h.url+path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer fixture-hook")
			res, err := h.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var reply map[string]any
			err = json.NewDecoder(res.Body).Decode(&reply)
			res.Body.Close()
			expected := map[string]any{"outcome": "unchanged"}
			if action == "redact" {
				expected = map[string]any{"outcome": "withheld", "text": "[REDACTED]"}
			}
			if err != nil || res.StatusCode != 200 || !reflect.DeepEqual(reply, expected) {
				t.Fatal("invalid input bypassed scoped failure policy")
			}
		}
	}
}

func TestToolOutputTransformAuditFailureHTTP(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.Register(core.Instance{ID: "audit-output", Agent: "claude", SessionID: "audit-output", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	review, err := h.engine.Submit(core.ReviewInput{InstanceID: "audit-output", CallID: "call", ToolName: "Read", Arguments: map[string]any{"file_path": "README.md"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.engine.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), core.Rule{ID: "U_OUTPUT", Name: "Output fixture", Matcher: "contains", Pattern: "private-fixture", Decision: "redact", Enabled: true, Categories: []string{core.SensitiveInfoCategory}}); err != nil {
		t.Fatal(err)
	}
	s := New(h.engine, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	handler := s.Handler()
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	// Reuse store_test.go's cross-store reject-audit trigger fixture.
	query := `CREATE TRIGGER reject_audit BEFORE INSERT ON records WHEN NEW.kind='audit' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;`
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") != "" {
		query = `CREATE FUNCTION reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$; CREATE TRIGGER reject_audit BEFORE INSERT ON records FOR EACH ROW WHEN (NEW.kind='audit') EXECUTE FUNCTION reject_audit();`
	}
	if _, err := teststore.Admin(t, h.engine.DB).Exec(query); err != nil {
		t.Fatal(err)
	}
	body := strings.NewReader(`{"operation":"transform_tool_output","text":"private-fixture"}`)
	req := httptest.NewRequest("POST", "http://127.0.0.1:18790/api/v1/reviews/"+review.ID+"/transform-tool-output", body)
	req.Header.Set("Authorization", "Bearer fixture-hook")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var reply map[string]string
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply["outcome"] != "rewritten" || reply["text"] != "[CUSTOM]" {
		t.Fatal("audit failure discarded replacement")
	}
	if !strings.Contains(logs.String(), "Tool output metadata audit unavailable") || strings.Contains(logs.String(), "private-fixture") {
		t.Fatal("audit failure log missing or exposed payload")
	}
}

func TestToolOutputTransformOwnership(t *testing.T) {
	h := newProtectionHTTP(t)
	ctx := core.WithActor(context.Background(), core.SystemActor("test"))
	ticket, err := h.engine.CreateEnrollment(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.engine.EnrollClient(ticket.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	ticket, err = h.engine.CreateEnrollment(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.engine.EnrollClient(ticket.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err = h.engine.Register(core.Instance{ID: "remote-output", NodeID: owner.NodeID, Platform: "linux", Agent: "claude", SessionID: "remote-output", Cwd: "/fixture", HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	review, err := h.engine.Submit(core.ReviewInput{InstanceID: "remote-output", CallID: "call", ToolName: "Read", Arguments: map[string]any{"file_path": "README.md"}})
	if err != nil {
		t.Fatal(err)
	}
	s := New(h.engine, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	handler := s.Handler()
	for _, tc := range []struct {
		id, token string
		status    int
	}{{review.ID, owner.Token, 200}, {review.ID, other.Token, 404}, {"missing", other.Token, 404}, {review.ID, "fixture-hook", 404}, {review.ID, "invalid", 403}} {
		req := httptest.NewRequest("POST", "http://127.0.0.1:18790/api/v1/reviews/"+tc.id+"/transform-tool-output", strings.NewReader(`{"operation":"transform_tool_output","text":""}`))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("ownership status=%d want=%d", w.Code, tc.status)
		}
		if tc.status == 404 && strings.TrimSpace(w.Body.String()) != `{"error":"Tool output review not found"}` {
			t.Fatal("existence leak in ownership failure")
		}
	}
}
