package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// Exercise the existing hook HTTP contract, not a separate decision endpoint.
func TestRuntimeDevicePolicyBinding(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := New(e, fstest.MapFS{}, "admin-fixture", "local-fixture", t.TempDir())
	h := s.Handler()
	request := func(method, path, token string, body any) *httptest.ResponseRecorder {
		t.Helper()
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "http://127.0.0.1:18790/api/v1"+path, strings.NewReader(string(b)))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	enroll := func(name string) core.ClientConnection {
		t.Helper()
		code, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), name)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := e.EnrollClient(code.Code, "linux")
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	a, b := enroll("A"), enroll("B")
	var bound core.Rule
	if err := json.Unmarshal([]byte(`{"id":"U_BOUND","name":"bound protected read","scopeOnly":true,"enabled":true,"decision":"reject","target":"arguments","field":"file_path","matcher":"contains","pattern":"protected.txt"}`), &bound); err != nil {
		t.Fatal(err)
	}
	if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), bound); err != nil {
		t.Fatal(err)
	}
	var scope core.Scope
	raw := `{"id":"policy-A","name":"A policy","nodeId":"` + a.NodeID + `","platform":"linux","project":"/remote/project","ruleIds":["U_BOUND"]}`
	if err := json.Unmarshal([]byte(raw), &scope); err != nil {
		t.Fatal(err)
	}
	if err := e.SaveScope(core.WithActor(context.Background(), core.SystemActor("test")), scope); err != nil {
		t.Fatal(err)
	}
	register := func(id string, conn core.ClientConnection) core.Instance {
		t.Helper()
		in := core.Instance{ID: id, NodeID: conn.NodeID, Agent: "claude", SessionID: id, Cwd: "/different/project", HookVersion: core.Version}
		if w := request("POST", "/instances", conn.Token, in); w.Code != 200 {
			t.Fatalf("register %s: %d %s", id, w.Code, w.Body.String())
		}
		return in
	}
	ia, ib := register("A", a), register("B", b)
	review := func(instance, tool string, args map[string]any) core.ReviewInput {
		return core.ReviewInput{InstanceID: instance, CallID: core.ID(), ToolName: tool, Arguments: args}
	}
	for _, tc := range []struct{ name, id, token, tool, key, value, decision, rule string }{
		{"bound deny", ia.ID, a.Token, "Read", "file_path", "protected.txt", "reject", "U_BOUND"},
		{"other node allowed", ib.ID, b.Token, "Read", "file_path", "protected.txt", "approve", "A7"},
		{"benign allowed", ia.ID, a.Token, "Read", "file_path", "README.md", "approve", "A7"},
		{"global deny A", ia.ID, a.Token, "Bash", "command", "redis-cli FLUSHALL", "reject", "R_DB_REDIS"},
		{"global deny B", ib.ID, b.Token, "Bash", "command", "redis-cli FLUSHALL", "reject", "R_DB_REDIS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request("POST", "/reviews", tc.token, review(tc.id, tc.tool, map[string]any{tc.key: tc.value}))
			var got core.Review
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 || got.Decision != tc.decision {
				t.Fatalf("status=%d response=%s err=%v", w.Code, w.Body.String(), err)
			}
			if got.RuleID != tc.rule {
				t.Fatalf("wrong rule %s, want %s", got.RuleID, tc.rule)
			}
		})
	}
	in := review(ia.ID, "Read", map[string]any{"file_path": "README.md"})
	for _, token := range []string{"", "invalid", b.Token, "local-fixture"} {
		if w := request("POST", "/reviews", token, in); w.Code != 401 && w.Code != 403 {
			t.Fatalf("forged/unauthenticated review accepted: %d", w.Code)
		}
	}
	forged := ia
	forged.ID = "forged"
	if w := request("POST", "/instances", b.Token, forged); w.Code != 403 {
		t.Fatalf("forged node: %d", w.Code)
	}
	forged.NodeID = b.NodeID
	forged.ID = ia.ID
	if w := request("POST", "/instances", b.Token, forged); w.Code != 400 {
		t.Fatalf("instance takeover: %d", w.Code)
	}
	for _, path := range []string{"heartbeat", "shutdown"} {
		if w := request("POST", "/instances/"+ia.ID+"/"+path, b.Token, map[string]any{}); w.Code != 403 {
			t.Fatalf("cross-device %s: %d", path, w.Code)
		}
	}
	w := request("POST", "/reviews", a.Token, in)
	var saved core.Review
	if json.Unmarshal(w.Body.Bytes(), &saved) != nil || w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request("GET", "/reviews/"+saved.ID, b.Token, nil); w.Code != 403 {
		t.Fatalf("cross-device get: %d", w.Code)
	}
	if w := request("POST", "/reviews/"+saved.ID+"/result", b.Token, map[string]any{"instanceId": ia.ID, "state": "succeeded"}); w.Code != 403 {
		t.Fatalf("cross-device result: %d", w.Code)
	}
	if err := e.RevokeClient(core.WithActor(context.Background(), core.SystemActor("test")), a.NodeID); err != nil {
		t.Fatal(err)
	}
	if w := request("POST", "/reviews", a.Token, in); w.Code != 403 {
		t.Fatalf("revoked decision accepted: %d", w.Code)
	}
}
