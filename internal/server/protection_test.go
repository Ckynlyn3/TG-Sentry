package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

type protectionHTTP struct {
	t         *testing.T
	engine    *core.Engine
	client    *http.Client
	url, etag string
}

func newProtectionHTTP(t *testing.T) *protectionHTTP {
	t.Helper()
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	server := httptest.NewServer(New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir()).Handler())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	h := &protectionHTTP{t: t, engine: e, client: client, url: server.URL, etag: `"0"`}
	h.call("POST", "/api/v1/login", map[string]any{"token": "fixture-admin"}, 200, "")
	return h
}
func (h *protectionHTTP) call(method, path string, body any, want int, token string) map[string]any {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.url+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", h.etag)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	if resp.StatusCode != want {
		h.t.Fatalf("%s %s status=%d want=%d body=%s", method, path, resp.StatusCode, want, b)
	}
	out := map[string]any{}
	if err = json.Unmarshal(b, &out); err != nil {
		h.t.Fatalf("non-JSON response %s: %s", path, b)
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		h.etag = etag
	}
	return out
}
func (h *protectionHTTP) publish(kind, id string, value map[string]any) map[string]any {
	h.t.Helper()
	base := "/api/v1/" + kind
	reviewPath := base + "/review"
	method := "POST"
	target := base
	if id != "" {
		reviewPath = base + "/" + id + "/review"
		method = "PUT"
		target = base + "/" + id
	}
	if value["delete"] == true {
		method = "DELETE"
	}
	r := h.call("POST", reviewPath, value, 200, "")
	return h.call(method, target, map[string]any{"reviewId": r["id"], "confirmDowngrade": true}, 200, "")
}
func templateInput(action string) map[string]any {
	return map[string]any{"name": "tag protection", "rules": []any{map[string]any{"ruleId": "U_TAG", "category": "category::sensitive-info", "action": action}}}
}
func installProtectionRule(t *testing.T, e *core.Engine) {
	t.Helper()
	if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), core.Rule{ID: "U_TAG", Name: "tag source", ScopeOnly: true, Enabled: true, Decision: "reject", Matcher: "contains", Pattern: "tag-secret"}); err != nil {
		t.Fatal(err)
	}
}
func TestProtectionServerTagEnforcementAndStaleRevision(t *testing.T) {
	h := newProtectionHTTP(t)
	installProtectionRule(t, h.engine)
	code, err := h.engine.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "fixture", core.EnrollmentOptions{Type: "reusable"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := h.engine.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.engine.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	created := h.publish("templates", "", templateInput("block"))
	id := created["item"].(map[string]any)["id"].(string)
	tagPath := "/api/v1/client-nodes/" + a.NodeID + "/tags"
	review := h.call("POST", tagPath+"/review", map[string]any{"tags": []string{"engineering"}}, 200, "")
	h.call("PUT", tagPath, map[string]any{"reviewId": review["id"]}, 200, "")
	h.publish("policies", "", map[string]any{"name": "engineering", "templateIds": []string{id}, "scope": map[string]any{"type": "tags", "tags": []string{"engineering"}}})
	for _, tc := range []struct {
		conn core.ClientConnection
		want string
	}{{a, "reject"}, {b, "approve"}} {
		h.call("POST", "/api/v1/instances", map[string]any{"id": tc.conn.NodeID, "nodeId": tc.conn.NodeID, "agent": "claude", "sessionId": tc.conn.NodeID, "cwd": "/project", "hookVersion": core.Version}, 200, tc.conn.Token)
		got := h.call("POST", "/api/v1/reviews", map[string]any{"instanceId": tc.conn.NodeID, "callId": core.ID(), "toolName": "Read", "argumentsObj": map[string]any{"file_path": "tag-secret"}}, 200, tc.conn.Token)
		if got["decision"] != tc.want {
			t.Fatalf("tag enforcement decision=%v want=%s", got["decision"], tc.want)
		}
		h.call("PUT", tagPath, map[string]any{"tags": []string{"escape"}}, 403, tc.conn.Token)
	}
	stale := h.etag
	draft := h.call("POST", "/api/v1/templates/"+id+"/review", templateInput("alert"), 200, "")
	if draft["warning"] == "" || len(draft["downgrades"].([]any)) == 0 {
		t.Fatal("missing downgrade warning")
	}
	if len(draft["affectedAgentIds"].([]any)) != 1 || len(draft["affectedPolicyIds"].([]any)) != 1 {
		t.Fatalf("wrong impact: %+v", draft)
	}
	h.call("PUT", "/api/v1/templates/"+id, map[string]any{"reviewId": draft["id"]}, 409, "")
	h.call("PUT", "/api/v1/templates/"+id, map[string]any{"reviewId": draft["id"], "confirmDowngrade": true}, 200, "")
	h.etag = stale
	h.call("PUT", "/api/v1/templates/"+id, map[string]any{"reviewId": draft["id"], "confirmDowngrade": true}, 412, "")
	h.call("POST", "/api/v1/templates/"+id+"/review", templateInput("block"), 412, "")
}
func TestProtectionCRUDAndAdminBoundary(t *testing.T) {
	h := newProtectionHTTP(t)
	installProtectionRule(t, h.engine)
	h.call("GET", "/api/v1/templates", nil, 200, "")
	h.call("GET", "/api/v1/policies", nil, 200, "")
	for _, kind := range []string{"templates", "policies"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			path := "/api/v1/" + kind
			if method == "PUT" || method == "DELETE" {
				path += "/id"
			}
			h.call(method, path, nil, 403, "fixture-hook")
		}
		h.call("POST", "/api/v1/"+kind+"/review", map[string]any{}, 403, "fixture-hook")
		h.call("GET", "/api/v1/"+kind+"/missing", nil, 404, "")
	}
	h.call("POST", "/api/v1/templates", map[string]any{}, 409, "")
	created := h.publish("templates", "", templateInput("block"))
	id := created["item"].(map[string]any)["id"].(string)
	h.call("GET", "/api/v1/templates/"+id, nil, 200, "")
	p := h.publish("policies", "", map[string]any{"name": "all", "templateIds": []string{id}, "scope": map[string]any{"type": "all"}})
	pid := p["item"].(map[string]any)["id"].(string)
	h.call("GET", "/api/v1/policies/"+pid, nil, 200, "")
	h.publish("policies", pid, map[string]any{"name": "renamed", "templateIds": []string{id}, "scope": map[string]any{"type": "all"}})
	h.call("POST", "/api/v1/templates/"+id+"/review", map[string]any{"delete": true}, 409, "")
	h.publish("policies", pid, map[string]any{"delete": true})
	h.publish("templates", id, map[string]any{"delete": true})
	h.call("GET", "/api/v1/templates/"+id, nil, 404, "")
	h.call("GET", "/api/v1/policies/"+pid, nil, 404, "")
	for _, path := range []string{"/api/v1/templates?pageSize=101", "/api/v1/templates?page=0", "/api/v1/policies?pageSize=bad"} {
		h.call("GET", path, nil, 400, "")
	}
	h.etag = ""
	h.call("POST", "/api/v1/templates/review", templateInput("block"), 428, "")
	h.etag = "*"
	h.call("POST", "/api/v1/templates/review", templateInput("block"), 400, "")
	h.etag = `W/"4"`
	h.call("POST", "/api/v1/templates/review", templateInput("block"), 412, "")
	h.etag = `"4"`
	h.call("POST", "/api/v1/templates/review", map[string]any{"unknown": "field"}, 400, "")
	h.call("GET", "/api/v1/client-nodes/missing/tags", nil, 404, "")
	// An authenticated session remains required even for reads.
	req, _ := http.NewRequest("GET", h.url+"/api/v1/templates", nil)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
}
func TestProtectionInvalidInputs(t *testing.T) {
	h := newProtectionHTTP(t)
	installProtectionRule(t, h.engine)
	for _, input := range []map[string]any{{"name": "", "rules": []any{}}, {"name": "bad", "rules": []any{map[string]any{"ruleId": "U_TAG", "category": "invalid", "action": "block"}}}, {"name": "bad", "rules": []any{map[string]any{"ruleId": "U_TAG", "category": "category::behavior", "action": "allow"}}}} {
		h.call("POST", "/api/v1/templates/review", input, 400, "")
	}
	for _, body := range []string{`{"name":"bad"} {}`, `{"name":`, strings.Repeat("x", 2<<20+1)} {
		req, _ := http.NewRequest("POST", h.url+"/api/v1/templates/review", strings.NewReader(body))
		req.Header.Set("If-Match", h.etag)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatal(fmt.Sprint(resp.StatusCode))
		}
	}
}
