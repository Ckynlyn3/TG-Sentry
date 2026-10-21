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
	"net/url"
	"os"
	"slices"
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
	s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	server := httptest.NewServer(s.Handler())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(target, []*http.Cookie{rbacCookie(s, "human", core.RoleAdmin)})
	return &protectionHTTP{t: t, engine: e, client: client, url: server.URL, etag: `"0"`}
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

func TestProtectionDiscoveryRoundTrip(t *testing.T) {
	h := newProtectionHTTP(t)
	before := h.engine.Config().Version
	path := "/api/v1/discovery-policy"
	input := map[string]any{"enabled": true, "intervalSeconds": 1}
	review := h.call("POST", path+"/review", input, 200, "")
	if len(review["diff"].([]any)) == 0 || len(review["downgrades"].([]any)) != 0 {
		t.Fatal("unexpected discovery review", review)
	}
	if h.engine.Config().Version != before {
		t.Fatal("review advanced bundle revision")
	}
	result := h.call("PUT", path, map[string]any{"reviewId": review["id"]}, 200, "")
	if result["revision"] != float64(1) || h.engine.Config().Version != before+1 {
		t.Fatal("publication did not advance revisions", result)
	}
	discovery := result["discovery"].(map[string]any)
	if discovery["enabled"] != true || discovery["intervalSeconds"] != float64(1) {
		t.Fatal("wrong discovery state", discovery)
	}
	state, err := h.engine.Protection()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil || !bytes.Contains(data, []byte(`"discovery":{"enabled":true,"intervalSeconds":1}`)) {
		t.Fatal("discovery not persisted", err)
	}
	h.etag = `"0"`
	h.call("PUT", path, map[string]any{"reviewId": review["id"]}, 412, "")
}

func TestProtectionDiscoveryStrictInputs(t *testing.T) {
	h := newProtectionHTTP(t)
	path := "/api/v1/discovery-policy"
	before := h.engine.Config().Version
	for _, body := range []string{
		`{"enabled":true,"intervalSeconds":-1}`,
		`{"enabled":false,"intervalSeconds":-1}`,
		`{"enabled":true,"intervalSeconds":1.5}`,
		`{"enabled":true,"intervalSeconds":9223372036854775808}`,
		`{"enabled":true,"intervalSeconds":1,"unknown":true}`,
		`{"enabled":true,"intervalSeconds":1} {}`,
	} {
		req, err := http.NewRequest("POST", h.url+path+"/review", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("If-Match", h.etag)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("invalid discovery input status=%d", resp.StatusCode)
		}
	}
	h.call("PUT", path, map[string]any{"enabled": true, "intervalSeconds": 1}, 400, "")
	h.call("PUT", path, map[string]any{}, 409, "")
	if h.engine.Config().Version != before {
		t.Fatal("invalid inputs changed revision")
	}
}

func TestProtectionDiscoveryAdminOnly(t *testing.T) {
	s, _ := sessionServer(t)
	for _, route := range []string{"POST /api/v1/discovery-policy/review", "PUT /api/v1/discovery-policy"} {
		if routeRoles[route] != core.RoleAdmin {
			t.Errorf("missing explicit admin matrix entry: %s", route)
		}
		method, path, _ := strings.Cut(route, " ")
		for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor, core.RoleAdmin} {
			for _, kind := range []string{"human", "cli"} {
				w := rbacRequest(s.Handler(), rbacCookie(s, kind, role), method, "http://127.0.0.1"+path, "{", "127.0.0.1:12345")
				want := 403
				if kind == "human" && role == core.RoleAdmin {
					want = 400 // Admin reaches the strict decoder, not a fallback 404.
				}
				if w.Code != want {
					t.Errorf("%s %s %s: status=%d want=%d", kind, role, route, w.Code, want)
				}
			}
		}
		w := rbacRequest(s.Handler(), nil, method, "http://127.0.0.1"+path, "{", "127.0.0.1:12345")
		if w.Code != 401 {
			t.Errorf("unauthenticated %s: status=%d", route, w.Code)
		}
	}
}

func TestProtectionDiscoveryOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/design/protection.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for path, method := range map[string]string{"/api/v1/discovery-policy/review": "post", "/api/v1/discovery-policy": "put"} {
		raw, ok := spec.Paths[path][method]
		var op struct {
			Security    []map[string][]string `json:"security"`
			RequestBody struct {
				Content map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
		}
		if !ok || json.Unmarshal(raw, &op) != nil || len(op.Security) != 1 {
			t.Fatal("missing discovery operation/security", path)
		}
		if _, ok := op.Security[0]["adminSession"]; !ok {
			t.Fatal("discovery operation lacks admin session", path)
		}
		want := "#/components/schemas/DiscoveryPolicy"
		if method == "put" {
			want = "#/components/schemas/Confirm"
		}
		if op.RequestBody.Content["application/json"].Schema.Ref != want {
			t.Fatal("discovery request contract differs", path)
		}
	}
	bundle := spec.Components.Schemas["PolicyBundle"]
	for _, name := range bundle.Required {
		if name == "discovery" {
			t.Fatal("discovery must remain optional")
		}
	}
	if _, ok := bundle.Properties["discovery"]; !ok {
		t.Fatal("missing optional bundle discovery")
	}
	policy := spec.Components.Schemas["DiscoveryPolicy"]
	if len(policy.Properties) != 2 {
		t.Fatal("discovery schema field count differs")
	}
	var enabled struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(policy.Properties["enabled"], &enabled); err != nil || enabled.Type != "boolean" {
		t.Fatal("discovery enabled schema differs", err)
	}
	var resource struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(spec.Components.Schemas["Review"].Properties["resource"], &resource); err != nil || !slices.Contains(resource.Enum, "discovery") {
		t.Fatal("discovery review resource enum missing", err)
	}
	var interval struct {
		Type    string `json:"type"`
		Minimum *int   `json:"minimum"`
	}
	if err := json.Unmarshal(policy.Properties["intervalSeconds"], &interval); err != nil || interval.Type != "integer" || interval.Minimum == nil || *interval.Minimum != 0 {
		t.Fatal("discovery interval schema differs", err)
	}
}

func TestProtectionDiscoveryDefaultNoOp(t *testing.T) {
	h := newProtectionHTTP(t)
	version := h.engine.Config().Version
	for _, body := range []map[string]any{{}, {"enabled": false, "intervalSeconds": 0}} {
		h.call("POST", "/api/v1/discovery-policy/review", body, 400, "")
	}
	h.call("PUT", "/api/v1/discovery-policy", map[string]any{}, 409, "")
	state, err := h.engine.Protection()
	if err != nil || state.Revision != 0 || state.Discovery != nil || h.engine.Config().Version != version {
		t.Fatal("default discovery inputs changed absent protection", err)
	}
}

func TestProtectionDiscoveryRejectsNullWithoutDisabling(t *testing.T) {
	h := newProtectionHTTP(t)
	path := "/api/v1/discovery-policy"
	review := h.call("POST", path+"/review", map[string]any{"enabled": true, "intervalSeconds": 1}, 200, "")
	h.call("PUT", path, map[string]any{"reviewId": review["id"]}, 200, "")
	before, err := h.engine.Protection()
	if err != nil {
		t.Fatal(err)
	}
	version := h.engine.Config().Version
	for _, body := range []string{
		`null`,
		`{"enabled":null,"intervalSeconds":1}`,
		`{"enabled":true,"intervalSeconds":null}`,
		`{"enabled":null,"intervalSeconds":null}`,
		`{"Enabled":null,"intervalSeconds":1}`,
	} {
		result := h.call("POST", path+"/review", json.RawMessage(body), 400, "")
		if result["error"] != core.ErrProtectionInvalid.Error() {
			t.Fatal("null input did not use static protection error")
		}
	}
	after, err := h.engine.Protection()
	if err != nil || after.Discovery == nil || !after.Discovery.Enabled || after.Discovery.IntervalSeconds != 1 || after.Revision != before.Revision || h.engine.Config().Version != version {
		t.Fatal("null discovery input changed enabled settings", err)
	}
}
