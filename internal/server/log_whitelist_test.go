package server

import (
	"aegishook/internal/core"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func whitelistNode(t *testing.T, e *core.Engine) string {
	t.Helper()
	ctx := core.WithActor(context.Background(), core.SystemActor("test"))
	code, err := e.CreateEnrollment(ctx, "device", core.EnrollmentOptions{Type: "reusable"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	return conn.NodeID
}
func whitelistInput(node string) map[string]any {
	return map[string]any{"name": "Device recording", "description": "All protected agents on this device", "enabled": true, "subject": map[string]any{"kind": "agents", "agentIds": []string{node}}}
}
func TestLogWhitelistCRUDAndAudit(t *testing.T) {
	h := newProtectionHTTP(t)
	empty := h.call("GET", "/api/v1/log-whitelist", nil, 200, "")
	if empty["total"] != float64(0) || len(empty["items"].([]any)) != 0 {
		t.Fatal(empty)
	}
	node := whitelistNode(t, h.engine)
	created := h.publish("log-whitelist", "", whitelistInput(node))
	id := created["item"].(map[string]any)["id"].(string)
	h.call("GET", "/api/v1/log-whitelist/"+id, nil, 200, "")
	input := whitelistInput(node)
	input["enabled"] = false
	h.publish("log-whitelist", id, input)
	h.publish("log-whitelist", id, map[string]any{"delete": true})
	h.call("GET", "/api/v1/log-whitelist/"+id, nil, 404, "")
	empty = h.call("GET", "/api/v1/log-whitelist", nil, 200, "")
	if empty["total"] != float64(0) || len(empty["items"].([]any)) != 0 {
		t.Fatal(empty)
	}
	audits, err := h.engine.Audits()
	if err != nil {
		t.Fatal(err)
	}
	publications := 0
	for _, a := range audits {
		if a.Action == "protection.log-whitelist.publish" {
			publications++
			if a.Actor.Kind != "human" || a.Actor.Subject != "fixture-subject" || !strings.Contains(a.Detail, "resource="+id) || !strings.Contains(a.Detail, "review=") || !strings.Contains(a.Detail, "base=") {
				t.Fatal("lost admin attribution", a)
			}
		}
	}
	if publications != 3 {
		t.Fatalf("publication audits=%d want=3", publications)
	}
}
func TestLogWhitelistReviewPreconditionsAndBinding(t *testing.T) {
	h := newProtectionHTTP(t)
	node := whitelistNode(t, h.engine)
	h.call("GET", "/api/v1/log-whitelist", nil, 200, "")
	created := h.publish("log-whitelist", "", whitelistInput(node))
	id := created["item"].(map[string]any)["id"].(string)
	base := h.etag
	draft := h.call("POST", "/api/v1/log-whitelist/review", whitelistInput(node), 200, "")
	if h.etag != base || draft["resource"] != "log-whitelist" || draft["warning"] == "" || len(draft["downgrades"].([]any)) == 0 {
		t.Fatal(draft)
	}
	confirm := map[string]any{"reviewId": draft["id"], "confirmDowngrade": true}
	h.call("POST", "/api/v1/log-whitelist", map[string]any{"reviewId": draft["id"]}, 409, "")
	h.call("PUT", "/api/v1/log-whitelist/"+id, confirm, 409, "")
	h.call("POST", "/api/v1/templates", confirm, 409, "")
	h.call("POST", "/api/v1/log-whitelist", confirm, 200, "")
	current := h.etag
	if current == base {
		t.Fatal("publication did not advance ETag")
	}
	h.etag = base
	h.call("POST", "/api/v1/log-whitelist", confirm, 412, "")
	h.call("POST", "/api/v1/log-whitelist/review", whitelistInput(node), 412, "")
	h.etag = current
	h.call("POST", "/api/v1/log-whitelist", confirm, 412, "") // Current ETag cannot rescue a stale review.
	h.call("POST", "/api/v1/log-whitelist", map[string]any{}, 409, "")
	h.call("POST", "/api/v1/log-whitelist", map[string]any{"reviewId": "missing"}, 404, "")
	h.call("POST", "/api/v1/log-whitelist/missing/review", whitelistInput(node), 404, "")
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		path := "/api/v1/log-whitelist"
		if method != "POST" {
			path += "/" + id
		}
		h.etag = ""
		h.call(method, path, confirm, 428, "")
	}
	for _, tag := range []string{"", "*", `W/` + current} {
		want := 412
		if tag == "" {
			want = 428
		}
		if tag == "*" {
			want = 400
		}
		h.etag = tag
		h.call("POST", "/api/v1/log-whitelist/review", whitelistInput(node), want, "")
	}
}

func TestLogWhitelistStrictInputsAndPagination(t *testing.T) {
	h := newProtectionHTTP(t)
	node := whitelistNode(t, h.engine)
	h.call("GET", "/api/v1/log-whitelist", nil, 200, "")
	for _, field := range []string{"unknown", "id", "updatedAt", "rules"} {
		in := whitelistInput(node)
		in[field] = "not accepted"
		h.call("POST", "/api/v1/log-whitelist/review", in, 400, "")
	}
	for _, field := range []string{"unknown", "tags", "principals"} {
		in := whitelistInput(node)
		in["subject"].(map[string]any)[field] = []string{"forged"}
		h.call("POST", "/api/v1/log-whitelist/review", in, 400, "")
	}
	for _, in := range []map[string]any{{}, {"delete": true}, {"name": "bad", "effect": "approve"}, {"name": "bad", "subject": map[string]any{"kind": "users", "agentIds": []string{node}}}} {
		h.call("POST", "/api/v1/log-whitelist/review", in, 400, "")
	}
	for _, route := range []string{"POST /api/v1/log-whitelist/review", "POST /api/v1/log-whitelist/whitelist-fixture/review", "POST /api/v1/log-whitelist", "PUT /api/v1/log-whitelist/whitelist-fixture", "DELETE /api/v1/log-whitelist/whitelist-fixture"} {
		method, path, _ := strings.Cut(route, " ")
		input := map[string]any{"reviewId": "missing"}
		if strings.HasSuffix(path, "/review") {
			input = whitelistInput(node)
		}
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		// protection.go uses the existing 2 MiB ceiling; valid JSON plus
		// leading whitespace must hit that ceiling, not a syntax/field error.
		oversized := strings.Repeat(" ", core.PolicyBundleMaxBytes) + string(data)
		for _, body := range []string{`{"unknown":true}`, `{} {}`, `{`, oversized} {
			req, _ := http.NewRequest(method, h.url+path, strings.NewReader(body))
			req.Header.Set("If-Match", h.etag)
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Fatalf("%s strict decoding: %d", route, resp.StatusCode)
			}
		}
	}
	for _, query := range []string{"?page=0", "?page=bad", "?pageSize=101", "?pageSize=0"} {
		h.call("GET", "/api/v1/log-whitelist"+query, nil, 400, "")
	}
	page := h.call("GET", "/api/v1/log-whitelist?page=2&pageSize=1", nil, 200, "")
	if page["total"] != float64(0) || page["page"] != float64(2) || page["pageSize"] != float64(1) || len(page["items"].([]any)) != 0 {
		t.Fatal(page)
	}
}

func TestLogWhitelistRBACRoutes(t *testing.T) {
	routes := map[string]core.Role{"GET /api/v1/log-whitelist": core.RoleReadOnly, "GET /api/v1/log-whitelist/{id}": core.RoleReadOnly, "POST /api/v1/log-whitelist/review": core.RoleAdmin, "POST /api/v1/log-whitelist/{id}/review": core.RoleAdmin, "POST /api/v1/log-whitelist": core.RoleAdmin, "PUT /api/v1/log-whitelist/{id}": core.RoleAdmin, "DELETE /api/v1/log-whitelist/{id}": core.RoleAdmin}
	h := newProtectionHTTP(t)
	node := whitelistNode(t, h.engine)
	created := h.publish("log-whitelist", "", whitelistInput(node))
	id := created["item"].(map[string]any)["id"].(string)
	s, _ := sessionServer(t)
	s.Engine = h.engine
	handler := s.Handler()
	for route, required := range routes {
		if got, ok := routeRoles[route]; !ok || got != required {
			t.Errorf("%s matrix=%s want=%s", route, got, required)
		}
		method, path, _ := strings.Cut(route, " ")
		path = strings.ReplaceAll(path, "{id}", id)
		for _, kind := range []string{"human", "cli", "unauthenticated", "hook"} {
			for _, role := range []core.Role{core.RoleAdmin, core.RoleAuditor, core.RoleReadOnly} {
				var cookie *http.Cookie
				if kind == "human" || kind == "cli" {
					cookie = rbacCookie(s, kind, role)
				}
				req := httptest.NewRequest(method, "http://127.0.0.1"+path, strings.NewReader("{"))
				req.RemoteAddr = "127.0.0.1:12345"
				if cookie != nil {
					req.AddCookie(cookie)
				}
				if kind == "hook" {
					req.Header.Set("Authorization", "Bearer test-hook")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				allowed := kind == "human" && (role == core.RoleAdmin || required == core.RoleReadOnly || role == core.RoleAuditor && required == core.RoleAuditor)
				want := 403
				if kind == "unauthenticated" {
					want = 401
				}
				if allowed {
					want = 400
					if method == "GET" {
						want = 200
					}
				}
				if w.Code != want {
					t.Errorf("%s %s/%s: got %d want %d %s", route, kind, role, w.Code, want, w.Body.String())
				}
			}
		}
	}
}

// As in the bundle/trust contract tests, this detects wire-field and operation
// drift; it does not claim to run a full OpenAPI schema validator.
func TestLogWhitelistOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/design/protection.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err = json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"LogWhitelistEntry": core.LogWhitelistEntry{}, "LogWhitelistSubject": core.LogWhitelistSubject{}} {
		fields := spec.Components.Schemas[name].Properties
		typ := reflect.TypeOf(value)
		if len(fields) != typ.NumField() {
			t.Fatalf("%s field count differs", name)
		}
		for n := range typ.NumField() {
			field := strings.Split(typ.Field(n).Tag.Get("json"), ",")[0]
			if _, ok := fields[field]; !ok {
				t.Fatal(name, field)
			}
		}
	}
	for path, methods := range map[string][]string{"/api/v1/log-whitelist": {"get", "post"}, "/api/v1/log-whitelist/{id}": {"get", "put", "delete"}, "/api/v1/log-whitelist/review": {"post"}, "/api/v1/log-whitelist/{id}/review": {"post"}} {
		for _, method := range methods {
			var op struct {
				Security   []map[string][]string `json:"security"`
				Parameters []struct {
					Name     string `json:"name"`
					Required bool   `json:"required"`
				} `json:"parameters"`
				RequestBody struct {
					Content map[string]struct {
						Schema struct {
							Ref string `json:"$ref"`
						} `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
				Responses map[string]struct {
					Headers map[string]json.RawMessage `json:"headers"`
					Content map[string]struct {
						Schema struct {
							Properties map[string]json.RawMessage `json:"properties"`
							Required   []string                   `json:"required"`
						} `json:"schema"`
					} `json:"content"`
				} `json:"responses"`
			}
			if err = json.Unmarshal(spec.Paths[path][method], &op); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			if len(op.Security) != 1 {
				t.Fatal("missing session security", path)
			}
			if _, ok := op.Security[0]["adminSession"]; !ok {
				t.Fatal("wrong security", path)
			}
			if _, ok := op.Responses["200"].Headers["ETag"]; !ok {
				t.Fatal("missing ETag", path)
			}
			for _, code := range []string{"400", "401", "403", "404", "409", "412", "428", "500"} {
				if _, ok := op.Responses[code]; !ok {
					t.Fatal(path, code)
				}
			}
			if method == "get" {
				schema := op.Responses["200"].Content["application/json"].Schema
				if slices.Contains(schema.Required, "virtualDefault") {
					t.Fatal("whitelist must not have virtual default", path)
				}
			} else {
				match := false
				for _, p := range op.Parameters {
					match = match || p.Name == "If-Match" && p.Required
				}
				if !match {
					t.Fatal("missing precondition", path)
				}
				ref := "#/components/schemas/Confirm"
				if strings.HasSuffix(path, "/review") {
					ref = "#/components/schemas/LogWhitelistInput"
				}
				if op.RequestBody.Content["application/json"].Schema.Ref != ref {
					t.Fatal("wrong input", path)
				}
			}
		}
	}
	var resource struct {
		Enum []string `json:"enum"`
	}
	json.Unmarshal(spec.Components.Schemas["Review"].Properties["resource"], &resource)
	if !slices.Contains(resource.Enum, "log-whitelist") {
		t.Fatal("review resource omits log-whitelist")
	}
}

func TestLogWhitelistNodeValidationAndRevocation(t *testing.T) {
	h := newProtectionHTTP(t)
	node := whitelistNode(t, h.engine)
	h.call("POST", "/api/v1/log-whitelist/review", whitelistInput("missing"), 404, "")
	for _, subject := range []map[string]any{
		{"kind": "all"}, {"kind": "tags", "agentIds": []string{node}}, {"kind": "agents"},
		{"kind": "agents", "agentIds": []string{node, node}},
	} {
		input := whitelistInput(node)
		input["subject"] = subject
		h.call("POST", "/api/v1/log-whitelist/review", input, 400, "")
	}
	review := h.call("POST", "/api/v1/log-whitelist/review", whitelistInput(node), 200, "")
	if err := h.engine.RevokeClient(core.WithActor(context.Background(), core.SystemActor("test")), node); err != nil {
		t.Fatal(err)
	}
	h.call("POST", "/api/v1/log-whitelist", map[string]any{"reviewId": review["id"], "confirmDowngrade": true}, 400, "")
	h.call("POST", "/api/v1/log-whitelist/review", whitelistInput(node), 400, "")
	empty := h.call("GET", "/api/v1/log-whitelist", nil, 200, "")
	if empty["revision"] != float64(0) || empty["total"] != float64(0) {
		t.Fatal("invalid publication changed resource", empty)
	}
}

func TestLogWhitelistRejectsEnrolledDeviceCredentials(t *testing.T) {
	h := newProtectionHTTP(t)
	code, err := h.engine.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "device", core.EnrollmentOptions{Type: "reusable"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := h.engine.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"GET /api/v1/log-whitelist", "GET /api/v1/log-whitelist/missing", "POST /api/v1/log-whitelist/review", "POST /api/v1/log-whitelist/missing/review", "POST /api/v1/log-whitelist", "PUT /api/v1/log-whitelist/missing", "DELETE /api/v1/log-whitelist/missing"} {
		method, path, _ := strings.Cut(route, " ")
		h.call(method, path, whitelistInput(conn.NodeID), 403, conn.Token)
	}
}

func TestLogWhitelistStoreUnavailable(t *testing.T) {
	h := newProtectionHTTP(t)
	if err := h.engine.DB.Close(); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "POST"} {
		path := "/api/v1/log-whitelist"
		body := any(map[string]any{"reviewId": "missing"})
		if method == "GET" {
			body = nil
		}
		result := h.call(method, path, body, 500, "")
		if result["error"] != "protection store unavailable" {
			t.Fatal("store details leaked", result)
		}
	}
}
