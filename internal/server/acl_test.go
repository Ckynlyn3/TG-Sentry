package server

import (
	"aegishook/internal/core"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func aclInput(effect string) map[string]any {
	return map[string]any{"name": "Tool access", "description": "Exact hook names", "enabled": true, "subject": map[string]any{"kind": "all"}, "effect": effect, "target": map[string]any{"kind": "tools", "tools": []string{"Read"}}}
}

func TestACLVirtualDefaultCRUDAndAudit(t *testing.T) {
	h := newProtectionHTTP(t)
	got := h.call("GET", "/api/v1/acl", nil, 200, "")
	if got["virtualDefault"] != true || got["total"] != float64(1) {
		t.Fatalf("virtual default: %v", got)
	}
	item := got["items"].([]any)[0].(map[string]any)
	id := item["id"].(string)
	if id != "acl-default-all-pass" || item["effect"] != "allow" || item["enabled"] != true {
		t.Fatalf("default: %v", item)
	}
	detail := h.call("GET", "/api/v1/acl/"+id, nil, 200, "")
	if detail["virtualDefault"] != true {
		t.Fatal(detail)
	}
	state, err := h.engine.Protection()
	if err != nil || state.ACL.Initialized {
		t.Fatalf("GET initialized state: %v %v", state, err)
	}
	updated := h.publish("acl", id, aclInput("deny"))
	if updated["virtualDefault"] != false || updated["item"].(map[string]any)["effect"] != "deny" {
		t.Fatal(updated)
	}
	created := h.publish("acl", "", aclInput("deny"))
	other := created["item"].(map[string]any)["id"].(string)
	h.call("GET", "/api/v1/acl/"+other, nil, 200, "")
	h.publish("acl", other, map[string]any{"delete": true})
	h.call("GET", "/api/v1/acl/"+other, nil, 404, "")
	h.publish("acl", id, map[string]any{"delete": true})
	empty := h.call("GET", "/api/v1/acl", nil, 200, "")
	if empty["virtualDefault"] != false || empty["total"] != float64(0) || len(empty["items"].([]any)) != 0 {
		t.Fatal(empty)
	}
	resp, err := h.client.Get(h.url + "/api/v1/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var audit []core.Audit
	if err := json.NewDecoder(resp.Body).Decode(&audit); err != nil || resp.StatusCode != 200 {
		t.Fatalf("audit response: %d %v", resp.StatusCode, err)
	}
	publications := 0
	for _, entry := range audit {
		if entry.Action == "protection.acl.publish" {
			publications++
			if entry.Actor.Kind != "human" || entry.Actor.Subject != "fixture-subject" || !strings.Contains(entry.Detail, "review=") {
				t.Fatalf("publication attribution: %+v", entry)
			}
		}
	}
	if publications != 4 { // Update, create, and two deletes above.
		t.Fatalf("publication audit count=%d want=4", publications)
	}
}

func TestACLReviewPreconditionsAndBinding(t *testing.T) {
	h := newProtectionHTTP(t)
	h.call("GET", "/api/v1/acl", nil, 200, "")
	base := h.etag
	draft := h.call("POST", "/api/v1/acl/review", aclInput("allow"), 200, "")
	if h.etag != base || draft["resource"] != "acl" || draft["warning"] == "" || len(draft["downgrades"].([]any)) == 0 {
		t.Fatal(draft)
	}
	confirm := map[string]any{"reviewId": draft["id"], "confirmDowngrade": true}
	h.call("POST", "/api/v1/acl", map[string]any{"reviewId": draft["id"]}, 409, "")
	h.call("PUT", "/api/v1/acl/acl-default-all-pass", confirm, 409, "")
	h.call("POST", "/api/v1/templates", confirm, 409, "")
	h.call("POST", "/api/v1/acl", confirm, 200, "")
	current := h.etag
	if current == base {
		t.Fatal("publication did not advance ETag")
	}
	h.etag = base
	h.call("POST", "/api/v1/acl", confirm, 412, "")
	h.call("POST", "/api/v1/acl/review", aclInput("deny"), 412, "")
	h.etag = current
	h.call("POST", "/api/v1/acl", confirm, 412, "") // Current ETag cannot rescue a stale review.
	h.call("POST", "/api/v1/acl", map[string]any{}, 409, "")
	h.call("POST", "/api/v1/acl", map[string]any{"reviewId": "missing"}, 404, "")
	h.call("POST", "/api/v1/acl/missing/review", aclInput("deny"), 404, "")
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		path := "/api/v1/acl"
		if method != "POST" {
			path += "/acl-default-all-pass"
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
		h.call("POST", "/api/v1/acl/review", aclInput("deny"), want, "")
	}
}

func TestACLStrictInputsAndPagination(t *testing.T) {
	h := newProtectionHTTP(t)
	h.call("GET", "/api/v1/acl", nil, 200, "")
	for _, field := range []string{"unknown", "id", "updatedAt", "rules"} {
		in := aclInput("deny")
		in[field] = "not accepted"
		h.call("POST", "/api/v1/acl/review", in, 400, "")
	}
	for _, field := range []string{"subject", "target"} {
		in := aclInput("deny")
		in[field].(map[string]any)["unknown"] = true
		h.call("POST", "/api/v1/acl/review", in, 400, "")
	}
	for _, in := range []map[string]any{{}, {"delete": true}, {"name": "bad", "effect": "approve"}, {"name": "bad", "effect": "deny", "subject": map[string]any{"kind": "users"}, "target": map[string]any{"kind": "all"}}} {
		h.call("POST", "/api/v1/acl/review", in, 400, "")
	}
	for _, route := range []string{"POST /api/v1/acl/review", "POST /api/v1/acl/acl-default-all-pass/review", "POST /api/v1/acl", "PUT /api/v1/acl/acl-default-all-pass", "DELETE /api/v1/acl/acl-default-all-pass"} {
		method, path, _ := strings.Cut(route, " ")
		input := map[string]any{"reviewId": "missing"}
		if strings.HasSuffix(path, "/review") {
			input = aclInput("deny")
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
		h.call("GET", "/api/v1/acl"+query, nil, 400, "")
	}
	page := h.call("GET", "/api/v1/acl?page=2&pageSize=1", nil, 200, "")
	if page["total"] != float64(1) || page["page"] != float64(2) || page["pageSize"] != float64(1) || len(page["items"].([]any)) != 0 {
		t.Fatal(page)
	}
	h.call("GET", "/api/v1/calls?reviewPath=acl", nil, 200, "")
}

func TestACLRBACRoutes(t *testing.T) {
	routes := map[string]core.Role{"GET /api/v1/acl": core.RoleReadOnly, "GET /api/v1/acl/{id}": core.RoleReadOnly, "POST /api/v1/acl/review": core.RoleAuditor, "POST /api/v1/acl/{id}/review": core.RoleAuditor, "POST /api/v1/acl": core.RoleAdmin, "PUT /api/v1/acl/{id}": core.RoleAdmin, "DELETE /api/v1/acl/{id}": core.RoleAdmin}
	h := newProtectionHTTP(t)
	s, _ := sessionServer(t)
	s.Engine = h.engine
	handler := s.Handler()
	for route, required := range routes {
		if got, ok := routeRoles[route]; !ok || got != required {
			t.Errorf("%s matrix=%s want=%s", route, got, required)
		}
		method, path, _ := strings.Cut(route, " ")
		path = strings.ReplaceAll(path, "{id}", "acl-default-all-pass")
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
func TestACLOpenAPIContract(t *testing.T) {
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
	for name, value := range map[string]any{"ACLRule": core.ACLRule{}, "ACLSubject": core.ACLSubject{}, "ACLTarget": core.ACLTarget{}} {
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
	for path, methods := range map[string][]string{"/api/v1/acl": {"get", "post"}, "/api/v1/acl/{id}": {"get", "put", "delete"}, "/api/v1/acl/review": {"post"}, "/api/v1/acl/{id}/review": {"post"}} {
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
				if !slices.Contains(schema.Required, "virtualDefault") {
					t.Fatal("virtual default missing", path)
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
					ref = "#/components/schemas/ACLInput"
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
	if !slices.Contains(resource.Enum, "acl") {
		t.Fatal("review resource omits acl")
	}
}
