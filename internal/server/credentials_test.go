package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestCredentialHTTPDeliveryBudget(t *testing.T) {
	t.Setenv("TG_SENTRY_CREDENTIALS_KEK_FILE", "")
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := New(e, fstest.MapFS{}, "admin", "legacy", t.TempDir())
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(string(encoded)))
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	frame, _ := json.Marshal(core.ResolvedCredential{ID: core.ID(), Env: "FIXTURE_KEY"})
	value := strings.Repeat("x", core.SecretResolveLimit-len(frame)-len("\n"))
	for _, extra := range []string{"", "x"} {
		w := call("POST", "/api/v1/credentials", map[string]any{"name": "budget", "type": "api_key", "env": "FIXTURE_KEY", "value": value + extra})
		want := http.StatusCreated
		if extra != "" {
			want = http.StatusBadRequest
		}
		if w.Code != want {
			t.Fatalf("create boundary extra=%d status=%d want=%d", len(extra), w.Code, want)
		}
	}
	items, err := e.Credentials()
	if err != nil || len(items) != 1 {
		t.Fatal("oversized create persisted")
	}
	for _, extra := range []string{"", "x"} {
		w := call("PUT", "/api/v1/credentials/"+items[0].ID, map[string]string{"value": value + extra})
		want := http.StatusOK
		if extra != "" {
			want = http.StatusBadRequest
		}
		if w.Code != want {
			t.Fatalf("rotate boundary extra=%d status=%d want=%d", len(extra), w.Code, want)
		}
	}
}

func TestCredentialHTTP(t *testing.T) {
	t.Setenv("TG_SENTRY_CREDENTIALS_KEK_FILE", "")
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := core.WithActor(context.Background(), core.SystemActor("test"))
	enroll := func() core.ClientConnection {
		t.Helper()
		code, err := e.CreateEnrollment(ctx, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := e.EnrollClient(code.Code, "linux")
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	bound, other := enroll(), enroll()
	s := New(e, fstest.MapFS{}, "admin", "legacy", t.TempDir())
	h := s.Handler()
	admin, auditor := rbacCookie(s, "human", core.RoleAdmin), rbacCookie(s, "human", core.RoleAuditor)
	secret, rotated := "synthetic-high-entropy-vault-45-first", "synthetic-high-entropy-vault-45-second"
	call := func(method, path, body, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
		if path == "/api/v1/events" {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(ctx)
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	payload, _ := json.Marshal(map[string]any{"name": "fixture", "type": "api_key", "env": "FIXTURE_KEY", "value": secret, "bindings": []core.CredentialBinding{{NodeID: bound.NodeID, AgentID: "agent"}}})
	w := call("POST", "/api/v1/credentials", string(payload), "", admin)
	if w.Code != 201 {
		t.Fatalf("create status %d", w.Code)
	}
	var c core.Credential
	if json.Unmarshal(w.Body.Bytes(), &c) != nil || c.ID == "" {
		t.Fatal("metadata response")
	}
	for _, value := range []string{secret, rotated} {
		if strings.Contains(w.Body.String(), value) {
			t.Fatal("create leaked")
		}
	}
	w = call("PUT", "/api/v1/credentials/"+c.ID, `{"value":"`+rotated+`"}`, "", admin)
	if w.Code != 200 || strings.Contains(w.Body.String(), rotated) {
		t.Fatal("rotate leaked or failed")
	}
	readPaths := []string{"/api/v1/audit", "/api/v1/audit/export", "/api/v1/events"}
	for route := range routeRoles {
		if strings.HasPrefix(route, "GET ") && strings.Contains(route, "credentials") && !strings.Contains(route, "/client/") {
			readPaths = append(readPaths, strings.ReplaceAll(strings.TrimPrefix(route, "GET "), "{id}", c.ID))
		}
	}
	for _, path := range readPaths {
		t.Run(path, func(t *testing.T) {
			w := call("GET", path, "", "", auditor)
			for _, value := range []string{secret, rotated} {
				if strings.Contains(w.Body.String(), value) {
					t.Fatal("read leaked secret")
				}
			}
			if path != "/api/v1/events" && w.Code != 200 {
				t.Fatalf("read status %d", w.Code)
			}
		})
	}
	for _, invalid := range []string{`{"value":"` + secret + `","type":"oauth"}`, `{"` + secret + `":"x"}`} {
		w := call("POST", "/api/v1/credentials", invalid, "", admin)
		if w.Code != 400 || strings.Contains(w.Body.String(), secret) {
			t.Fatal("write error leaked")
		}
	}
	rows, err := teststore.Admin(t, e.DB).Query("SELECT payload FROM records WHERE tenant_id=$1 AND kind IN ('credentials','audit')", "default")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, secret) || strings.Contains(payload, rotated) {
			t.Fatal("plaintext persisted")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	target := "/api/v1/client/credentials/" + c.ID + "?agent=agent"
	for _, tc := range []struct {
		name, token, path string
		cookie            *http.Cookie
		status            int
	}{
		{"unauthenticated", "", target, nil, 401}, {"cookie", "", target, admin, 403},
		{"local-hook", "legacy", target, nil, 403}, {"other-node", other.Token, target, nil, 403},
		{"other-agent", bound.Token, "/api/v1/client/credentials/" + c.ID + "?agent=other", nil, 403},
		{"unknown", bound.Token, "/api/v1/client/credentials/unknown?agent=agent", nil, 403},
		{"bound", bound.Token, target, nil, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := call("GET", tc.path, "", tc.token, tc.cookie)
			if w.Code != tc.status {
				t.Fatalf("status %d want %d", w.Code, tc.status)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cacheable response")
			}
			if tc.status == 200 && !strings.Contains(w.Body.String(), rotated) {
				t.Fatal("missing plaintext")
			}
			if tc.status != 200 && strings.Contains(w.Body.String(), rotated) {
				t.Fatal("error leaked")
			}
		})
	}
	for route, role := range map[string]core.Role{
		"POST /api/v1/credentials": core.RoleAdmin, "PUT /api/v1/credentials/{id}": core.RoleAdmin,
		"DELETE /api/v1/credentials/{id}": core.RoleAdmin, "GET /api/v1/credentials": core.RoleAuditor,
		"GET /api/v1/credentials/{id}": core.RoleAuditor, "GET /api/v1/client/credentials/{id}": "",
	} {
		if got, ok := routeRoles[route]; !ok || got != role {
			t.Errorf("RBAC %s", route)
		}
	}
	if w := call("DELETE", "/api/v1/credentials/"+c.ID, "", "", admin); w.Code != 200 {
		t.Fatal("delete failed")
	}
	if w := call("GET", target, "", bound.Token, nil); w.Code != 403 {
		t.Fatal("deleted credential readable")
	}
}
