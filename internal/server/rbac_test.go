package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func rbacCookie(s *Server, kind string, role core.Role) *http.Cookie {
	v := s.createSession(session{Kind: kind, Principal: core.Principal{Issuer: "https://issuer.example", Subject: "fixture-subject"}, Name: "Fixture", Role: role, Tenant: "default"})
	return &http.Cookie{Name: sessionCookieName, Value: v.ID}
}

func rbacRequest(h http.Handler, cookie *http.Cookie, method, target, body, peer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.RemoteAddr = peer
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Approved #12 plan D2: every mutation family, including future whitelist and
// retention paths, is denied before decoding inputs or touching the store.
func TestMatrixDeniesNonAdminWrites(t *testing.T) {
	routes := []string{
		"PUT /settings", "POST /model/test", "POST /installations", "DELETE /installations/id",
		"POST /rules", "DELETE /rules/id", "POST /scopes", "DELETE /scopes/id",
		"POST /client-enrollments", "DELETE /client-enrollments/id", "DELETE /client-nodes/id",
		"DELETE /client-ip-blocks/id", "POST /client-requests/id/decision", "POST /approvals/id/decision",
		"POST /device-grants/lookup", "POST /device-grants/decision",
		"POST /templates", "PUT /templates/id", "DELETE /templates/id",
		"POST /policies", "PUT /policies/id", "DELETE /policies/id", "PUT /client-nodes/id/tags",
		"POST /whitelist", "DELETE /whitelist/id", "PUT /retention",
	}
	for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor} {
		for _, route := range routes {
			t.Run(string(role)+route, func(t *testing.T) {
				s, _ := sessionServer(t)
				method, path, _ := strings.Cut(route, " ")
				w := rbacRequest(s.Handler(), rbacCookie(s, "human", role), method, "http://127.0.0.1/api/v1"+path, "{", "127.0.0.1:12345")
				if w.Code != http.StatusForbidden {
					t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestUnlistedRouteRequiresAdmin(t *testing.T) {
	for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor, core.RoleAdmin, "unknown", ""} {
		s, _ := sessionServer(t)
		w := rbacRequest(s.Handler(), rbacCookie(s, "human", role), "GET", "http://127.0.0.1/api/v1/future-route", "", "127.0.0.1:12345")
		want := http.StatusForbidden
		if role == core.RoleAdmin {
			want = http.StatusNotFound
		}
		if w.Code != want {
			t.Errorf("role %q: got %d, want %d", role, w.Code, want)
		}
	}
}

func TestLogoutAndMeAllowedForAllRoles(t *testing.T) {
	for _, kind := range []string{"human", "cli"} {
		for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor, core.RoleAdmin} {
			s, _ := sessionServer(t)
			cookie := rbacCookie(s, kind, role)
			h := s.Handler()
			w := rbacRequest(h, cookie, "GET", "http://127.0.0.1/api/v1/me", "", "127.0.0.1:12345")
			var me map[string]any
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &me) != nil || me["role"] != string(role) || me["kind"] != kind || me["subject"] != "fixture-subject" || me["tenant"] != "default" || me["name"] != "Fixture" || me["version"] != core.Version {
				t.Fatalf("%s/%s me: %d %s", kind, role, w.Code, w.Body.String())
			}
			capabilities, ok := me["capabilities"].([]any)
			if !ok || len(capabilities) != 1 || capabilities[0] != "risk-stats" {
				t.Fatalf("%s/%s capabilities: %v", kind, role, me["capabilities"])
			}
			w = rbacRequest(h, cookie, "POST", "http://127.0.0.1/api/v1/logout", "", "127.0.0.1:12345")
			if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
				t.Fatalf("%s/%s logout: %d", kind, role, w.Code)
			}
			if _, ok := s.useSession(cookie.Value); ok {
				t.Fatal("logout retained server session")
			}
		}
	}
}

func TestCliSessionLoopbackOnlyOnIssue(t *testing.T) {
	for _, tc := range []struct {
		peer, host string
		want       int
	}{
		{"127.0.0.1:12345", "127.0.0.1", 200}, {"[::1]:12345", "localhost", 200},
		{"[::ffff:127.0.0.2]:12345", "127.0.0.2", 200},
		{"192.0.2.1:12345", "127.0.0.1", 403}, {"", "localhost", 403},
		{"localhost:12345", "localhost", 403}, {"127.0.0.1:12345", "console.example", 403},
	} {
		s, _ := sessionServer(t)
		s.PublicURL = "https://console.example"
		w := rbacRequest(s.Handler(), nil, "POST", "https://"+tc.host+"/api/v1/cli/session", `{"token":"legacy-test-admin"}`, tc.peer)
		if w.Code != tc.want {
			t.Errorf("peer=%q host=%s: got %d want %d", tc.peer, tc.host, w.Code, tc.want)
		}
		if tc.want == 200 {
			if len(w.Result().Cookies()) != 1 {
				t.Fatal("no CLI cookie")
			}
			v, ok := s.useSession(w.Result().Cookies()[0].Value)
			if !ok || v.Kind != "cli" || v.Principal != (core.Principal{Issuer: "local", Subject: "cli"}) || v.Role != core.RoleAdmin || v.Name != "cli" || v.Tenant != "default" {
				t.Fatal("wrong CLI principal")
			}
		} else if len(s.sessions) != 0 {
			t.Fatal("forbidden peer created session")
		}
	}
}

func TestCliCookieReplayRejected(t *testing.T) {
	for _, tc := range []struct{ peer, target string }{
		{"127.0.0.1:12345", "https://console.example/api/v1/me"},
		{"192.0.2.1:12345", "http://127.0.0.1/api/v1/me"},
	} {
		s, _ := sessionServer(t)
		s.PublicURL = "https://console.example"
		cookie := rbacCookie(s, "cli", core.RoleAdmin)
		w := rbacRequest(s.Handler(), cookie, "GET", tc.target, "", tc.peer)
		if w.Code != 403 {
			t.Fatalf("replayed CLI: %d", w.Code)
		}
		if _, ok := s.useSession(cookie.Value); ok {
			t.Fatal("replayed CLI session not deleted")
		}
	}
}

func TestCliSessionCannotChangePolicy(t *testing.T) {
	s, _ := sessionServer(t)
	cookie := rbacCookie(s, "cli", core.RoleAdmin)
	for _, route := range []string{"POST /policies", "GET /policies", "GET /settings", "POST /rules/test", "GET /client-enrollments", "GET /client-installer"} {
		method, path, _ := strings.Cut(route, " ")
		w := rbacRequest(s.Handler(), cookie, method, "http://127.0.0.1/api/v1"+path, "{", "127.0.0.1:12345")
		if w.Code != 403 {
			t.Errorf("%s: got %d", route, w.Code)
		}
	}
}

func TestOldLoginRouteGone(t *testing.T) {
	for _, body := range []string{`{"token":"legacy-test-admin"}`, `{"token":""}`, `{`} {
		s, _ := sessionServer(t)
		w := rbacRequest(s.Handler(), nil, "POST", "http://127.0.0.1/api/v1/login", body, "127.0.0.1:12345")
		if w.Code != http.StatusNotFound || len(w.Result().Cookies()) != 0 || len(s.sessions) != 0 {
			t.Fatalf("removed login: status=%d cookies=%d sessions=%d", w.Code, len(w.Result().Cookies()), len(s.sessions))
		}
	}
}

func TestUnknownAPIStillRequiresSession(t *testing.T) {
	s, _ := sessionServer(t)
	for _, route := range []string{"POST /api/v1/unregistered", "GET /api/v1/login", "POST /api/v1/settings",
		"POST /api/v1%2Flogin", "POST /api/v1/%6cogin", "POST /api/v1/login/", "POST /api/v1/Login", "PUT /api/v1/login", "POST /api/v1%2Fcli/session",
		"GET /api/v1/client/device-authorization", "GET /api/v1/client/device-token",
		"PUT /api/v1/client/device-token", "POST /api/v1/client/device-token/", "POST /api/v1/client/device-token/extra",
		"POST /api/v1/client/device-Authorization", "POST /api/v1/client/%64evice-token", "POST /api/v1/client%2Fdevice-authorization"} {
		method, path, _ := strings.Cut(route, " ")
		w := rbacRequest(s.Handler(), nil, method, "http://127.0.0.1"+path, "", "127.0.0.1:12345")
		if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 || len(s.sessions) != 0 {
			t.Errorf("%s: got %d cookies=%d, want 401 and no session", route, w.Code, len(w.Result().Cookies()))
		}
	}
}

func TestCliSessionRejectsInvalidToken(t *testing.T) {
	for _, token := range []string{"", "wrong", "legacy-test-admi", "legacy-test-admin-extra"} {
		s, _ := sessionServer(t)
		body, err := json.Marshal(map[string]string{"token": token})
		if err != nil {
			t.Fatal(err)
		}
		w := rbacRequest(s.Handler(), nil, "POST", "http://127.0.0.1/api/v1/cli/session", string(body), "127.0.0.1:12345")
		if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 || len(s.sessions) != 0 {
			t.Fatal("invalid CLI token issued a session")
		}
	}
}

func TestRoleMatrixAndCliAllowlist(t *testing.T) {
	for pattern, minimum := range routeRoles {
		// #72 S1/U3: association preview/confirm are admitted only by the
		// server-owned grant continuation, never by a role. They are covered by
		// TestDeviceAssociationLiveOIDC (bound success, unbound/roleless denial).
		if deviceAssociationRoutes[pattern] {
			if sessionAllows(session{Kind: "human", Role: core.RoleAdmin, AssociationGrant: "g"}, pattern) == false {
				t.Errorf("%s denies a bound continuation", pattern)
			}
			for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor, core.RoleAdmin} {
				if sessionAllows(session{Kind: "human", Role: role}, pattern) {
					t.Errorf("%s granted by role %s", pattern, role)
				}
			}
			continue
		}
		for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor, core.RoleAdmin, "", "other"} {
			want := role == core.RoleAdmin || (role == core.RoleAuditor && (minimum == core.RoleAuditor || minimum == core.RoleReadOnly)) || (role == core.RoleReadOnly && minimum == core.RoleReadOnly)
			v := session{Kind: "human", Role: role}
			if got := sessionAllows(v, pattern); got != want {
				t.Errorf("%s %s: got %v want %v", role, pattern, got, want)
			}
			v.Kind = "cli"
			if got := sessionAllows(v, pattern); got != (want && cliRoutes[pattern]) {
				t.Errorf("CLI %s %s: got %v", role, pattern, got)
			}
		}
	}
	if sessionAllows(session{Kind: "unknown", Role: core.RoleAdmin}, "GET /api/v1/me") {
		t.Fatal("unknown session kind admitted")
	}
}

func TestSessionDenyOverridesAndExactMethods(t *testing.T) {
	s, now := sessionServer(t)
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleReadOnly)
	for _, method := range []string{"HEAD", "OPTIONS", "POST", "PUT"} {
		if w := rbacRequest(h, cookie, method, "http://127.0.0.1/api/v1/me", "", "127.0.0.1:12345"); w.Code != 403 {
			t.Errorf("%s: %d", method, w.Code)
		}
	}
	for _, mode := range []string{"host", "origin", "bearer"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1/api/v1/me", nil)
		r.AddCookie(rbacCookie(s, "human", core.RoleAdmin))
		switch mode {
		case "host":
			r.Host = "evil.example"
		case "origin":
			r.Header.Set("Origin", "https://evil.example")
		case "bearer":
			r.Header.Set("Authorization", "Bearer test-hook")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s guard overridden by admin cookie: %d", mode, w.Code)
		}
	}
	*now = now.Add(sessionIdle + time.Nanosecond)
	if w := rbacRequest(h, cookie, "GET", "http://127.0.0.1/api/v1/me", "", "127.0.0.1:12345"); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
}

func TestCliSessionRejectsInvalidInputAndSpoofedPeer(t *testing.T) {
	s, _ := sessionServer(t)
	for _, tc := range []struct {
		body   string
		status int
	}{{"{", 400}, {`{}`, 401}, {`{"token":"wrong"}`, 401}, {`{"token":""}`, 401}} {
		w := rbacRequest(s.Handler(), nil, "POST", "http://127.0.0.1/api/v1/cli/session", tc.body, "127.0.0.1:12345")
		if w.Code != tc.status || len(s.sessions) != 0 {
			t.Fatalf("CLI input %s: %d", tc.body, w.Code)
		}
	}
	s.TrustedProxies = []string{"192.0.2.0/24"}
	r := httptest.NewRequest("POST", "http://localhost/api/v1/cli/session", strings.NewReader(`{"token":"legacy-test-admin"}`))
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("X-Real-IP", "127.0.0.1")
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 || len(s.sessions) != 0 {
		t.Fatal("forwarded address trusted as CLI peer")
	}
}

func rbacStoreServer(t *testing.T) *Server {
	t.Helper()
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
}

// Real HTTP handler -> engine -> persisted audit, not a context-only mock.
// Covers server.go, client_requests.go and protection.go mutation callsites (D6).
func TestSessionActorPersistedEndToEnd(t *testing.T) {
	s, p, _ := oidcFixture(t)
	store := rbacStoreServer(t)
	s.Engine = store.Engine
	s.Engine.Notify = s.publish
	cookie := successfulCookie(t, s, p)
	h := s.Handler()
	call := func(method, path, body string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, "http://127.0.0.1:18790/api/v1"+path, strings.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("If-Match", `"0"`)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	call("POST", "/rules", `{"id":"U_RBAC","name":"fixture","enabled":true,"decision":"reject","matcher":"contains","pattern":"rbac-fixture"}`)
	key := call("POST", "/client-enrollments", `{"name":"fixture","type":"one-off"}`)
	call("DELETE", "/client-enrollments/"+key["id"].(string), "")
	ticket, err := s.Engine.CreateClientRequest("fixture", "linux", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	call("POST", "/client-requests/"+ticket.ID+"/decision", `{"decision":"approve"}`)
	draft := call("POST", "/templates/review", `{"name":"fixture","rules":[{"ruleId":"U_RBAC","category":"category::sensitive-info","action":"block"}]}`)
	call("POST", "/templates", `{"reviewId":"`+draft["id"].(string)+`","confirmDowngrade":true}`)
	audits, err := s.Engine.Audits()
	if err != nil {
		t.Fatal(err)
	}
	wantActor := core.Actor{Issuer: p.URL, Subject: "subject", Name: "Display Name", Kind: "human"}
	for _, action := range []string{"rule.save", "client.enrollment.create", "client.enrollment.revoke", "client.request.approve", "protection.templates.publish"} {
		found := false
		for _, audit := range audits {
			if audit.Action == action {
				found = true
				if audit.Actor != wantActor {
					t.Errorf("%s actor=%+v want=%+v", action, audit.Actor, wantActor)
				}
			}
		}
		if !found {
			t.Errorf("no persisted %s audit", action)
		}
	}
}

func seedRBACReview(t *testing.T, s *Server) string {
	t.Helper()
	const sentinel = "RBAC-CONTENT-SENTINEL"
	review := core.Review{ID: "rbac-review", ReviewInput: core.ReviewInput{InstanceID: "rbac-instance", ToolName: "Bash", Arguments: map[string]any{"command": sentinel}, UserMessage: sentinel, Context: sentinel, Scripts: []core.ReviewScript{{Path: "fixture.sh", Content: sentinel}}}, ModelContext: ptrRBACString(sentinel), ModelInput: json.RawMessage(`{"fixture":"` + sentinel + `"}`), Result: sentinel, Decision: "approve", Execution: "succeeded", CreatedAt: time.Now()}
	b, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := teststore.Admin(t, s.Engine.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('default','reviews',$1,$2)", review.ID, string(b)); err != nil {
		t.Fatal(err)
	}
	return sentinel
}

func ptrRBACString(s string) *string { return &s }

func TestReadOnlyListHasNoContentFields(t *testing.T) {
	s := rbacStoreServer(t)
	sentinel := seedRBACReview(t, s)
	cookie := rbacCookie(s, "human", core.RoleReadOnly)
	for _, path := range []string{"/calls", "/calls?page=1&size=1", "/overview"} {
		w := rbacRequest(s.Handler(), cookie, "GET", "http://127.0.0.1/api/v1"+path, "", "127.0.0.1:12345")
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), sentinel) || !strings.Contains(w.Body.String(), `"id":"rbac-review"`) {
			t.Fatalf("%s content projection missing or leaked", path)
		}
		for _, field := range []string{"argumentsObj", "userMessage", "context", "result", "modelContext", "modelInput"} {
			if strings.Contains(w.Body.String(), `"`+field+`":`) {
				t.Errorf("%s exposes %s", path, field)
			}
		}
		if path == "/overview" && strings.Contains(w.Body.String(), `"diagnostic":`) {
			t.Fatal("readonly overview exposes diagnostic")
		}
	}
}

func TestReadOnlyResponsesCarryNoContent(t *testing.T) {
	s := rbacStoreServer(t)
	sentinel := seedRBACReview(t, s)
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleReadOnly)
	for pattern, role := range routeRoles {
		if deviceAssociationRoutes[pattern] && strings.HasPrefix(pattern, "GET ") {
			// #72 S1/U3: no role admits it; the unbound 403 is expected and is
			// asserted for bound/unbound in TestDeviceAssociationLiveOIDC.
			w := rbacRequest(h, cookie, "GET", "http://127.0.0.1"+strings.TrimPrefix(pattern, "GET "), "", "127.0.0.1:12345")
			if w.Code != 403 || strings.Contains(w.Body.String(), sentinel) {
				t.Errorf("%s: unbound session must be refused without content", pattern)
			}
			continue
		}
		if role != core.RoleReadOnly || !strings.HasPrefix(pattern, "GET ") {
			continue
		}
		path := strings.ReplaceAll(strings.TrimPrefix(pattern, "GET "), "{id}", "missing")
		w := rbacRequest(h, cookie, "GET", "http://127.0.0.1"+path, "", "127.0.0.1:12345")
		// #16 S3 has not registered its route yet: the mux fallback is still
		// admin-default. The matrix entry above becomes active when it lands.
		if pattern == "GET /api/v1/session-summaries" && w.Code == 403 {
			continue
		}
		// Missing resource IDs may return 404.
		if w.Code != 200 && w.Code != 404 {
			t.Errorf("%s: unexpected %d %s", pattern, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), sentinel) {
			t.Errorf("%s leaked content", pattern)
		}
	}
}

func TestReadOnlyNoDetailNoExport(t *testing.T) {
	s, _ := sessionServer(t)
	cookie := rbacCookie(s, "human", core.RoleReadOnly)
	for _, path := range []string{"/reviews/rbac-review", "/calls/export", "/audit", "/audit/export", "/risk-events", "/risk-events/id", "/risk-events/export", "/events", "/settings", "/settings/versions", "/settings/default-prompt", "/pi", "/client-enrollments", "/client-installer"} {
		w := rbacRequest(s.Handler(), cookie, "GET", "http://127.0.0.1/api/v1"+path, "", "127.0.0.1:12345")
		if w.Code != 403 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
}

func TestAuditorReadsRawContent(t *testing.T) {
	s := rbacStoreServer(t)
	sentinel := seedRBACReview(t, s)
	for _, role := range []core.Role{core.RoleAuditor, core.RoleAdmin} {
		cookie := rbacCookie(s, "human", role)
		for _, path := range []string{"/calls", "/calls?page=1&size=1", "/reviews/rbac-review", "/calls/export", "/overview"} {
			w := rbacRequest(s.Handler(), cookie, "GET", "http://127.0.0.1/api/v1"+path, "", "127.0.0.1:12345")
			if w.Code != 200 || !strings.Contains(w.Body.String(), sentinel) {
				t.Errorf("%s %s: missing content: %d", role, path, w.Code)
			}
		}
	}
}

func TestContentCapabilityCannotBeGrantedByOverride(t *testing.T) {
	s, _ := sessionServer(t)
	s.contentAllowedOverride = func(*http.Request) bool { return true }
	for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor, core.RoleAdmin, "unknown", ""} {
		for _, kind := range []string{"human", "cli", "unknown"} {
			r := httptest.NewRequest("GET", "http://127.0.0.1/api/v1/calls", nil)
			r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, session{Kind: kind, Role: role}))
			want := kind == "human" && (role == core.RoleAuditor || role == core.RoleAdmin)
			if got := s.contentAllowed(r); got != want {
				t.Errorf("%s %s: got %v want %v", kind, role, got, want)
			}
		}
	}
}

func TestRiskStatsRouteAuthorization(t *testing.T) {
	s := rbacStoreServer(t)
	seedServerRiskStats(t, s)
	// A forged tenant must not be interchangeable with the default fixture.
	var foreignPayload []byte
	if err := teststore.Admin(t, s.Engine.DB).QueryRow("SELECT payload FROM records WHERE tenant_id='foreign' AND kind='audit' AND id='stats-fixture'").Scan(&foreignPayload); err != nil {
		t.Fatal(err)
	}
	var foreign core.Audit
	if err := json.Unmarshal(foreignPayload, &foreign); err != nil || len(foreign.Events) != 1 || foreign.Events[0].Data.Actor.AppUID != "foreign-agent" {
		t.Fatal("foreign fixture must have a distinct count and agent identity")
	}
	h := s.Handler()
	target := "http://127.0.0.1/api/v1/risk-events/stats"
	if w := rbacRequest(h, nil, "GET", target, "", "127.0.0.1:12345"); w.Code != 401 {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	for _, kind := range []string{"human", "cli"} {
		for _, role := range []core.Role{core.RoleReadOnly, core.RoleAuditor, core.RoleAdmin} {
			cookie := rbacCookie(s, kind, role)
			want := 403
			if kind == "human" && role != core.RoleReadOnly {
				want = 200
			}
			w := rbacRequest(h, cookie, "GET", target, "", "127.0.0.1:12345")
			if w.Code != want {
				t.Fatalf("%s/%s: %d %s", kind, role, w.Code, w.Body.String())
			}
		}
	}
	r := httptest.NewRequest("GET", target, nil)
	r.Header.Set("Authorization", "Bearer fixture-hook")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("hook bearer: %d", w.Code)
	}
	r = httptest.NewRequest("GET", target+"?tenant=foreign&tenant_uid=foreign", nil)
	r.AddCookie(rbacCookie(s, "human", core.RoleAuditor))
	r.Header.Set("X-Tenant-ID", "foreign")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var stats core.RiskStats
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &stats) != nil || stats.Totals.Total != 4 || stats.Totals.Block != 1 || stats.Totals.Alert != 1 || stats.Totals.Other != 2 || stats.Totals.FutureExcluded != 1 || strings.Contains(w.Body.String(), "foreign-agent") {
		t.Fatalf("forged tenant changed aggregate: %d %s", w.Code, w.Body.String())
	}
	if routeRoles["GET /api/v1/risk-events/stats"] != core.RoleAuditor || routeRoles["GET /api/v1/session-summaries"] != core.RoleReadOnly {
		t.Fatal("risk stats/session summaries matrix contract missing")
	}
}

func TestRiskStatsRouteReconcilesPagedList(t *testing.T) {
	s := rbacStoreServer(t)
	seedServerRiskStats(t, s)
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAuditor)
	for _, window := range []string{"24h", "7d", "all"} {
		for _, filter := range []string{"", "&severity=high", "&category=category::behavior", "&agent=agent-a", "&severity=high&category=category::behavior&agent=agent-a", "&agent=absent"} {
			statsResponse := rbacRequest(h, cookie, "GET", "http://127.0.0.1/api/v1/risk-events/stats?window="+window+filter, "", "127.0.0.1:12345")
			var stats core.RiskStats
			if statsResponse.Code != 200 || json.Unmarshal(statsResponse.Body.Bytes(), &stats) != nil {
				t.Fatalf("%s %s stats: %d %s", window, filter, statsResponse.Code, statsResponse.Body.String())
			}
			query := fmt.Sprintf("?from=%d&to=%d&page_size=1%s", stats.From, stats.To, filter)
			token, total := "", int64(0)
			for {
				response := rbacRequest(h, cookie, "GET", "http://127.0.0.1/api/v1/risk-events"+query+"&page_token="+token, "", "127.0.0.1:12345")
				var page core.RiskEventPage
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil {
					t.Fatalf("list: %d %s", response.Code, response.Body.String())
				}
				total += int64(len(page.Items))
				if page.NextPageToken == "" {
					break
				}
				if page.NextPageToken == token || total > stats.Totals.Total {
					t.Fatal("cursor failed to advance within aggregate")
				}
				token = page.NextPageToken
			}
			if total != stats.Totals.Total {
				t.Fatalf("%s %s: list=%d stats=%d", window, filter, total, stats.Totals.Total)
			}
		}
	}
}

// #75 replaces the pre-#75 cursor limitation with occurrence-complete traversal.
func TestRiskStatsRouteDuplicateOccurrencePagination(t *testing.T) {
	s := rbacStoreServer(t)
	at := time.Now().UTC().Add(-time.Hour)
	event := core.Event{ID: "duplicate", Source: "/stats-fixture", Type: "tg.sentry.risk.v1", Time: at, Data: core.EventData{Time: at.UnixMilli(), Actor: core.EventActor{AppUID: "duplicate-agent"}, EventControl: &core.EventControl{ActionID: 2, DispositionID: 2}}}
	payload, err := json.Marshal(core.Audit{ID: "duplicates", Events: []core.Event{event, event, event}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = teststore.Admin(t, s.Engine.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('default','audit','duplicates',$1)", string(payload)); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAuditor)
	response := rbacRequest(h, cookie, "GET", "http://127.0.0.1/api/v1/risk-events/stats", "", "127.0.0.1:12345")
	var stats core.RiskStats
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &stats) != nil || stats.Totals.Total != 3 || stats.Totals.Block != 3 {
		t.Fatalf("duplicate stats: %d %s", response.Code, response.Body.String())
	}
	query := fmt.Sprintf("http://127.0.0.1/api/v1/risk-events?from=%d&to=%d", stats.From, stats.To)
	list := func(target string) core.RiskEventPage {
		t.Helper()
		w := rbacRequest(h, cookie, "GET", target, "", "127.0.0.1:12345")
		var page core.RiskEventPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil {
			t.Fatalf("duplicate list: %d %s", w.Code, w.Body.String())
		}
		return page
	}
	// Three duplicates exercise two continuation anchors before the terminal page.
	whole := list(query)
	if int64(len(whole.Items)) != stats.Totals.Total || whole.NextPageToken != "" {
		t.Fatalf("single page lost occurrences: %+v", whole)
	}
	first := list(query + "&page_size=1")
	if len(first.Items) != 1 || first.NextPageToken == "" {
		t.Fatalf("first duplicate page: %+v", first)
	}
	second := list(query + "&page_size=1&page_token=" + first.NextPageToken)
	if len(second.Items) != 1 || second.NextPageToken == "" || second.NextPageToken == first.NextPageToken {
		t.Fatalf("duplicate cursor did not advance: %+v", second)
	}
	third := list(query + "&page_size=1&page_token=" + second.NextPageToken)
	if len(third.Items) != 1 || third.NextPageToken != "" {
		t.Fatalf("duplicate traversal did not terminate: %+v", third)
	}
	if int64(len(first.Items)+len(second.Items)+len(third.Items)) != stats.Totals.Total {
		t.Fatal("paged duplicate occurrences do not reconcile with stats")
	}
}
