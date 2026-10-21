package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"aegishook/internal/core"
	"aegishook/internal/testoidc"
	"aegishook/internal/teststore"
)

func newFakeOIDC(t *testing.T) *testoidc.Provider {
	t.Helper()
	p, err := testoidc.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func oidcFixture(t *testing.T) (*Server, *testoidc.Provider, *time.Time) {
	t.Helper()
	p := newFakeOIDC(t)
	for k, v := range map[string]string{"ISSUER": p.URL, "CLIENT_ID": "client", "CLIENT_SECRET": "synthetic-fixture-secret", "REDIRECT_URL": "http://127.0.0.1:18790/api/v1/auth/callback", "ROLE_CLAIM": "roles", "ROLE_MAP": "admin=admins,auditor=auditors,readonly=readers", "TRUSTED_AUDIENCES": ""} {
		t.Setenv("TG_SENTRY_OIDC_"+k, v)
	}
	s, now := sessionServer(t)
	s.ListenAddr = "127.0.0.1:18790"
	return s, p, now
}

func startOIDC(t *testing.T, s *Server, p *testoidc.Provider, prior *http.Cookie) (*http.Cookie, url.Values) {
	t.Helper()
	r := httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/auth/login?next=%2Fcalls%3Fpage%3D2", nil)
	if prior != nil {
		r.AddCookie(prior)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	dest, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	authW := httptest.NewRecorder()
	p.ServeHTTP(authW, httptest.NewRequest("GET", dest.String(), nil))
	return w.Result().Cookies()[len(w.Result().Cookies())-1], dest.Query()
}

func callbackOIDC(s *Server, cookie *http.Cookie, state string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/auth/callback?code=fixture-code&state="+url.QueryEscape(state), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func successfulCookie(t *testing.T, s *Server, p *testoidc.Provider) *http.Cookie {
	t.Helper()
	tx, q := startOIDC(t, s, p, nil)
	w := callbackOIDC(s, tx, q.Get("state"))
	if w.Code != 302 {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "aegis_session" {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestOIDCLoginRedirectHasStateNonceS256(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	if len(q.Get("state")) != 64 || len(q.Get("nonce")) != 64 || q.Get("state") == q.Get("nonce") || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("response_type") != "code" || q.Get("scope") != "openid profile email" || q.Get("redirect_uri") != "http://127.0.0.1:18790/api/v1/auth/callback" {
		t.Fatal("invalid authorization parameters")
	}
	if c.Name != "aegis_oidc_tx" || c.Value != q.Get("state") || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/api/v1/auth/callback" || c.MaxAge != 300 || c.Secure || c.Domain != "" {
		t.Fatal("weak transaction cookie")
	}
}

func TestCallbackExchangeSucceedsWithPKCE(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c := successfulCookie(t, s, p)
	v, ok := s.useSession(c.Value)
	if !ok || v.Kind != "human" || v.Principal != (core.Principal{Issuer: p.URL, Subject: "subject"}) || v.Role != core.RoleAdmin || v.Name != "Display Name" || v.Tenant != "default" || p.TokenCalls == 0 || p.InvalidGrant {
		t.Fatal("invalid verified session")
	}
}

func TestCallbackRejectsBadPKCE(t *testing.T) {
	s, p, _ := oidcFixture(t)
	tx, q := startOIDC(t, s, p, nil)
	p.Challenge = "not-the-stored-challenge"
	w := callbackOIDC(s, tx, q.Get("state"))
	if w.Code != 401 || !p.InvalidGrant || len(s.sessions) != 0 {
		t.Fatal("PKCE mismatch was not rejected by token endpoint")
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	for _, mode := range []string{"missing-cookie", "mismatch", "unknown", "replay"} {
		t.Run(mode, func(t *testing.T) {
			s, p, _ := oidcFixture(t)
			c, q := startOIDC(t, s, p, nil)
			state := q.Get("state")
			switch mode {
			case "missing-cookie":
				c = nil
			case "mismatch":
				state = "other"
			case "unknown":
				c.Value = "unknown"
				state = "unknown"
			case "replay":
				first := callbackOIDC(s, c, state)
				if first.Code != 302 {
					t.Fatal("first callback failed")
				}
				s.sessions = map[string]session{}
			}
			w := callbackOIDC(s, c, state)
			if w.Code != 401 || len(s.sessions) != 0 {
				t.Fatal("bad state accepted")
			}
		})
	}
}

func rejectOIDCClaim(t *testing.T, change func(*testoidc.Provider)) {
	t.Helper()
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	change(p)
	w := callbackOIDC(s, c, q.Get("state"))
	if w.Code != 401 || len(s.sessions) != 0 {
		t.Fatalf("invalid token accepted: %d", w.Code)
	}
}
func TestCallbackRejectsNonceMismatch(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.Claims["nonce"] = "other" })
}
func TestCallbackRejectsWrongIssuer(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.Claims["iss"] = "https://wrong.example" })
}
func TestCallbackRejectsUntrustedExtraAudience(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.Claims["aud"] = []string{"client", "untrusted"} })
}
func TestCallbackRejectsAzpMismatch(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.Claims["azp"] = "wrong" })
}
func TestCallbackRejectsEmptySub(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.Claims["sub"] = "" })
}
func TestCallbackRejectsInvalidSignature(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.BadSignature = true })
}
func TestCallbackRejectsExpiredToken(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.Claims["exp"] = time.Now().Add(-time.Hour).Unix() })
}
func TestCallbackRejectsWrongAudience(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.Claims["aud"] = "wrong" })
}
func TestCallbackRejectsMissingIDToken(t *testing.T) {
	rejectOIDCClaim(t, func(p *testoidc.Provider) { p.MissingIDToken = true })
}

func TestCallbackUnmappedRoleNoSession(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	p.Claims["roles"] = []string{"unknown"}
	w := callbackOIDC(s, c, q.Get("state"))
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"error":"no_role"`) || len(s.sessions) != 0 {
		t.Fatal("unmapped role admitted")
	}
}
func TestCallbackSetsStrictHttpOnlyCookie8h(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c := successfulCookie(t, s, p)
	if c.SameSite != http.SameSiteStrictMode || !c.HttpOnly || c.MaxAge != 28800 || c.Path != "/" || c.Domain != "" || len(c.Value) != 64 {
		t.Fatal("weak session cookie")
	}
}
func TestReauthInvalidatesPriorSession(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c := successfulCookie(t, s, p)
	tx, q := startOIDC(t, s, p, c)
	if _, ok := s.useSession(c.Value); ok {
		t.Fatal("prior session survived reauth initiation")
	}
	w := callbackOIDC(s, tx, q.Get("state"))
	if w.Code != 302 {
		t.Fatal("reauth failed")
	}
	for _, next := range w.Result().Cookies() {
		if next.Name == "aegis_session" && next.Value == c.Value {
			t.Fatal("identifier reused")
		}
	}
}
func TestLogoutInvalidatesNewSession(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c := successfulCookie(t, s, p)
	r := httptest.NewRequest("POST", "http://127.0.0.1:18790/api/v1/logout", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout failed")
	}
	if _, ok := s.useSession(c.Value); ok {
		t.Fatal("session survived logout")
	}
}
func TestSSOUnconfigured503(t *testing.T) {
	s, _, _ := oidcFixture(t)
	t.Setenv("TG_SENTRY_OIDC_CLIENT_ID", "")
	for _, path := range []string{"login", "callback"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/auth/"+path, nil))
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"error":"sso_not_configured"`) {
			t.Fatal("unconfigured SSO not closed")
		}
	}
}
func TestCallbackRejectsExpiredTx(t *testing.T) {
	s, p, now := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	*now = now.Add(5*time.Minute + time.Nanosecond)
	w := callbackOIDC(s, c, q.Get("state"))
	if w.Code != 401 || p.TokenCalls != 0 {
		t.Fatal("expired transaction exchanged")
	}
}
func TestTxMapEvictsExpiredOnNextLogin(t *testing.T) {
	s, p, now := oidcFixture(t)
	_, q := startOIDC(t, s, p, nil)
	*now = now.Add(5*time.Minute + time.Nanosecond)
	startOIDC(t, s, p, nil)
	if _, exists := s.oidcTransactions[q.Get("state")]; exists || len(s.oidcTransactions) != 1 {
		t.Fatal("expired transaction retained")
	}
}

func TestOIDCRedirectConfigurationFailsClosed(t *testing.T) {
	for _, mode := range []string{"public-mismatch", "localhost", "wrong-port", "missing-listener"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _ := oidcFixture(t)
			switch mode {
			case "public-mismatch":
				s.PublicURL = "https://console.example"
			case "localhost":
				t.Setenv("TG_SENTRY_OIDC_REDIRECT_URL", "http://localhost:18790/api/v1/auth/callback")
			case "wrong-port":
				s.ListenAddr = "127.0.0.1:18800"
			case "missing-listener":
				s.ListenAddr = ""
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/auth/login", nil))
			if w.Code != 503 {
				t.Fatalf("bad redirect configuration accepted: %d", w.Code)
			}
		})
	}
}

func TestCallbackRoleAndIdentityClaims(t *testing.T) {
	for _, mode := range []string{"trusted-audience", "string-role", "admin-wins", "username-fallback", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			s, p, _ := oidcFixture(t)
			switch mode {
			case "trusted-audience":
				t.Setenv("TG_SENTRY_OIDC_TRUSTED_AUDIENCES", "trusted")
				p.Claims["aud"] = []string{"client", "trusted"}
				p.Claims["azp"] = "client"
			case "string-role":
				p.Claims["roles"] = "admins"
			case "admin-wins":
				p.Claims["roles"] = []string{"readers", "admins", "auditors"}
			case "username-fallback":
				delete(p.Claims, "name")
			case "recovery":
				p.Claims["roles"] = []string{"unknown"}
				e, err := core.Open(teststore.Dir(t, t.TempDir()))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { e.Close() })
				s.Engine = e
				before, err := e.Audits()
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Engine.BindAdmin(core.Principal{Issuer: p.URL, Subject: "subject"}, "recovery"); err != nil {
					t.Fatal(err)
				}
				audits, err := e.Audits()
				if err != nil || len(audits) != len(before)+1 {
					t.Fatalf("recovery bind did not add one audit: %v", err)
				}
				found := false
				for _, audit := range audits {
					if audit.Action == "admin.bind" {
						var target core.Principal
						if err := json.Unmarshal([]byte(audit.Detail), &target); err != nil || target != (core.Principal{Issuer: p.URL, Subject: "subject"}) || audit.Actor != (core.Actor{Issuer: "local", Subject: "cli", Name: "cli", Kind: "cli"}) {
							t.Fatalf("invalid recovery audit: %+v", audit)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("recovery bind audit missing")
				}
			}
			c := successfulCookie(t, s, p)
			v, ok := s.useSession(c.Value)
			if !ok {
				t.Fatal("no session")
			}
			if v.Role != core.RoleAdmin {
				t.Fatal("admin admission lost")
			}
			if mode == "username-fallback" && v.Name != "username" {
				t.Fatal("wrong fallback")
			}
		})
	}
}

func TestReauthInvalidatesPriorSessionWhenDiscoveryFails(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c := successfulCookie(t, s, p)
	p.Close()
	r := httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/auth/login", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("failed discovery admitted login")
	}
	if _, ok := s.useSession(c.Value); ok {
		t.Fatal("prior session survives failed reauthentication initiation")
	}
}

func TestOIDCConfigurationValidation(t *testing.T) {
	s, _, _ := oidcFixture(t)
	for _, tc := range []struct{ key, value string }{
		{"ISSUER", ":invalid"}, {"ISSUER", "http://remote.example"},
		{"CLIENT_SECRET", ""}, {"REDIRECT_URL", "http://127.0.0.1:18790/api/v1/auth/callback?evil=1"},
		{"REDIRECT_URL", "http://user@127.0.0.1:18790/api/v1/auth/callback"},
		{"ROLE_MAP", "admin=admins"}, {"ROLE_MAP", "admin=admins,auditor=auditors,unknown=readers"},
		{"ROLE_MAP", "admin=admins,admin=other,auditor=auditors,readonly=readers"},
		{"ROLE_MAP", "admin=,auditor=auditors,readonly=readers"},
		{"TRUSTED_AUDIENCES", "trusted,"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			t.Setenv("TG_SENTRY_OIDC_"+tc.key, tc.value)
			if readOIDCSettings(s.PublicURL, s.ListenAddr) != nil {
				t.Fatal("invalid configuration admitted")
			}
		})
	}
	t.Setenv("TG_SENTRY_OIDC_ROLE_CLAIM", "")
	if got := readOIDCSettings(s.PublicURL, s.ListenAddr); got == nil || got.roleClaim != "roles" {
		t.Fatal("default role claim missing")
	}
}

func TestOIDCIPv6LoopbackRedirect(t *testing.T) {
	s, _, _ := oidcFixture(t)
	s.ListenAddr = "[::1]:18790"
	t.Setenv("TG_SENTRY_OIDC_REDIRECT_URL", "http://[::1]:18790/api/v1/auth/callback")
	if readOIDCSettings("", s.ListenAddr) == nil {
		t.Fatal("IP-literal IPv6 redirect rejected")
	}
}

func TestOIDCPublicCookiesAndRedirect(t *testing.T) {
	s, p, _ := oidcFixture(t)
	s.PublicURL = "https://console.example"
	t.Setenv("TG_SENTRY_OIDC_REDIRECT_URL", s.PublicURL+oidcCallbackPath)
	handler := s.Handler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", s.PublicURL+"/api/v1/auth/login?next=//evil.example", nil))
	if w.Code != 302 {
		t.Fatal("public login failed")
	}
	c := w.Result().Cookies()[0]
	if !c.Secure {
		t.Fatal("public transaction cookie is insecure")
	}
	dest, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	authW := httptest.NewRecorder()
	p.ServeHTTP(authW, httptest.NewRequest("GET", dest.String(), nil))
	// The fixture records nonce/PKCE but deliberately refuses non-loopback
	// redirects. Complete the synthetic callback below, without following one.
	if authW.Code != http.StatusBadRequest {
		t.Fatalf("public provider redirect: got %d, want %d", authW.Code, http.StatusBadRequest)
	}
	r := httptest.NewRequest("GET", s.PublicURL+oidcCallbackPath+"?code=fixture-code&state="+dest.Query().Get("state"), nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 302 || w.Header().Get("Location") != "/" {
		t.Fatal("unsafe callback redirect")
	}
	for _, c := range w.Result().Cookies() {
		if !c.Secure {
			t.Fatal("public callback cookie is insecure")
		}
	}
}

func TestCallbackRejectsMalformedRole(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	p.Claims["roles"] = map[string]string{"role": "admins"}
	w := callbackOIDC(s, c, q.Get("state"))
	if w.Code != 403 || len(s.sessions) != 0 {
		t.Fatal("malformed role admitted")
	}
}

func TestCallbackFailureConsumesTransaction(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	p.TokenFailure = true
	w := callbackOIDC(s, c, q.Get("state"))
	if w.Code != 401 {
		t.Fatal("provider failure admitted")
	}
	calls := p.TokenCalls
	w = callbackOIDC(s, c, q.Get("state"))
	if w.Code != 401 || p.TokenCalls != calls {
		t.Fatal("failed transaction replayed")
	}
}

func TestCallbackDiscoveryFailure(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	p.Close()
	w := callbackOIDC(s, c, q.Get("state"))
	if w.Code != 401 || len(s.sessions) != 0 {
		t.Fatal("failed discovery admitted")
	}
}

func TestOIDCTransactionConsumedOnceConcurrently(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	request := httptest.NewRequest("GET", "http://127.0.0.1:18790"+oidcCallbackPath+"?state="+q.Get("state"), nil)
	request.AddCookie(c)
	result := make(chan bool)
	go func() { _, ok := s.consumeTransaction(request); result <- ok }()
	go func() { _, ok := s.consumeTransaction(request); result <- ok }()
	a, b := <-result, <-result
	if a == b {
		t.Fatal("transaction not consumed exactly once")
	}
}

func TestCallbackAdmitsMappedRolesWithCapabilities(t *testing.T) {
	for _, tc := range []struct {
		claim string
		role  core.Role
	}{{"auditors", core.RoleAuditor}, {"readers", core.RoleReadOnly}} {
		t.Run(tc.claim, func(t *testing.T) {
			s, p, _ := oidcFixture(t)
			p.Claims["roles"] = []string{tc.claim}
			cookie := successfulCookie(t, s, p)
			v, ok := s.useSession(cookie.Value)
			if !ok || v.Role != tc.role {
				t.Fatal("mapped role not admitted")
			}
			h := s.Handler()
			w := rbacRequest(h, cookie, "GET", "http://127.0.0.1:18790/api/v1/me", "", "192.0.2.1:12345")
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"role":"`+string(tc.role)+`"`) {
				t.Fatal("role missing from /me")
			}
			w = rbacRequest(h, cookie, "PUT", "http://127.0.0.1:18790/api/v1/settings", "{", "192.0.2.1:12345")
			if w.Code != 403 {
				t.Fatal("lower role reached mutation handler")
			}
		})
	}
}
