package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"aegishook/internal/core"
	"aegishook/internal/teststore"
)

// The provider enforces RFC 7636 §4.6, not merely the presence of a verifier.
// RSA-2048 follows RFC 7518 §3.3's minimum for RS256 signatures.
type fakeOIDC struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	claims         map[string]any
	challenge      string
	tokenCalls     int
	invalidGrant   bool
	tokenFailure   bool
	missingIDToken bool
	badSignature   bool
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeOIDC{key: key}
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	p.claims = map[string]any{"iss": p.server.URL, "sub": "subject", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "roles": []string{"readers", "admins", "auditors"}, "name": "Display Name", "preferred_username": "username"}
	return p
}

func (p *fakeOIDC) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		json.NewEncoder(w).Encode(map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/keys":
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes())}}})
	case "/authorize":
		p.challenge = r.URL.Query().Get("code_challenge")
		p.claims["nonce"] = r.URL.Query().Get("nonce")
		w.WriteHeader(http.StatusOK)
	case "/token":
		p.tokenCalls++
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}
		digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if p.tokenFailure || p.challenge == "" || base64.RawURLEncoding.EncodeToString(digest[:]) != p.challenge {
			p.invalidGrant = true
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		token := map[string]any{"access_token": "fixture-access", "token_type": "Bearer"}
		if !p.missingIDToken {
			token["id_token"] = p.sign()
		}
		json.NewEncoder(w).Encode(token)
	default:
		w.WriteHeader(404)
	}
}

func (p *fakeOIDC) sign() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture"}`))
	claims, _ := json.Marshal(p.claims)
	input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	if p.badSignature {
		sig[0] ^= 1
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func oidcFixture(t *testing.T) (*Server, *fakeOIDC, *time.Time) {
	t.Helper()
	p := newFakeOIDC(t)
	for k, v := range map[string]string{"ISSUER": p.server.URL, "CLIENT_ID": "client", "CLIENT_SECRET": "synthetic-fixture-secret", "REDIRECT_URL": "http://127.0.0.1:18790/api/v1/auth/callback", "ROLE_CLAIM": "roles", "ROLE_MAP": "admin=admins,auditor=auditors,readonly=readers", "TRUSTED_AUDIENCES": ""} {
		t.Setenv("TG_SENTRY_OIDC_"+k, v)
	}
	s, now := sessionServer(t)
	s.ListenAddr = "127.0.0.1:18790"
	return s, p, now
}

func startOIDC(t *testing.T, s *Server, p *fakeOIDC, prior *http.Cookie) (*http.Cookie, url.Values) {
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
	p.serve(authW, httptest.NewRequest("GET", dest.String(), nil))
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

func successfulCookie(t *testing.T, s *Server, p *fakeOIDC) *http.Cookie {
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
	if !ok || v.Kind != "human" || v.Principal != (core.Principal{Issuer: p.server.URL, Subject: "subject"}) || v.Role != core.RoleAdmin || v.Name != "Display Name" || v.Tenant != "default" || p.tokenCalls == 0 || p.invalidGrant {
		t.Fatal("invalid verified session")
	}
}

func TestCallbackRejectsBadPKCE(t *testing.T) {
	s, p, _ := oidcFixture(t)
	tx, q := startOIDC(t, s, p, nil)
	p.challenge = "not-the-stored-challenge"
	w := callbackOIDC(s, tx, q.Get("state"))
	if w.Code != 401 || !p.invalidGrant || len(s.sessions) != 0 {
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

func rejectOIDCClaim(t *testing.T, change func(*fakeOIDC)) {
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
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.claims["nonce"] = "other" })
}
func TestCallbackRejectsWrongIssuer(t *testing.T) {
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.claims["iss"] = "https://wrong.example" })
}
func TestCallbackRejectsUntrustedExtraAudience(t *testing.T) {
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.claims["aud"] = []string{"client", "untrusted"} })
}
func TestCallbackRejectsAzpMismatch(t *testing.T) {
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.claims["azp"] = "wrong" })
}
func TestCallbackRejectsEmptySub(t *testing.T) {
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.claims["sub"] = "" })
}
func TestCallbackRejectsInvalidSignature(t *testing.T) {
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.badSignature = true })
}
func TestCallbackRejectsExpiredToken(t *testing.T) {
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.claims["exp"] = time.Now().Add(-time.Hour).Unix() })
}
func TestCallbackRejectsWrongAudience(t *testing.T) {
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.claims["aud"] = "wrong" })
}
func TestCallbackRejectsMissingIDToken(t *testing.T) {
	rejectOIDCClaim(t, func(p *fakeOIDC) { p.missingIDToken = true })
}

func TestCallbackUnmappedRoleNoSession(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	p.claims["roles"] = []string{"unknown"}
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
	if w.Code != 401 || p.tokenCalls != 0 {
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
				p.claims["aud"] = []string{"client", "trusted"}
				p.claims["azp"] = "client"
			case "string-role":
				p.claims["roles"] = "admins"
			case "admin-wins":
				p.claims["roles"] = []string{"readers", "admins", "auditors"}
			case "username-fallback":
				delete(p.claims, "name")
			case "recovery":
				p.claims["roles"] = []string{"unknown"}
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
				if err := s.Engine.BindAdmin(core.Principal{Issuer: p.server.URL, Subject: "subject"}, "recovery"); err != nil {
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
						if err := json.Unmarshal([]byte(audit.Detail), &target); err != nil || target != (core.Principal{Issuer: p.server.URL, Subject: "subject"}) || audit.Actor != (core.Actor{Issuer: "local", Subject: "cli", Name: "cli", Kind: "cli"}) {
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
	p.server.Close()
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
	p.serve(httptest.NewRecorder(), httptest.NewRequest("GET", dest.String(), nil))
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
	p.claims["roles"] = map[string]string{"role": "admins"}
	w := callbackOIDC(s, c, q.Get("state"))
	if w.Code != 403 || len(s.sessions) != 0 {
		t.Fatal("malformed role admitted")
	}
}

func TestCallbackFailureConsumesTransaction(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	p.tokenFailure = true
	w := callbackOIDC(s, c, q.Get("state"))
	if w.Code != 401 {
		t.Fatal("provider failure admitted")
	}
	calls := p.tokenCalls
	w = callbackOIDC(s, c, q.Get("state"))
	if w.Code != 401 || p.tokenCalls != calls {
		t.Fatal("failed transaction replayed")
	}
}

func TestCallbackDiscoveryFailure(t *testing.T) {
	s, p, _ := oidcFixture(t)
	c, q := startOIDC(t, s, p, nil)
	p.server.Close()
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
			p.claims["roles"] = []string{tc.claim}
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
