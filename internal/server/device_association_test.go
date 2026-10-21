package server

import (
	"aegishook/internal/core"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const associationBeginPath = "/api/v1/device-grants/association/begin"
const associationConfirmPath = "/api/v1/device-grants/association/confirm"

func TestDeviceAssociationLiveOIDC(t *testing.T) {
	s, p, _ := oidcFixture(t)
	s.Engine = deviceServer(t).Engine
	s.UI = fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("association fixture")}}
	p.Claims["roles"] = []string{"unmapped-employee"}
	host := httptest.NewUnstartedServer(nil)
	s.ListenAddr = host.Listener.Addr().String()
	t.Setenv("TG_SENTRY_OIDC_REDIRECT_URL", "http://"+s.ListenAddr+oidcCallbackPath)
	host.Config.Handler = s.Handler()
	host.Start()
	t.Cleanup(host.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	ticket, err := s.Engine.CreateDeviceGrant("Employee device", "linux", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	submit := func(path, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("POST", host.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { res.Body.Close() })
		return res
	}
	res := submit(associationBeginPath, `{"userCode":"`+ticket.UserCode+`"}`)
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("begin/OIDC continuation: %d %s", res.StatusCode, b)
	}
	// The continuation target is the standalone employee page the console serves
	// (router.tsx /device/associate); it carries no authority of its own.
	if res.Request.URL.RequestURI() != deviceAssociationNext {
		t.Fatalf("callback landed on %q, want %q", res.Request.URL.RequestURI(), deviceAssociationNext)
	}
	preview, err := client.Get(host.URL + associationConfirmPath)
	if err != nil {
		t.Fatal(err)
	}
	defer preview.Body.Close()
	if preview.StatusCode != 200 {
		t.Fatalf("preview: %d", preview.StatusCode)
	}
	var body struct {
		Grant        core.DeviceGrantLookup `json:"grant"`
		User         core.AssociatedUser    `json:"user"`
		Confirmation string                 `json:"confirmation"`
	}
	if err := json.NewDecoder(preview.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.User.Subject != "subject" || body.User.Issuer != p.URL || body.User.Name != "Display Name" || body.Grant.AssociatedUser != nil {
		t.Fatalf("verified preview: %+v", body)
	}
	// Every registered route requiring a role still denies this roleless cookie.
	for pattern := range routeRoles {
		if strings.Contains(pattern, "association/") || routeRoles[pattern] == "" {
			continue
		}
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			continue
		}
		path = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(path, "{id}", "fixture"), "{version}", "1"), "{script}", "fixture")
		req, _ := http.NewRequest(method, host.URL+path, bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		denied, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		denied.Body.Close()
		if denied.StatusCode != 403 {
			t.Fatalf("roleless %s: %d", pattern, denied.StatusCode)
		}
	}
	for _, injected := range []string{`{"confirm":true,"issuer":"injected"}`, `{"confirm":true,"subject":"injected"}`, `{"confirm":true,"name":"injected"}`, `{"confirm":true,"grantId":"injected"}`, `{"confirm":false}`} {
		if got := submit(associationConfirmPath, injected).StatusCode; got != 400 {
			t.Fatalf("identity injection: %d", got)
		}
	}
	confirmation := `{"confirm":true,"confirmation":"` + body.Confirmation + `"}`
	if got := submit(associationConfirmPath, confirmation).StatusCode; got != 200 {
		t.Fatalf("confirm: %d", got)
	}
	if got := submit(associationConfirmPath, confirmation).StatusCode; got != 403 {
		t.Fatalf("consumed continuation: %d", got)
	}
	lookup, err := s.Engine.LookupDeviceGrant(ticket.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if lookup.AssociatedUser == nil || lookup.AssociatedUser.Subject != "subject" {
		t.Fatal("confirmed identity missing")
	}
	// Callback alone and confirmation never approve; employee A != approving B.
	if lookup.Status != "pending" {
		t.Fatal("association approved grant")
	}
}

func TestDeviceAssociationRequiresOwnContinuation(t *testing.T) {
	s := deviceServer(t)
	s.PublicURL = ""
	h := s.Handler()
	for _, kind := range []string{"human", "cli"} {
		cookie := rbacCookie(s, kind, core.RoleAdmin)
		for _, method := range []string{"GET", "POST"} {
			r := httptest.NewRequest(method, "http://127.0.0.1"+associationConfirmPath, strings.NewReader(`{"confirm":true}`))
			r.RemoteAddr = "127.0.0.1:12345"
			r.AddCookie(cookie)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("ordinary %s session allowed association: %d", kind, w.Code)
			}
		}
	}
}
func TestDeviceGrantDecisionETagHTTP(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	ticket := deviceStart(t, h)
	lookup := deviceJSON(t, h, deviceLookupPath, map[string]string{"userCode": ticket["user_code"].(string)}, cookie)
	if lookup.Header().Get("ETag") == "" {
		t.Fatal("missing grant ETag")
	}
	body := deviceBody(t, lookup, 200)
	for _, tc := range []struct {
		tag  string
		want int
	}{{"", 428}, {`W/` + lookup.Header().Get("ETag"), 412}, {`"stale"`, 412}, {"*", 400}, {`"other", ` + lookup.Header().Get("ETag"), 200}} {
		r := httptest.NewRequest("POST", s.PublicURL+deviceDecisionPath, strings.NewReader(`{"grantId":"`+body["grantId"].(string)+`","decision":"approve"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("If-Match", tc.tag)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("precondition %q: %d want %d", tc.tag, w.Code, tc.want)
		}
	}
}
func TestDeviceAssociationExpiredContinuation(t *testing.T) {
	s := deviceServer(t)
	ticket, err := s.Engine.CreateDeviceGrant("device", "linux", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	g, err := s.Engine.LookupDeviceGrant(ticket.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	v := s.createSession(session{Kind: "human", Principal: core.Principal{Issuer: "https://issuer.example", Subject: "employee"}, AssociationGrant: g.GrantID, AssociationDeadline: s.now().Add(-time.Second)})
	r := httptest.NewRequest("GET", s.PublicURL+associationConfirmPath, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: v.ID})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("expired continuation: %d", w.Code)
	}
}

// OWASP Transaction Authorization §2.6: a different continuation cannot confirm a displayed preview.
func TestDeviceAssociationPreviewSessionReplacement(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	makeSession := func(subject, source string) session {
		ticket, err := s.Engine.CreateDeviceGrant(subject, "linux", source)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := s.Engine.LookupDeviceGrant(ticket.UserCode)
		if err != nil {
			t.Fatal(err)
		}
		return s.createSession(session{Kind: "human", Principal: core.Principal{Issuer: "https://issuer.example", Subject: subject}, AssociationGrant: grant.GrantID, AssociationDeadline: s.now().Add(oidcTransactionLifetime)})
	}
	a := makeSession("employee-a", "192.0.2.1")
	b := makeSession("employee-b", "192.0.2.2")
	request := func(v session, method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, s.PublicURL+associationConfirmPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: v.ID})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	preview := func(v session) string {
		w := request(v, "GET", "")
		if w.Code != 200 {
			t.Fatalf("preview: %d %s", w.Code, w.Body.String())
		}
		var body struct {
			Confirmation string `json:"confirmation"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Confirmation == "" {
			t.Fatal("preview missing confirmation")
		}
		return body.Confirmation
	}
	tokenA, tokenB := preview(a), preview(b)
	confirm := func(v session, token string) *httptest.ResponseRecorder {
		return request(v, "POST", `{"confirm":true,"confirmation":"`+token+`"}`)
	}
	if w := confirm(b, tokenA); w.Code != 409 {
		t.Fatalf("replaced session accepted stale preview: %d", w.Code)
	}
	for _, v := range []session{a, b} {
		g, err := s.Engine.DeviceGrantAssociation(v.AssociationGrant)
		if err != nil || g.AssociatedUser != nil {
			t.Fatalf("stale preview mutated grant: %+v %v", g, err)
		}
	}
	freshB := preview(b)
	if w := confirm(b, tokenB); w.Code != 409 {
		t.Fatalf("replaced preview accepted: %d", w.Code)
	}
	if w := confirm(b, freshB); w.Code != 200 {
		t.Fatalf("fresh preview rejected: %d %s", w.Code, w.Body.String())
	}
	if w := confirm(b, freshB); w.Code != 403 {
		t.Fatalf("single-use replay: %d", w.Code)
	}
	if w := confirm(a, tokenA); w.Code != 200 {
		t.Fatalf("original session preview: %d", w.Code)
	}
}

func TestDeviceAssociationAnonymousFailuresDoNotStarveAdmin(t *testing.T) {
	s, _, _ := oidcFixture(t)
	s.Engine = deviceServer(t).Engine
	h := s.Handler()
	// Existing #40 S1 D5 / device_grants.go deviceUserCodeLimit: 50 submissions/hour.
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest("POST", "http://"+s.ListenAddr+associationBeginPath, strings.NewReader(`{"userCode":"invalid"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("anonymous guess %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	ticket, err := s.Engine.CreateDeviceGrant("admin review", "linux", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Engine.LookupDeviceGrant(ticket.UserCode); err != nil {
		t.Fatalf("anonymous failures starved admin: %v", err)
	}
}

func TestDeviceAssociationBeginNativeForm(t *testing.T) {
	s, _, _ := oidcFixture(t)
	s.Engine = deviceServer(t).Engine
	ticket, err := s.Engine.CreateDeviceGrant("employee", "linux", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://"+s.ListenAddr+associationBeginPath, strings.NewReader("client_id=aegishook&userCode="+ticket.UserCode))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 302 || w.Header().Get("Location") != "/api/v1/auth/login" {
		t.Fatalf("form begin: %d %s", w.Code, w.Body.String())
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == oidcTransactionCookie {
			tx, ok := s.oidcTransactions[cookie.Value]
			if !ok || tx.AssociationGrant == "" {
				t.Fatal("form did not create server-owned grant continuation")
			}
			return
		}
	}
	t.Fatal("form missing continuation cookie")
}
