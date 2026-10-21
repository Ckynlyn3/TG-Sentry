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
	"time"
)

func TestDeviceConfiguredOriginAndSource(t *testing.T) {
	for _, tc := range []struct {
		name, publicURL, listenAddr, peer, forwarded, trusted, uri, source string
		status                                                             int
	}{
		{"public", "https://review.example", "", "192.0.2.1:12345", "203.0.113.7", "", "https://review.example/device", "192.0.2.1", 200},
		{"trusted proxy", "https://review.example", "", "192.0.2.1:12345", "203.0.113.7", "192.0.2.0/24", "https://review.example/device", "203.0.113.7", 200},
		{"loopback", "", "127.0.0.1:18790", "127.0.0.1:12345", "203.0.113.7", "", "http://127.0.0.1:18790/device", "127.0.0.1", 200},
		{"ipv6 loopback", "", "[::1]:18790", "[::1]:12345", "", "", "http://[::1]:18790/device", "::1", 200},
		{"missing identity", "", "", "127.0.0.1:12345", "", "", "", "", 500},
		{"unbound identity", "", "127.0.0.1:0", "127.0.0.1:12345", "", "", "", "", 500},
		{"nonloopback HTTP", "", "192.0.2.1:18790", "127.0.0.1:12345", "", "", "", "", 500},
		{"origin with path", "https://review.example/path", "", "192.0.2.1:12345", "", "", "", "", 500},
		{"origin with userinfo", "https://user@review.example", "", "192.0.2.1:12345", "", "", "", "", 500},
		{"malformed source", "https://review.example", "", "invalid", "203.0.113.7", "", "", "", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := deviceServer(t)
			s.PublicURL = tc.publicURL
			s.ListenAddr = tc.listenAddr
			if tc.trusted != "" {
				s.TrustedProxies = []string{tc.trusted}
			}
			target := "https://review.example"
			if tc.publicURL == "" {
				target = "http://127.0.0.1:18790"
			}
			r := httptest.NewRequest("POST", target+deviceAuthorizationPath, strings.NewReader(deviceStartForm().Encode()))
			r.RemoteAddr = tc.peer
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("X-Real-IP", tc.forwarded)
			r.Header.Set("X-Forwarded-Host", "evil.example")
			r.Header.Set("X-Forwarded-Proto", "http")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			body := deviceBody(t, w, tc.status)
			deviceContractResponse(t, deviceAuthorizationPath, w)
			if tc.status == 200 {
				if body["verification_uri"] != tc.uri {
					t.Fatal("verification URI used request identity")
				}
				lookup, err := s.Engine.LookupDeviceGrant(body["user_code"].(string))
				if err != nil || lookup.Source != tc.source {
					t.Fatal("request source did not follow trusted proxy boundary")
				}
			} else {
				var count int
				if err := teststore.Admin(t, s.Engine.DB).QueryRow("SELECT COUNT(*) FROM records WHERE tenant_id=$1 AND kind='device_grants'", "default").Scan(&count); err != nil || count != 0 {
					t.Fatal("invalid source/identity created grant")
				}
			}
		})
	}
}

func TestDeviceNameByteBoundary(t *testing.T) {
	for _, name := range []string{strings.Repeat("a", 120), strings.Repeat("界", 40)} {
		s := deviceServer(t)
		form := deviceStartForm()
		form.Set("name", name)
		w := deviceHTTP(s.Handler(), deviceAuthorizationPath, "application/x-www-form-urlencoded", form.Encode(), nil, "")
		deviceBody(t, w, 200)
		deviceContractResponse(t, deviceAuthorizationPath, w)
	}
}

func TestDeviceTokenClientBindingAndBodyOnlyParameters(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	ticket := deviceStart(t, h)
	code := ticket["device_code"].(string)
	form := devicePollForm(code)
	form.Set("client_id", "other")
	w := deviceHTTP(h, deviceTokenPath, "application/x-www-form-urlencoded", form.Encode(), nil, "")
	if deviceBody(t, w, 400)["error"] != "invalid_client" {
		t.Fatal("incorrect client binding error")
	}
	// Query parameters cannot replace form fields, and duplicates across query/body are rejected.
	for _, tc := range []struct{ path, body, want string }{
		{deviceTokenPath + "?client_id=aegishook", "grant_type=" + deviceGrantTypeFixture + "&device_code=" + code, "invalid_client"},
		{deviceTokenPath + "?device_code=" + code, "client_id=aegishook&grant_type=" + deviceGrantTypeFixture, "invalid_request"},
		{deviceTokenPath + "?client_id=aegishook", devicePollForm(code).Encode(), "invalid_request"},
		{deviceTokenPath, "client_id=aegishook&grant_type=" + deviceGrantTypeFixture + "&user_code=" + ticket["user_code"].(string), "invalid_request"},
	} {
		w = deviceHTTP(h, tc.path, "application/x-www-form-urlencoded", tc.body, nil, "")
		if deviceBody(t, w, 400)["error"] != tc.want {
			t.Fatal("query/user code bypassed form contract")
		}
		deviceContractResponse(t, deviceTokenPath, w)
	}
	if deviceBody(t, devicePoll(t, h, code), 400)["error"] != "authorization_pending" {
		t.Fatal("invalid request mutated poll cadence")
	}
}

func TestDeviceOriginAndIPProtection(t *testing.T) {
	for _, path := range []string{deviceAuthorizationPath, deviceTokenPath} {
		s := deviceServer(t)
		h := s.Handler()
		r := httptest.NewRequest("POST", s.PublicURL+path, strings.NewReader(deviceStartForm().Encode()))
		r.RemoteAddr = "192.0.2.1:12345"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("Pragma") != "no-cache" {
			t.Fatal("origin guard/cache protection not preserved")
		}
		r = httptest.NewRequest("POST", "https://evil.example"+path, strings.NewReader(deviceStartForm().Encode()))
		r.RemoteAddr = "192.0.2.1:12345"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("unconfigured Host accepted")
		}
		request, err := s.Engine.CreateClientRequest("fixture", "linux", "192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Engine.DecideClientRequest(core.WithActor(context.Background(), core.SystemActor("fixture")), request.ID, "block_ip"); err != nil {
			t.Fatal(err)
		}
		w = deviceHTTP(h, path, "application/x-www-form-urlencoded", deviceStartForm().Encode(), nil, "")
		if w.Code != 403 || w.Header().Get("Pragma") != "no-cache" {
			t.Fatal("IP block/cache protection not preserved")
		}
	}
}

func TestDeviceUserCodeThrottleAppliesAcrossSessions(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	ticket := deviceStart(t, h)
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	// D5's 50/hour application ceiling counts unsuccessful guesses too.
	for range 50 {
		deviceBody(t, deviceJSON(t, h, deviceLookupPath, map[string]string{"userCode": "unknown"}, cookie), 404)
	}
	w := deviceJSON(t, h, deviceLookupPath, map[string]string{"userCode": ticket["user_code"].(string)}, rbacCookie(s, "human", core.RoleAdmin))
	deviceBody(t, w, 400)
}

func TestDeviceStoreErrorIsGeneric(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	ticket := deviceStart(t, h)
	if _, err := teststore.Admin(t, s.Engine.DB).Exec("DROP TABLE records"); err != nil {
		t.Fatal(err)
	}
	for _, w := range []*httptest.ResponseRecorder{
		deviceHTTP(h, deviceAuthorizationPath, "application/x-www-form-urlencoded", deviceStartForm().Encode(), nil, ""),
		devicePoll(t, h, ticket["device_code"].(string)),
	} {
		body := deviceBody(t, w, 500)
		if len(body) != 1 || body["error"] != "server_error" {
			t.Fatal("operational failure is not a generic OAuth 500")
		}
	}
}

func TestDeviceCodeClassesDoNotGrantAdmin(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	ticket := deviceStart(t, h)
	for _, token := range []string{ticket["device_code"].(string), ticket["user_code"].(string)} {
		for _, path := range []string{deviceLookupPath, deviceDecisionPath} {
			w := deviceHTTP(h, path, "application/json", "{}", nil, token)
			deviceBody(t, w, 403)
			deviceContractResponse(t, path, w)
		}
	}
	var count int
	if err := teststore.Admin(t, s.Engine.DB).QueryRow("SELECT COUNT(*) FROM records WHERE tenant_id=$1 AND kind='device_user_code_throttle'", "default").Scan(&count); err != nil || count != 0 {
		t.Fatal("unauthenticated code attempted verification")
	}
}

func TestDevicePendingThrottlePersistence(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	ticket := deviceStart(t, h)
	lookup := deviceLookup(t, h, ticket["user_code"].(string), cookie)
	deviceBody(t, devicePoll(t, h, ticket["device_code"].(string)), 400)
	deviceBody(t, devicePoll(t, h, ticket["device_code"].(string)), 400)
	deviceTimeFixture(t, s, lookup["grantId"].(string), "lastPoll", time.Now().Add(-5*time.Second))
	w := devicePoll(t, h, ticket["device_code"].(string))
	body := deviceBody(t, w, 400)
	if body["error"] != "slow_down" || body["interval"] != float64(15) {
		t.Fatal("slow_down did not retain the increased interval")
	}
	// Persisted protocol metadata never leaks through the admin lookup shape.
	lookup = deviceLookup(t, h, ticket["user_code"].(string), cookie)
	encoded, err := json.Marshal(lookup)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"deviceCodeHash", "lastPoll", "interval", "access_token"} {
		if strings.Contains(string(encoded), field) {
			t.Fatal("management response leaked internal poll metadata")
		}
	}
}

// RFC 6749 §3.2: scope is unrecognized on the RFC 8628 §3.4 token request.
func TestDeviceTokenIgnoresScopeThroughLifecycle(t *testing.T) {
	for _, scope := range []string{"", "admin"} {
		t.Run("scope="+scope, func(t *testing.T) {
			s := deviceServer(t)
			h := s.Handler()
			cookie := rbacCookie(s, "human", core.RoleAdmin)
			ticket := deviceStart(t, h)
			form := devicePollForm(ticket["device_code"].(string))
			if scope != "" {
				form.Set("scope", scope)
			}
			poll := func() *httptest.ResponseRecorder {
				w := deviceHTTP(h, deviceTokenPath, "application/x-www-form-urlencoded", form.Encode(), nil, "")
				deviceContractResponse(t, deviceTokenPath, w)
				return w
			}
			if deviceBody(t, poll(), 400)["error"] != "authorization_pending" {
				t.Fatal("unknown token scope changed pending response")
			}
			lookup := deviceLookup(t, h, ticket["user_code"].(string), cookie)
			deviceBody(t, deviceDecide(t, h, lookup["grantId"].(string), "approve", cookie, deviceReviewedTag(t, h, ticket["user_code"].(string), cookie)), 200)
			issued := deviceBody(t, poll(), 200)
			if issued["token_type"] != "Bearer" {
				t.Fatal("unknown token scope changed issuance")
			}
			if deviceBody(t, poll(), 400)["error"] != "invalid_grant" {
				t.Fatal("unknown token scope permitted replay")
			}
			nodes, err := s.Engine.ClientNodes()
			if err != nil || len(nodes) != 1 {
				t.Fatal("scope flow did not issue exactly one node")
			}
		})
	}
}

// Assert bootstrap classification directly as well as through the actual mux.
func TestDeviceExactBootstrapInventory(t *testing.T) {
	for _, path := range []string{deviceAuthorizationPath, deviceTokenPath} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
			r := httptest.NewRequest(method, "https://review.example"+path, nil)
			if clientBootstrap(r) != (method == http.MethodPost) {
				t.Fatal("incorrect protocol method exemption")
			}
		}
		for _, suffix := range []string{"/", "/extra"} {
			r := httptest.NewRequest("POST", "https://review.example"+path+suffix, nil)
			if clientBootstrap(r) {
				t.Fatal("protocol prefix incorrectly exempted")
			}
		}
	}
}
