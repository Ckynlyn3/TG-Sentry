package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const deviceAuthorizationPath = "/api/v1/client/device-authorization"
const deviceTokenPath = "/api/v1/client/device-token"
const deviceLookupPath = "/api/v1/device-grants/lookup"
const deviceDecisionPath = "/api/v1/device-grants/decision"
const deviceGrantTypeFixture = "urn:ietf:params:oauth:grant-type:device_code"

func deviceServer(t *testing.T) *Server {
	t.Helper()
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	s := New(e, fstest.MapFS{}, "admin-fixture", "hook-fixture", t.TempDir())
	s.PublicURL = "https://review.example"
	return s
}

func deviceHTTP(h http.Handler, path, contentType, body string, cookie *http.Cookie, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://review.example"+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("Content-Type", contentType)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func deviceForm(values url.Values) string { return values.Encode() }
func deviceStartForm() url.Values {
	return url.Values{"client_id": {"aegishook"}, "name": {"workstation"}, "platform": {"linux"}}
}
func devicePollForm(code string) url.Values {
	return url.Values{"client_id": {"aegishook"}, "grant_type": {deviceGrantTypeFixture}, "device_code": {code}}
}
func deviceBody(t *testing.T, w *httptest.ResponseRecorder, status int) map[string]any {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP status %d, want %d", w.Code, status)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal("invalid JSON response", err)
	}
	return body
}
func deviceStart(t *testing.T, h http.Handler) map[string]any {
	t.Helper()
	w := deviceHTTP(h, deviceAuthorizationPath, "application/x-www-form-urlencoded", deviceForm(deviceStartForm()), nil, "")
	deviceContractResponse(t, deviceAuthorizationPath, w)
	return deviceBody(t, w, 200)
}
func devicePoll(t *testing.T, h http.Handler, code string) *httptest.ResponseRecorder {
	t.Helper()
	w := deviceHTTP(h, deviceTokenPath, "application/x-www-form-urlencoded", deviceForm(devicePollForm(code)), nil, "")
	deviceContractResponse(t, deviceTokenPath, w)
	return w
}
func deviceJSON(t *testing.T, h http.Handler, path string, input map[string]string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	w := deviceHTTP(h, path, "application/json", string(body), cookie, "")
	deviceContractResponse(t, path, w)
	return w
}
func deviceLookup(t *testing.T, h http.Handler, userCode string, cookie *http.Cookie) map[string]any {
	t.Helper()
	return deviceBody(t, deviceJSON(t, h, deviceLookupPath, map[string]string{"userCode": userCode}, cookie), 200)
}

// #72 U4: the admin decision requires the reviewed grant ETag (428 without it).
// Lookup is the only source of that strong validator.
func deviceReviewedTag(t *testing.T, h http.Handler, userCode string, cookie *http.Cookie) string {
	t.Helper()
	w := deviceJSON(t, h, deviceLookupPath, map[string]string{"userCode": userCode}, cookie)
	deviceBody(t, w, 200)
	return w.Header().Get("ETag")
}

// deviceDecide sends the reviewed precondition. A stale tag is enough for
// outcomes that the store resolves before comparing tags (409/404/500).
func deviceDecide(t *testing.T, h http.Handler, grantID, decision string, cookie *http.Cookie, tag string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"grantId": grantID, "decision": decision})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://review.example"+deviceDecisionPath, strings.NewReader(string(body)))
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", tag)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	deviceContractResponse(t, deviceDecisionPath, w)
	return w
}

// Use the disposable owner pool, as device_grant_test.go does. Moving persisted
// timestamps exercises the actual HTTP/core path without wall-clock sleeps or
// changing the production lifetime/interval constants.
func deviceTimeFixture(t *testing.T, s *Server, grantID, field string, value time.Time) {
	t.Helper()
	db := teststore.Admin(t, s.Engine.DB)
	var payload []byte
	if err := db.QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind='device_grants' AND id=$2", "default", grantID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	updated := maps.Clone(record)
	updated[field] = value.UTC().Format(time.RFC3339Nano)
	payload, err := json.Marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE records SET payload=$1 WHERE tenant_id=$2 AND kind='device_grants' AND id=$3", string(payload), "default", grantID); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceAuthorizationAndTokenLifecycle(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	ticket := deviceStart(t, h)
	if ticket["expires_in"] != float64(900) || ticket["interval"] != float64(5) || ticket["verification_uri"] != s.PublicURL+"/device" {
		t.Fatal("authorization profile differs from #40 D5")
	}
	code := ticket["device_code"].(string)
	lookup := deviceLookup(t, h, strings.ToLower(ticket["user_code"].(string)), cookie)
	if lookup["status"] != "pending" || lookup["name"] != "workstation" || lookup["platform"] != "linux" || lookup["source"] != "192.0.2.1" {
		t.Fatal("lookup did not preserve descriptive grant fields")
	}
	for i, want := range []string{"authorization_pending", "slow_down", "slow_down"} {
		body := deviceBody(t, devicePoll(t, h, code), 400)
		if body["error"] != want || (i > 0 && body["interval"] != float64(5+5*i)) {
			t.Fatal("pending polling cadence differs from RFC 8628 §3.5")
		}
	}
	grantID := lookup["grantId"].(string)
	deviceTimeFixture(t, s, grantID, "lastPoll", time.Now().Add(-15*time.Second))
	if deviceBody(t, devicePoll(t, h, code), 400)["error"] != "authorization_pending" {
		t.Fatal("accepted pending poll failed after increased interval")
	}
	decision := deviceDecide(t, h, grantID, "approve", cookie, deviceReviewedTag(t, h, ticket["user_code"].(string), cookie))
	if deviceBody(t, decision, 200)["status"] != "approved" {
		t.Fatal("approval not recorded")
	}
	nodes, err := s.Engine.ClientNodes()
	if err != nil || len(nodes) != 0 {
		t.Fatal("decision issued a credential before polling")
	}
	if deviceBody(t, deviceDecide(t, h, grantID, "deny", cookie, `"stale"`), 409)["error"] == nil {
		t.Fatal("redecision was not refused")
	}
	// Decided grants are answered immediately, even directly after a pending poll.
	body := deviceBody(t, devicePoll(t, h, code), 200)
	token := body["access_token"].(string)
	if body["token_type"] != "Bearer" || body["bundlePublicKey"] == nil || body["bundleTrust"] == nil {
		t.Fatal("missing device credential or authenticated trust bootstrap")
	}
	node, ok := s.Engine.AuthenticateClient(token)
	if !ok || node.ID != body["nodeId"] || node.Name != "workstation" || node.Platform != "linux" {
		t.Fatal("OAuth access token is not the existing device credential")
	}
	if deviceBody(t, devicePoll(t, h, code), 400)["error"] != "invalid_grant" || deviceLookup(t, h, ticket["user_code"].(string), cookie)["status"] != "consumed" {
		t.Fatal("consumed grant replay did not fail")
	}
	audits, err := s.Engine.Audits()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"client.device.approve", "client.device.enroll"} {
		found := false
		for _, audit := range audits {
			if audit.Action == action {
				found = audit.Actor.Kind == "human" && audit.Actor.Issuer == "https://issuer.example" && audit.Actor.Subject == "fixture-subject"
			}
		}
		if !found {
			t.Fatal("authenticated actor missing from decision/issuance audit")
		}
	}
}

func TestDeviceTerminalStates(t *testing.T) {
	for _, state := range []string{"deny", "expire", "unknown", "malformed"} {
		t.Run(state, func(t *testing.T) {
			s := deviceServer(t)
			h := s.Handler()
			cookie := rbacCookie(s, "human", core.RoleAdmin)
			ticket := deviceStart(t, h)
			lookup := deviceLookup(t, h, ticket["user_code"].(string), cookie)
			tag := deviceReviewedTag(t, h, ticket["user_code"].(string), cookie)
			code, want := ticket["device_code"].(string), "invalid_grant"
			switch state {
			case "deny":
				deviceBody(t, devicePoll(t, h, code), 400)
				if deviceBody(t, deviceDecide(t, h, lookup["grantId"].(string), "deny", cookie, tag), 200)["status"] != "denied" {
					t.Fatal("deny status missing")
				}
				want = "access_denied"
			case "expire":
				deviceTimeFixture(t, s, lookup["grantId"].(string), "expiresAt", time.Now().Add(-time.Second))
				want = "expired_token"
				deviceBody(t, deviceJSON(t, h, deviceLookupPath, map[string]string{"userCode": ticket["user_code"].(string)}, cookie), 404)
				deviceBody(t, deviceDecide(t, h, lookup["grantId"].(string), "approve", cookie, tag), 404)
			case "unknown":
				code = strings.Repeat("f", 64)
			case "malformed":
				code = "not-a-device-code"
			}
			if deviceBody(t, devicePoll(t, h, code), 400)["error"] != want {
				t.Fatal("incorrect terminal OAuth error")
			}
			nodes, err := s.Engine.ClientNodes()
			if err != nil || len(nodes) != 0 {
				t.Fatal("terminal error issued a device")
			}
		})
	}
}

func TestDeviceAdminCredentialClassesAndInput(t *testing.T) {
	s := deviceServer(t)
	s.PublicURL = "" // CLI sessions must be tested on their real loopback boundary.
	h := s.Handler()
	key, err := s.Engine.CreateEnrollment(context.Background(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := s.Engine.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{deviceLookupPath, deviceDecisionPath} {
		for _, tc := range []struct {
			kind  string
			role  core.Role
			token string
			want  int
		}{
			{want: 401}, {kind: "human", role: core.RoleReadOnly, want: 403},
			{kind: "human", role: core.RoleAuditor, want: 403}, {kind: "cli", role: core.RoleAdmin, want: 403},
			{kind: "other", role: core.RoleAdmin, want: 403}, {token: s.AdminToken, want: 403},
			{token: s.HookToken, want: 403}, {token: connection.Token, want: 403},
			{token: key.Code, want: 403}, {kind: "human", role: core.RoleAdmin, token: connection.Token, want: 403},
		} {
			r := httptest.NewRequest("POST", "http://127.0.0.1"+path, strings.NewReader("{"))
			r.RemoteAddr = "127.0.0.1:12345"
			r.Header.Set("Content-Type", "application/json")
			if tc.kind != "" {
				r.AddCookie(rbacCookie(s, tc.kind, tc.role))
			}
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("%s %s/%s credential denial: %d want %d", path, tc.kind, tc.role, w.Code, tc.want)
			}
			deviceContractResponse(t, path, w)
		}
	}
	s.PublicURL = "https://review.example"
	h = s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	for _, tc := range []struct{ path, body string }{
		{deviceLookupPath, "{"}, {deviceLookupPath, "{}"}, {deviceLookupPath, `{"userCode":""}`},
		{deviceLookupPath, `{"userCode":"CODE","extra":true}`}, {deviceLookupPath, `{"userCode":"CODE"} {}`},
		{deviceDecisionPath, "{}"}, {deviceDecisionPath, `{"grantId":"id","decision":"other"}`},
		{deviceDecisionPath, `{"grantId":"id","decision":"approve","actor":{"kind":"human"}}`},
	} {
		w := deviceHTTP(h, tc.path, "application/json", tc.body, cookie, "")
		deviceBody(t, w, 400)
		deviceContractResponse(t, tc.path, w)
	}
	deviceBody(t, deviceJSON(t, h, deviceLookupPath, map[string]string{"userCode": "unknown"}, cookie), 404)
	deviceBody(t, deviceDecide(t, h, "unknown", "approve", cookie, `"stale"`), 404)
	for _, path := range []string{deviceLookupPath, deviceDecisionPath} {
		w := deviceHTTP(h, path, "application/x-www-form-urlencoded", `{"userCode":"CODE"}`, cookie, "")
		deviceBody(t, w, 400)
		r := httptest.NewRequest("POST", s.PublicURL+path, strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://evil.example")
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		deviceBody(t, w, 403)
	}
}

func TestDeviceStoreFailuresRemainOperational(t *testing.T) {
	s := deviceServer(t)
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	ticket := deviceStart(t, h)
	lookup := deviceLookup(t, h, ticket["user_code"].(string), cookie)
	tag := deviceReviewedTag(t, h, ticket["user_code"].(string), cookie)
	if _, err := teststore.Admin(t, s.Engine.DB).Exec("DROP TABLE records"); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{ticket["device_code"].(string), strings.Repeat("f", 64)} {
		if deviceBody(t, devicePoll(t, h, code), 500)["error"] == "invalid_grant" {
			t.Fatal("store failure misreported as unknown code")
		}
	}
	w := deviceHTTP(h, deviceAuthorizationPath, "application/x-www-form-urlencoded", deviceForm(deviceStartForm()), nil, "")
	deviceBody(t, w, 500)
	deviceContractResponse(t, deviceAuthorizationPath, w)
	deviceBody(t, deviceJSON(t, h, deviceLookupPath, map[string]string{"userCode": ticket["user_code"].(string)}, cookie), 500)
	deviceBody(t, deviceDecide(t, h, lookup["grantId"].(string), "approve", cookie, tag), 500)
}

func TestDeviceLegacySeparationAndSecretFreeLogs(t *testing.T) {
	var logs bytes.Buffer
	originalOutput, originalSlog := log.Writer(), slog.Default()
	log.SetOutput(&logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(originalSlog); log.SetOutput(originalOutput) })
	log.Print("device log capture active")
	s := deviceServer(t)
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	ticket := deviceStart(t, h)
	lookup := deviceLookup(t, h, ticket["user_code"].(string), cookie)
	code, grantID := ticket["device_code"].(string), lookup["grantId"].(string)
	tag := deviceReviewedTag(t, h, ticket["user_code"].(string), cookie)
	if deviceHTTP(h, "/api/v1/client/enroll", "application/json", `{"code":"`+code+`","platform":"linux"}`, nil, "").Code != 403 {
		t.Fatal("setup enrollment redeemed device code")
	}
	if deviceHTTP(h, "/api/v1/client-requests/"+grantID+"/decision", "application/json", `{"decision":"approve"}`, cookie, "").Code != 400 {
		t.Fatal("legacy decision approved device grant")
	}
	r := httptest.NewRequest("GET", s.PublicURL+"/api/v1/client/requests/"+grantID, nil)
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("Authorization", "Bearer "+code)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("legacy poll redeemed device grant")
	}
	if deviceLookup(t, h, ticket["user_code"].(string), cookie)["status"] != "pending" {
		t.Fatal("legacy path changed device grant")
	}
	deviceBody(t, deviceDecide(t, h, grantID, "approve", cookie, tag), 200)
	token := deviceBody(t, devicePoll(t, h, code), 200)["access_token"].(string)
	for _, path := range []string{"/api/v1/client-enrollments", "/api/v1/client-nodes", "/api/v1/client-requests", "/api/v1/audit"} {
		w = rbacRequest(h, cookie, "GET", s.PublicURL+path, "", "192.0.2.1:12345")
		if w.Code != 200 || strings.Contains(w.Body.String(), code) || strings.Contains(w.Body.String(), token) {
			t.Fatal("management response failed or exposed credential")
		}
	}
	if !strings.Contains(logs.String(), "device log capture active") {
		t.Fatal("log capture inactive")
	}
	for _, secret := range []string{code, token, ticket["user_code"].(string)} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("device flow secret leaked into logs")
		}
	}
}
