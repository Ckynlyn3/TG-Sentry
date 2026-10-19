package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestSetupKeyAPIAndSecretFreeLogs(t *testing.T) {
	var logs bytes.Buffer
	originalOutput, originalSlog := log.Writer(), slog.Default()
	log.SetOutput(&logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(originalSlog); log.SetOutput(originalOutput) })
	log.Print("enrollment log capture active")
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := New(e, fstest.MapFS{}, "admin-fixture", "legacy-fixture", t.TempDir())
	s.PublicURL = "https://review.example"
	h := s.Handler()
	call := func(method, path, token, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://review.example"+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:12345"
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
	login := call("POST", "/api/v1/login", "", `{"token":"admin-fixture"}`, nil)
	cookie := login.Result().Cookies()[0]
	for _, method := range []string{"GET", "POST", "DELETE"} {
		path := "/api/v1/client-enrollments"
		if method == "DELETE" {
			path += "/missing"
		}
		if w := call(method, path, "", `{}`, nil); w.Code != 401 {
			t.Fatal("setup-key management allowed without admin")
		}
	}
	for _, body := range []string{`{`, `{"type":"bad"}`, `{"maxUses":-1}`, `{"expiresAt":"bad"}`} {
		if w := call("POST", "/api/v1/client-enrollments", "", body, cookie); w.Code != 400 {
			t.Fatal("invalid options accepted")
		}
	}
	w := call("POST", "/api/v1/client-enrollments", "", `{"name":"fleet","type":"reusable","maxUses":2}`, cookie)
	var key core.EnrollmentCode
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &key) != nil || key.ID == "" || len(key.Code) != 64 {
		t.Fatal("setup key creation failed")
	}
	enroll := func(code string) *httptest.ResponseRecorder {
		return call("POST", "/api/v1/client/enroll", "", `{"code":"`+code+`","platform":"linux"}`, nil)
	}
	var first, second core.ClientConnection
	w = enroll(key.Code)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &first) != nil || len(first.Token) != 64 {
		t.Fatal("first enrollment failed")
	}
	w = enroll(key.Code)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &second) != nil || first.Token == second.Token {
		t.Fatal("device credential not unique")
	}
	if w := enroll(key.Code); w.Code != 403 {
		t.Fatal("usage limit ignored over HTTP")
	}
	if w := call("GET", "/api/v1/client-enrollments", first.Token, "", nil); w.Code != 403 {
		t.Fatal("device can manage setup keys")
	}
	for _, path := range []string{"client-enrollments", "client-nodes", "audit"} {
		w := call("GET", "/api/v1/"+path, "", "", cookie)
		if w.Code != 200 || strings.Contains(w.Body.String(), key.Code) || strings.Contains(w.Body.String(), first.Token) || strings.Contains(w.Body.String(), second.Token) {
			t.Fatal("management response failed or leaked secret")
		}
	}
	register := func(c core.ClientConnection, id string) *httptest.ResponseRecorder {
		return call("POST", "/api/v1/instances", c.Token, `{"id":"`+id+`","sessionId":"session","cwd":"/remote/project","agent":"claude","hookVersion":"`+core.Version+`","nodeId":"`+c.NodeID+`"}`, nil)
	}
	if w := register(first, "first"); w.Code != 200 {
		t.Fatal("device could not call bridge API")
	}
	if w := call("DELETE", "/api/v1/client-nodes/"+first.NodeID, "", "", cookie); w.Code != 200 {
		t.Fatal("device revoke failed")
	}
	if w := call("POST", "/api/v1/instances/first/heartbeat", first.Token, `{}`, nil); w.Code != 403 {
		t.Fatal("revoked device accepted next call")
	}
	if w := register(second, "second"); w.Code != 200 {
		t.Fatal("unrelated device rejected")
	}
	if w := call("DELETE", "/api/v1/client-enrollments/"+key.ID, "", "", cookie); w.Code != 200 {
		t.Fatal("setup key revoke failed")
	}
	if w := enroll(key.Code); w.Code != 403 {
		t.Fatal("revoked setup key accepted")
	}
	if w := call("DELETE", "/api/v1/client-enrollments/missing", "", "", cookie); w.Code != 404 {
		t.Fatal("missing key not reported")
	}
	// A past timestamp is rejected by the public creation contract too.
	body := `{"expiresAt":"` + time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) + `"}`
	if w := call("POST", "/api/v1/client-enrollments", "", body, cookie); w.Code != 400 {
		t.Fatal("past expiry accepted")
	}
	if !strings.Contains(logs.String(), "enrollment log capture active") {
		t.Fatal("log capture not active")
	}
	for _, secret := range []string{key.Code, first.Token, second.Token} {
		if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), secret[:32]) {
			t.Fatal("credential substring leaked to logs")
		}
	}
}
