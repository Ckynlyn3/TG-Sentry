package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRiskEventsReviewToConsole(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Register(core.Instance{ID: "fixture", Agent: "claude", SessionID: "session", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	h := s.Handler()
	login := httptest.NewRequest("POST", "http://127.0.0.1/api/v1/login", strings.NewReader(`{"token":"fixture-admin"}`))
	logged := httptest.NewRecorder()
	h.ServeHTTP(logged, login)
	if logged.Code != 200 {
		t.Fatal(logged.Body.String())
	}
	cookie := logged.Result().Cookies()[0]
	request := func(path string, admin bool, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://127.0.0.1"+path, nil)
		if admin {
			req.AddCookie(cookie)
		}
		req.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	empty := request("/api/v1/risk-events", true, "")
	if empty.Code != 200 || !strings.Contains(empty.Body.String(), `"items":[]`) || !strings.Contains(empty.Body.String(), `"next_page_token":""`) {
		t.Fatal(empty.Code, empty.Body.String())
	}
	for _, path := range []string{"/api/v1/risk-events", "/api/v1/risk-events/fixture"} {
		if w := request(path, false, ""); w.Code != 401 {
			t.Fatal("unauthenticated risk read", w.Code)
		}
		if w := request(path, false, "Bearer fixture-hook"); w.Code != 403 {
			t.Fatal("hook risk read", w.Code)
		}
	}
	// Subscribe through the same post-commit notification the SSE handler uses.
	ch := make(chan struct{}, 1)
	s.subscribers[ch] = struct{}{}
	for _, call := range []string{"first", "second"} {
		body := `{"instanceId":"fixture","callId":"` + call + `","toolName":"Bash","argumentsObj":{"command":"redis-cli FLUSHALL"},"tenant_uid":"forged"}`
		req := httptest.NewRequest("POST", "http://127.0.0.1/api/v1/reviews", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer fixture-hook")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		select {
		case <-ch:
		default:
			t.Fatal("commit did not publish SSE update")
		}
	}
	w := request("/api/v1/risk-events?page_size=1", true, "")
	var page core.RiskEventPage
	if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Items) != 1 || page.NextPageToken == "" {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	event := page.Items[0]
	if event.Data.Metadata.TenantUID != "default" || event.Data.Unmapped.TGSentry.IdentityState != "unenrolled" {
		t.Fatal(event)
	}
	detail := request("/api/v1/risk-events/"+event.ID, true, "")
	if detail.Code != 200 {
		t.Fatal(detail.Body.String())
	}
	var got core.Event
	if err = json.Unmarshal(detail.Body.Bytes(), &got); err != nil || got.ID != event.ID {
		t.Fatal(got, err)
	}
	next := request("/api/v1/risk-events?page_size=100&page_token="+page.NextPageToken, true, "")
	if err = json.Unmarshal(next.Body.Bytes(), &page); err != nil || next.Code != 200 || len(page.Items) != 1 || page.NextPageToken != "" || page.Items[0].Time.After(event.Time) {
		t.Fatal(next.Code, next.Body.String(), err)
	}
	for _, query := range []string{"?page_size=-1", "?page_size=no", "?page_size=2147483648", "?severity=bogus", "?category=bogus", "?page_token=bogus"} {
		if bad := request("/api/v1/risk-events"+query, true, ""); bad.Code != 400 || !strings.Contains(bad.Body.String(), `"error"`) {
			t.Fatal(query, bad.Code, bad.Body.String())
		}
	}
	if w = request("/api/v1/risk-events/missing", true, ""); w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("/api/v1/risk-events?agent=absent", true, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("/api/v1/risk-events?page_size=0", true, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request("/api/v1/risk-events?page_size=1000", true, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if err = e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/risk-events", "/api/v1/risk-events/" + event.ID} {
		if w = request(path, true, ""); w.Code != 500 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
