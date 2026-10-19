package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
)

func callsLogin(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	r := httptest.NewRequest("POST", "http://127.0.0.1:18790/api/v1/login", strings.NewReader(`{"token":"fixture-admin"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || len(w.Result().Cookies()) != 1 {
		t.Fatal("console login failed", w.Code)
	}
	return w.Result().Cookies()[0]
}

func TestCallsSessionKeyExactMatch(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	raw := "sha256:" + strings.Repeat("a", 64)
	var first core.Review
	for _, instance := range []string{"first", "second"} {
		session := raw
		if instance == "second" {
			session = first.SessionID
		}
		if err := e.Register(core.Instance{ID: instance, SessionID: session, Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
			t.Fatal(err)
		}
		r, err := e.Submit(core.ReviewInput{InstanceID: instance, CallID: "call", ToolName: "read", Arguments: map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		if instance == "first" {
			first = r
		}
	}
	// A matching session key in another tenant must not enter the count or items.
	payload, err := json.Marshal(core.Review{ID: "foreign", SessionID: first.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('other','reviews','foreign',$1)", string(payload)); err != nil {
		t.Fatal(err)
	}
	h := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir()).Handler()
	cookie := callsLogin(t, h)
	for _, tc := range []struct {
		query, want string
		status      int
	}{
		{"sessionKey=" + url.QueryEscape(first.SessionID), "first", 200},
		{"sessionId=" + url.QueryEscape(raw), "first", 200},
		{"sessionId=" + url.QueryEscape(first.SessionID), "second", 200},
		{"sessionKey=" + url.QueryEscape(raw), "", 200},
		{"sessionKey=" + url.QueryEscape(first.SessionID) + "&sessionId=" + url.QueryEscape(raw), "", 400},
		{"sessionKey=&sessionId=" + url.QueryEscape(raw), "", 400},
	} {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/calls?"+tc.query, nil)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if tc.status != 200 {
				return
			}
			var page core.ReviewPage
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal("sessionKey must select paginated response", err)
			}
			if tc.want == "" {
				if page.Total != 0 || len(page.Items) != 0 {
					t.Fatal("nonmatching exact key returned reviews")
				}
			} else if page.Total != 1 || len(page.Items) != 1 || page.Items[0].InstanceID != tc.want {
				t.Fatal("incorrect exact session match/count")
			}
		})
	}
}
