package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestSessionSummariesHTTP(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	now := time.Date(2026, 10, 18, 0, 0, 0, 1, time.UTC)
	secret := "fixture-content-must-not-leak"
	for _, fixture := range []struct {
		tenant, kind, id string
		value            any
	}{
		{"default", "instances", "instance", core.Instance{ID: "instance", SessionID: "stored-key", Agent: "claude", NodeID: "device", StartedAt: now, Cwd: secret}},
		{"default", "reviews", "review", core.Review{ID: "review", SessionID: "stored-key", Agent: "cursor", CreatedAt: now, ReviewInput: core.ReviewInput{Arguments: map[string]any{"secret": secret}, UserMessage: secret, Context: secret}, Result: secret, ModelContext: &secret}},
		{"default", "client_nodes", "device", map[string]any{"id": "device", "name": "Laptop", "tokenHash": secret}},
		{"other", "instances", "other-instance", core.Instance{ID: "other-instance", SessionID: "foreign", StartedAt: now}},
		{"other", "reviews", "other-review", core.Review{ID: "other-review", SessionID: "stored-key", Agent: "foreign-agent", CreatedAt: now}},
		{"other", "client_nodes", "device", core.ClientNode{ID: "device", Name: "foreign-name"}},
	} {
		b, err := json.Marshal(fixture.value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4)", fixture.tenant, fixture.kind, fixture.id, string(b)); err != nil {
			t.Fatal(err)
		}
	}
	s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	h := s.Handler()
	cookie := rbacCookie(s, "human", core.RoleAdmin)
	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/"+path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, allowed := range []bool{true, false} {
		s.contentAllowedOverride = func(*http.Request) bool { return allowed }
		for _, q := range []url.Values{{}, {"agent": {"cursor"}}, {"nodeId": {"device"}}, {"sessionKey": {"stored-key"}}, {"from": {"2026-10-18T02:00:00.000000001+02:00"}, "to": {"2026-10-18"}}} {
			w := request("session-summaries?" + q.Encode())
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			var p core.SessionSummaryPage
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if p.Total != 1 || len(p.Items) != 1 || p.Items[0].CallCount != 1 || len(p.Items[0].Agents) != 2 || p.Items[0].Devices[0].Name != "Laptop" || p.Items[0].User != nil {
				t.Fatalf("tenant/summary metadata: %+v", p)
			}
			for _, forbidden := range []string{secret, "foreign", "argumentsObj", "userMessage", "context", "result", "modelContext", "tokenHash"} {
				if strings.Contains(w.Body.String(), forbidden) {
					t.Errorf("summary exposed %q", forbidden)
				}
			}
			var raw map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			item := raw["items"].([]any)[0].(map[string]any)
			if v, ok := item["user"]; !ok || v != nil {
				t.Fatal("user must be explicit null")
			}
		}
	}
	// This older endpoint remains Instance[], not a summary/page response.
	w := request("sessions")
	var instances []core.Instance
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &instances) != nil || len(instances) != 1 || instances[0].ID != "instance" {
		t.Fatal("/sessions changed", w.Code, w.Body)
	}
	for _, q := range []string{"size=0", "size=101", "size=-1", "size=x", "size=", "page=0", "page=-1", "page=x", "page=999999999999999999999", "page=9223372036854775807&size=100", "from=bad", "to=bad", "from=2026-10-20&to=2026-10-18", "from=2026-10-18T00%3A00%3A01Z&to=2026-10-18T02%3A00%3A00%2B02%3A00"} {
		if w := request("session-summaries?" + q); w.Code != 400 {
			t.Errorf("invalid query %s: %d", q, w.Code)
		}
	}
	for _, q := range []string{"sessionKey=foreign", "agent=foreign-agent", "nodeId=unknown", "page=2&size=1"} {
		w := request("session-summaries?" + q)
		var p core.SessionSummaryPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || len(p.Items) != 0 || p.Items == nil {
			t.Fatal("empty/tenant filter", q, w.Code, w.Body)
		}
	}
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	w = request("session-summaries")
	if w.Code != 500 || strings.Contains(w.Body.String(), "database") {
		t.Fatal("store failure not sanitized", w.Code, w.Body)
	}
}

func TestSessionSummariesCallerDenials(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	code, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	device, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	h := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir()).Handler()
	for _, tc := range []struct {
		auth   string
		status int
	}{{"", 401}, {"Bearer fixture-hook", 403}, {"Bearer " + device.Token, 403}} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:18790/api/v1/session-summaries", nil)
		r.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("denial status %d want %d", w.Code, tc.status)
		}
	}
}
