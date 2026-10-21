package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"aegishook/internal/core"
	"aegishook/internal/teststore"
)

func TestConfirmedBlockResultRouteToRiskEvents(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, instance := range []string{"fixture", "other"} {
		if err := e.Register(core.Instance{ID: instance, Agent: "claude", SessionID: "session", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := e.Submit(core.ReviewInput{InstanceID: "fixture", CallID: "blocked", ToolName: "Bash", Arguments: map[string]any{"command": "redis-cli FLUSHALL"}})
	if err != nil || r.Decision != "reject" {
		t.Fatal(r, err)
	}
	s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	h := s.Handler()
	for _, tc := range []struct {
		instance, state, auth string
		code                  int
	}{
		{"fixture", "not_executed", "", 401},
		{"other", "not_executed", "Bearer fixture-hook", 409},
		{"fixture", "succeeded", "Bearer fixture-hook", 409},
		{"fixture", "failed", "Bearer fixture-hook", 409},
		{"fixture", "invalid", "Bearer fixture-hook", 409},
		{"fixture", "not_executed", "Bearer fixture-hook", 200},
		{"fixture", "not_executed", "Bearer fixture-hook", 200},
	} {
		body := `{"instanceId":"` + tc.instance + `","state":"` + tc.state + `","result":"not-retained"}`
		req := httptest.NewRequest("POST", "http://127.0.0.1/api/v1/reviews/"+r.ID+"/result", strings.NewReader(body))
		req.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.code {
			t.Fatalf("%s/%s: status=%d want=%d", tc.instance, tc.state, w.Code, tc.code)
		}
	}
	req := httptest.NewRequest("GET", "http://127.0.0.1/api/v1/risk-events", nil)
	req.AddCookie(rbacCookie(s, "human", core.RoleAuditor))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var page core.RiskEventPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Items) != 2 {
		t.Fatal("expected immutable original and one update", w.Code, err)
	}
	original, update := page.Items[1], page.Items[0]
	if original.Data.ActionID != 0 || original.Data.DispositionID != 0 || update.Data.ActionID != 2 || update.Data.DispositionID != 2 || update.Data.ActivityID != 2 || update.Data.TypeUID != 200402 || update.Data.FindingInfo.UID != original.Data.FindingInfo.UID || update.ID == original.ID {
		t.Fatal("wrong result-to-console projection", page)
	}
}
