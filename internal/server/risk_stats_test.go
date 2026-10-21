package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const riskStatsSentinel = "RISK-STATS-CONTENT-SENTINEL"

// Persist occurrences, not precomputed totals; the same fixture drives HTTP
// reconciliation and sentinel checks on both SQLite and the disposable PG gate.
func seedServerRiskStats(t *testing.T, s *Server) []core.Event {
	t.Helper()
	now := time.Now().UTC()
	event := func(id string, at time.Time, agent string, severity, action, disposition int, categories ...string) core.Event {
		return core.Event{ID: id, Source: "/stats-fixture", Type: "tg.sentry.risk.v1", Time: at,
			Data: core.EventData{Time: at.UnixMilli(), SeverityID: severity, Actor: core.EventActor{AppUID: agent},
				EventControl: &core.EventControl{ActionID: action, DispositionID: disposition}, FindingInfo: &core.EventFinding{Types: categories}}}
	}
	events := []core.Event{
		event("block", now.Add(-time.Hour), "agent-a", 4, 2, 2, "category::behavior"),
		event("alert", now.Add(-time.Hour), "agent-b", 4, 3, 19, "category::behavior", "category::prompt-attack"),
		event("reject", now.Add(-time.Hour), "", 0, 0, 0),
		event("monitor", now.Add(-time.Hour), "agent-a", 1, 3, 17, "category::sensitive-info"),
		event("old", now.Add(-7*24*time.Hour-time.Hour), "agent-a", 4, 2, 2, "category::behavior"),
		event("future", now.AddDate(1, 0, 0), "agent-a", 4, 2, 2, "category::behavior"),
	}
	for _, tenant := range []string{"default", "foreign"} {
		tenantEvents := events
		if tenant == "foreign" {
			tenantEvents = []core.Event{event("foreign-risk", now.Add(-time.Hour), "foreign-agent", 5, 3, 19, "category::supply-chain")}
		}
		b, err := json.Marshal(map[string]any{"id": "stats-fixture", "events": tenantEvents, "detail": riskStatsSentinel})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = teststore.Admin(t, s.Engine.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES($1,'audit','stats-fixture',$2)", tenant, string(b)); err != nil {
			t.Fatal(err)
		}
	}
	return events
}

func directRiskStats(s *Server, target string, ctx context.Context) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1/api/v1/risk-events/stats"+target, nil).WithContext(ctx)
	w := httptest.NewRecorder()
	s.riskStats(w, r)
	return w
}

func TestRiskStatsHandlerWindowsAndContent(t *testing.T) {
	s := rbacStoreServer(t)
	seedServerRiskStats(t, s)
	for _, tc := range []struct {
		query, window                      string
		total, block, alert, other, future int64
	}{
		{"", "7d", 4, 1, 1, 2, 1},
		{"?window=24h", "24h", 4, 1, 1, 2, 1},
		{"?window=7d", "7d", 4, 1, 1, 2, 1},
		{"?window=all", "all", 5, 2, 1, 2, 1},
		{"?severity=high&category=category::behavior&agent=agent-a", "7d", 1, 1, 0, 0, 1},
		{"?agent=absent", "7d", 0, 0, 0, 0, 0},
	} {
		t.Run(tc.query, func(t *testing.T) {
			before := time.Now().UnixMilli()
			w := directRiskStats(s, tc.query, context.Background())
			var got core.RiskStats
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if got.Window != tc.window || got.Totals.Total != tc.total || got.Totals.Block != tc.block || got.Totals.Alert != tc.alert || got.Totals.Other != tc.other || got.Totals.FutureExcluded != tc.future {
				t.Fatalf("wrong stats: %+v", got)
			}
			if got.GeneratedAt != got.To || got.To < before || got.To > time.Now().UnixMilli() {
				t.Fatal("response did not use request-time bounds")
			}
			for _, forbidden := range []string{riskStatsSentinel, "argumentsObj", "userMessage", "modelInput", "modelContext", "foreign", `"name":`} {
				if strings.Contains(w.Body.String(), forbidden) {
					t.Fatalf("aggregate leaked %s", forbidden)
				}
			}
		})
	}
}

func TestRiskStatsHandlerEmptyAndFailures(t *testing.T) {
	s := rbacStoreServer(t)
	w := directRiskStats(s, "?window=all", context.Background())
	var got core.RiskStats
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.From != got.To || got.Buckets == nil || len(got.Buckets) != 0 || got.ByCategory == nil || got.TopAgents == nil {
		t.Fatalf("empty shape: %d %s", w.Code, w.Body.String())
	}
	for _, query := range []string{"window=30d", "window=SECRET", "severity=SECRET", "category=SECRET"} {
		w = directRiskStats(s, "?"+query, context.Background())
		if w.Code != 400 || w.Body.String() != `{"error":"invalid risk event query or page token"}`+"\n" {
			t.Fatalf("invalid query must be static: %d %s", w.Code, w.Body.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = directRiskStats(s, "", ctx)
	if w.Code != 500 || w.Body.String() != `{"error":"risk stats unavailable"}`+"\n" {
		t.Fatalf("cancel returned partial totals: %d %s", w.Code, w.Body.String())
	}
	if err := s.Engine.DB.Close(); err != nil {
		t.Fatal(err)
	}
	w = directRiskStats(s, "", context.Background())
	if w.Code != 500 || w.Body.String() != `{"error":"risk stats unavailable"}`+"\n" {
		t.Fatalf("store failure: %d %s", w.Code, w.Body.String())
	}
}

func TestRiskEventsExplicitBoundsHandler(t *testing.T) {
	s := rbacStoreServer(t)
	events := seedServerRiskStats(t, s)
	from := events[0].Data.Time
	to := from + 1 // One millisecond: data.time's documented precision.
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"from=" + strconv.FormatInt(from, 10) + "&to=" + strconv.FormatInt(to, 10), 4},
		{"from=" + strconv.FormatInt(from, 10) + "&to=" + strconv.FormatInt(from, 10), 0},
		{"to=" + strconv.FormatInt(from, 10), 1},
		{"from=" + strconv.FormatInt(from, 10), 5},
	} {
		w := httptest.NewRecorder()
		s.riskEvents(w, httptest.NewRequest("GET", "/api/v1/risk-events?"+tc.query, nil))
		var page core.RiskEventPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != tc.want {
			t.Fatalf("bounds %s: %d %s", tc.query, w.Code, w.Body.String())
		}
	}
	for _, query := range []string{"from=SECRET", "to=SECRET", "from=9223372036854775808", "to=9223372036854775808", "from=2&to=1", "from=", "to="} {
		w := httptest.NewRecorder()
		s.riskEvents(w, httptest.NewRequest("GET", "/api/v1/risk-events?"+query, nil))
		if w.Code != 400 || w.Body.String() != `{"error":"invalid risk event query or page token"}`+"\n" {
			t.Fatalf("invalid bounds must be static: %d %s", w.Code, w.Body.String())
		}
	}
	// The optional bounds bind page tokens; no relative window moves on page 2.
	q := url.Values{"from": {strconv.FormatInt(from, 10)}, "to": {strconv.FormatInt(to, 10)}, "page_size": {"1"}}
	var page core.RiskEventPage
	for count := 0; ; count++ {
		w := httptest.NewRecorder()
		s.riskEvents(w, httptest.NewRequest("GET", "/api/v1/risk-events?"+q.Encode(), nil))
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
			t.Fatalf("page %d: %d %s", count, w.Code, w.Body.String())
		}
		if page.NextPageToken == "" {
			if count+1 != 4 {
				t.Fatalf("walked %d occurrences", count+1)
			}
			break
		}
		q.Set("page_token", page.NextPageToken)
	}
}
