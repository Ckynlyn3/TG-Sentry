package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// Fixed synthetic dates exercise the plan's named UTC-alignment exception.
var statsNow = time.Date(2026, 10, 19, 12, 30, 0, 0, time.UTC)

func sqliteStatsEngine(t *testing.T) *Engine {
	t.Helper()
	db, err := openSQLite(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Engine{DB: db, clock: func() time.Time { return statsNow }}
}

func statsEvent(id string, at time.Time, agent string, severity, action, disposition int, categories ...string) Event {
	return Event{ID: id, Source: "/fixture", Type: "tg.sentry.risk.v1", Time: at,
		Data: EventData{Time: at.UnixMilli(), SeverityID: severity, Actor: EventActor{AppUID: agent},
			EventControl: &EventControl{ActionID: action, DispositionID: disposition}, FindingInfo: &EventFinding{Types: categories}}}
}

func seedStats(t *testing.T, e *Engine) {
	t.Helper()
	e.clock = func() time.Time { return statsNow }
	events := []Event{
		statsEvent("old", statsNow.AddDate(-3, 0, 0), "old-agent", 0, 0, 0),
		statsEvent("from-7d", statsNow.Add(-7*24*time.Hour), "agent-a", 4, 2, 2, "category::behavior"),
		statsEvent("before-24h", statsNow.Add(-24*time.Hour-time.Millisecond), "agent-b", 3, 3, 19, "category::high-risk-ops"),
		statsEvent("from-24h", statsNow.Add(-24*time.Hour), "agent-a", 4, 2, 2, "category::behavior", "category::prompt-attack"),
		statsEvent("reject", statsNow.Add(-time.Hour), "", 0, 0, 0),
		statsEvent("monitor", statsNow.Add(-time.Minute), "agent-c", 1, 3, 17, "category::sensitive-info"),
		statsEvent("at-to", statsNow, "agent-a", 4, 2, 2, "category::behavior"),
		statsEvent("future", statsNow.AddDate(2, 0, 0), "", 0, 3, 19),
	}
	duplicate := statsEvent("identical", statsNow.Add(-time.Minute), "agent-b", 4, 3, 19, "category::behavior", "category::behavior", "category::prompt-attack")
	events = append(events, duplicate, duplicate)
	for _, agent := range []string{"agent-d", "agent-e", "agent-f", "agent-g"} {
		events = append(events, statsEvent(agent, statsNow.Add(-2*time.Hour), agent, 5, 2, 2, "category::supply-chain"))
	}
	nonRisk := statsEvent("not-risk", statsNow.Add(-time.Minute), "ignored", 4, 2, 2)
	nonRisk.Type = "tg.sentry.access.v1"
	events = append(events, nonRisk)
	if err := e.put("audit", "stats-fixture", Audit{ID: "stats-fixture", Events: events}); err != nil {
		t.Fatal(err)
	}
	// Same CloudEvents identity in a different audit is another occurrence too.
	if err := e.put("audit", "stats-second", Audit{ID: "stats-second", Events: []Event{statsEvent("from-24h", statsNow.Add(-24*time.Hour), "agent-a", 4, 2, 2, "category::behavior")}}); err != nil {
		t.Fatal(err)
	}
}

func statsFilters() []RiskEventFilter {
	filters := []RiskEventFilter{{}, {Agent: "agent-a"}, {Agent: "' OR 1=1 --"}, {Severity: "unknown"}, {Severity: "low"}, {Severity: "medium"}, {Severity: "high"}, {Severity: "critical"}}
	for _, category := range []string{"category::behavior", "category::prompt-attack", "category::sensitive-info", "category::high-risk-ops", "category::supply-chain"} {
		filters = append(filters, RiskEventFilter{Category: category}, RiskEventFilter{Category: category, Severity: "high", Agent: "agent-a"})
	}
	return filters
}

func assertStatsReconcile(t *testing.T, e *Engine) {
	t.Helper()
	events, err := e.riskEvents()
	if err != nil {
		t.Fatal(err)
	}
	for _, window := range []string{"24h", "7d", "all"} {
		for _, filter := range statsFilters() {
			t.Run(window+fmt.Sprint(filter), func(t *testing.T) {
				got, err := e.RiskStats(context.Background(), filter, window)
				if err != nil {
					t.Fatal(err)
				}
				bounded := filter
				bounded.From, bounded.To = &got.From, &got.To
				var total, block, alert, other, unknown, unattributed, uncategorized, future int64
				for _, event := range events {
					if riskEventMatches(event, filter) && event.Data.Time >= got.To {
						future++
					}
					if !riskEventMatches(event, bounded) {
						continue
					}
					total++
					switch {
					case event.Data.ActionID == 2 && event.Data.DispositionID == 2:
						block++
					case event.Data.ActionID == 3 && event.Data.DispositionID == 19:
						alert++
					default:
						other++
					}
					if event.Data.SeverityID == 0 {
						unknown++
					}
					if event.Data.Actor.AppUID == "" {
						unattributed++
					}
					if event.Data.FindingInfo == nil || len(event.Data.FindingInfo.Types) == 0 {
						uncategorized++
					}
				}
				if got.Totals.Total != total || got.Totals.Block != block || got.Totals.Alert != alert || got.Totals.Other != other || got.Totals.SeverityUnknown != unknown || got.Totals.Unattributed != unattributed || got.Uncategorized != uncategorized || got.Totals.FutureExcluded != future {
					t.Fatalf("counts: %+v uncategorized=%d; want total=%d block=%d alert=%d other=%d unknown=%d unattributed=%d uncategorized=%d future=%d", got.Totals, got.Uncategorized, total, block, alert, other, unknown, unattributed, uncategorized, future)
				}
				var sum RiskVerdictCounts
				for i, bucket := range got.Buckets {
					sum.Block += bucket.Block
					sum.Alert += bucket.Alert
					sum.Other += bucket.Other
					if bucket.Start < got.From || bucket.End > got.To || bucket.Start >= bucket.End {
						t.Fatal("unclipped bucket", bucket)
					}
					if i > 0 && got.Buckets[i-1].End != bucket.Start {
						t.Fatal("bucket gap", bucket)
					}
					nominal := time.UnixMilli(bucket.Start).UTC().Truncate(time.Duration(got.BucketMS) * time.Millisecond).UnixMilli()
					if bucket.Partial != (nominal < got.To && got.To < nominal+got.BucketMS) {
						t.Fatal("partial must use nominal interval", bucket)
					}
				}
				if sum.Block != block || sum.Alert != alert || sum.Other != other {
					t.Fatal("bucket sums", sum, got.Totals)
				}
				if got.GeneratedAt != statsNow.UnixMilli() || got.To != got.GeneratedAt {
					t.Fatal("clock", got)
				}
			})
		}
	}
}

func TestRiskStatsReconciliation(t *testing.T) {
	e := sqliteStatsEngine(t)
	seedStats(t, e)
	assertStatsReconcile(t, e)
}

func TestRiskStatsBucketsAndRanking(t *testing.T) {
	e := sqliteStatsEngine(t)
	seedStats(t, e)
	for _, tc := range []struct {
		window           string
		aligned, clipped int
	}{{"24h", 24, 25}, {"7d", 7, 8}} {
		for _, exact := range []bool{false, true} {
			now := statsNow
			if exact {
				now = now.Truncate(24 * time.Hour)
			}
			e.clock = func() time.Time { return now }
			got, err := e.RiskStats(context.Background(), RiskEventFilter{}, tc.window)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.clipped
			if exact {
				want = tc.aligned
			}
			if len(got.Buckets) != want || got.Buckets[0].Start != got.From || got.Buckets[len(got.Buckets)-1].End != got.To {
				t.Fatal("bucket coverage", got)
			}
			for i, b := range got.Buckets {
				if b.Partial != (!exact && i == len(got.Buckets)-1) {
					t.Fatal("partial", b)
				}
			}
		}
	}
	e.clock = func() time.Time { return statsNow }
	got, err := e.RiskStats(context.Background(), RiskEventFilter{}, "24h")
	if err != nil {
		t.Fatal(err)
	}
	agents := []string{}
	for _, a := range got.TopAgents {
		agents = append(agents, a.Agent)
	}
	if !reflect.DeepEqual(agents, []string{"agent-a", "agent-b", "agent-c", "agent-d", "agent-e"}) {
		t.Fatal("agent ranking", got.TopAgents)
	}
	categories := []string{}
	for _, c := range got.ByCategory {
		categories = append(categories, c.Category)
	}
	if !reflect.DeepEqual(categories, []string{"category::behavior", "category::supply-chain", "category::prompt-attack", "category::sensitive-info"}) {
		t.Fatal("category ranking", got.ByCategory)
	}
	if got.TopAgents[0].LastSeen != statsNow.Add(-24*time.Hour).UnixMilli() {
		t.Fatal("last seen", got.TopAgents)
	}
}

func TestRiskStatsIdenticalOccurrences(t *testing.T) {
	e := sqliteStatsEngine(t)
	event := statsEvent("same", statsNow.Add(-time.Minute), "agent", 4, 2, 2, "category::behavior", "category::behavior", "category::prompt-attack")
	if err := e.put("audit", "duplicates", Audit{Events: []Event{event, event}}); err != nil {
		t.Fatal(err)
	}
	got, err := e.RiskStats(context.Background(), RiskEventFilter{Category: "category::behavior"}, "all")
	if err != nil || got.Totals.Total != 2 || len(got.ByCategory) != 2 {
		t.Fatal(got, err)
	}
	for _, c := range got.ByCategory {
		if c.Block != 2 {
			t.Fatal("category dedup lost occurrences", c)
		}
	}
}

func TestRiskStatsEmptyFutureAndErrors(t *testing.T) {
	e := sqliteStatsEngine(t)
	for _, future := range []bool{false, true} {
		if future {
			if err := e.put("audit", "future", Audit{Events: []Event{statsEvent("future", statsNow, "", 0, 0, 0)}}); err != nil {
				t.Fatal(err)
			}
		}
		for _, window := range []string{"24h", "7d", "all"} {
			got, err := e.RiskStats(context.Background(), RiskEventFilter{}, window)
			if err != nil || got.Totals.Total != 0 || len(got.Buckets) != 0 || got.Buckets == nil || got.ByCategory == nil || got.TopAgents == nil {
				t.Fatal(got, err)
			}
			if window == "all" && got.From != got.To {
				t.Fatal("empty bounds", got)
			}
			if (got.Totals.FutureExcluded == 1) != future {
				t.Fatal(got.Totals)
			}
		}
	}
	for _, tc := range []struct {
		filter RiskEventFilter
		window string
	}{{RiskEventFilter{}, "30d"}, {RiskEventFilter{Severity: "bad"}, "all"}, {RiskEventFilter{Category: "bad"}, "all"}} {
		if _, err := e.RiskStats(context.Background(), tc.filter, tc.window); !errors.Is(err, ErrRiskEventQuery) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := e.RiskStats(ctx, RiskEventFilter{}, "all")
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, RiskStats{}) {
		t.Fatal("partial on cancellation", got, err)
	}
	if err = e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err = e.RiskStats(context.Background(), RiskEventFilter{}, "all"); err == nil || !reflect.DeepEqual(got, RiskStats{}) {
		t.Fatal(got, err)
	}
}

func TestRiskStatsZeroFilledWindowWithOnlyOldOccurrences(t *testing.T) {
	e := sqliteStatsEngine(t)
	if err := e.put("audit", "old", Audit{Events: []Event{statsEvent("old", statsNow.AddDate(-3, 0, 0), "agent", 4, 2, 2)}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		window  string
		buckets int
	}{{"24h", 25}, {"7d", 8}} {
		got, err := e.RiskStats(t.Context(), RiskEventFilter{}, tc.window)
		if err != nil || got.Totals.Total != 0 || len(got.Buckets) != tc.buckets {
			t.Fatal("empty selection must retain its zero-filled interval", got, err)
		}
	}
}

func TestRiskStatsQueryFailure(t *testing.T) {
	e := sqliteStatsEngine(t)
	if _, err := e.DB.Exec("DROP TABLE records"); err != nil {
		t.Fatal(err)
	}
	if got, err := e.RiskStats(context.Background(), RiskEventFilter{}, "all"); err == nil || !reflect.DeepEqual(got, RiskStats{}) {
		t.Fatal(got, err)
	}
}

func TestRiskEventExplicitBoundsAndCursorCompatibility(t *testing.T) {
	e := sqliteStatsEngine(t)
	events := []Event{}
	for i := 0; i < 3; i++ {
		events = append(events, statsEvent(fmt.Sprint(i), statsNow.Add(time.Duration(i-3)*time.Hour), "agent", 4, 2, 2))
	}
	if err := e.put("audit", "paging", Audit{Events: events}); err != nil {
		t.Fatal(err)
	}
	event := events[0]
	filter := RiskEventFilter{Severity: "high", Agent: "agent"}
	legacy, _ := json.Marshal(struct {
		ID, Source string
		Filter     struct{ Severity, Category, Agent string }
	}{event.ID, event.Source, struct{ Severity, Category, Agent string }{filter.Severity, filter.Category, filter.Agent}})
	sum := sha256.Sum256(legacy)
	if got := riskPageToken(event, filter); got != hex.EncodeToString(sum[:]) {
		t.Fatal("unwindowed cursor changed", got)
	}
	from, to := events[0].Data.Time, statsNow.UnixMilli()
	filter.From, filter.To = &from, &to
	token := ""
	ids := []string{}
	for {
		page, err := e.RiskEvents(1, token, filter)
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range page.Items {
			ids = append(ids, ev.ID)
		}
		token = page.NextPageToken
		e.clock = func() time.Time { return statsNow.Add(24 * time.Hour) }
		if token == "" {
			break
		}
	}
	if !reflect.DeepEqual(ids, []string{"2", "1", "0"}) {
		t.Fatal(ids)
	}
	filter.To = &from
	page, err := e.RiskEvents(1, "", filter)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("half open empty range", page, err)
	}
	filter.From = &to
	if _, err = e.RiskEvents(1, "", filter); !errors.Is(err, ErrRiskEventQuery) {
		t.Fatal("inverted bounds accepted", err)
	}
}
