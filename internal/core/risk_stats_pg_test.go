package core

import (
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestRiskStatsPostgresParityAndTenantIsolation(t *testing.T) {
	pg := postgresEngine(t)
	sqlite := sqliteStatsEngine(t)
	seedStats(t, pg)
	seedStats(t, sqlite)
	foreign, err := json.Marshal(Audit{Events: []Event{statsEvent("foreign", statsNow.Add(-time.Minute), "foreign-agent", 4, 2, 2, "category::behavior")}})
	if err != nil {
		t.Fatal(err)
	}
	admin := teststore.Admin(t, pg.DB)
	if _, err = admin.Exec("INSERT INTO records VALUES ('other','audit','foreign',$1)", string(foreign)); err != nil {
		t.Fatal(err)
	}
	// A restrictive policy makes isolation/read-only options executable assertions,
	// rather than a test that merely assumes BeginTx was configured as requested.
	if _, err = admin.Exec(`CREATE POLICY stats_snapshot ON records AS RESTRICTIVE FOR SELECT USING
  (current_setting('transaction_isolation')='repeatable read' AND current_setting('transaction_read_only')='on')`); err != nil {
		t.Fatal(err)
	}
	for _, window := range []string{"24h", "7d", "all"} {
		for _, filter := range statsFilters() {
			want, err := sqlite.RiskStats(t.Context(), filter, window)
			if err != nil {
				t.Fatal(err)
			}
			got, err := pg.RiskStats(t.Context(), filter, window)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %+v: PG=%+v SQLite=%+v err=%v", window, filter, got, want, err)
			}
		}
	}
	if _, err = admin.Exec("DROP POLICY stats_snapshot ON records"); err != nil {
		t.Fatal(err)
	}
	assertStatsReconcile(t, pg)
}

func TestRiskStatsPostgresCancellationReleasesConnection(t *testing.T) {
	e := postgresEngine(t)
	seedStats(t, e)
	var pid int
	if err := e.DB.QueryRow("SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	admin := teststore.Admin(t, e.DB)
	locker, err := admin.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback()
	if _, err = locker.ExecContext(t.Context(), "LOCK TABLE records IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type outcome struct {
		result RiskStats
		err    error
	}
	done := make(chan outcome, 1)
	go func() { result, err := e.RiskStats(ctx, RiskEventFilter{}, "all"); done <- outcome{result, err} }()
	// Synchronize on the real blocked SELECT, not a timing guess or a pre-cancelled
	// context. The test's deadline bounds observation and connection reacquisition.
	for {
		var waiting bool
		if err = admin.QueryRowContext(t.Context(), "SELECT EXISTS (SELECT FROM pg_locks WHERE pid=$1 AND NOT granted)", pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case result := <-done:
			t.Fatalf("stats did not wait for the fixture lock: %+v", result)
		default:
			runtime.Gosched()
		}
	}
	cancel()
	var got outcome
	select {
	case got = <-done:
	case <-t.Context().Done():
		t.Fatal("cancelled stats did not finish")
	}
	if got.err == nil || !reflect.DeepEqual(got.result, RiskStats{}) {
		t.Fatal("cancellation returned partial result", got)
	}
	if err = locker.Rollback(); err != nil {
		t.Fatal(err)
	}
	// PingContext must reacquire the single connection (or a replacement) and work.
	if err = e.DB.PingContext(t.Context()); err != nil {
		t.Fatal("connection was not released", err)
	}
	if result, err := e.RiskStats(t.Context(), RiskEventFilter{}, "all"); err != nil || result.Totals.Total == 0 {
		t.Fatal("pool unusable after cancellation", result, err)
	}
}

func TestRiskStatsPostgresMeasurement(t *testing.T) {
	e := postgresEngine(t)
	seedStats(t, e)
	// Reuse the shared fixture's documented synthetic three-year history and
	// two-year future span; no workload size cap or latency threshold is invented.
	start := time.Now()
	got, err := e.RiskStats(t.Context(), RiskEventFilter{}, "all")
	duration := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	measurement := struct {
		DurationNS     int64 `json:"duration_ns"`
		BucketCount    int   `json:"bucket_count"`
		ResponseBytes  int   `json:"response_bytes"`
		Total          int64 `json:"total"`
		FutureExcluded int64 `json:"future_excluded"`
		From           int64 `json:"from"`
		To             int64 `json:"to"`
	}{duration.Nanoseconds(), len(got.Buckets), len(response), got.Totals.Total, got.Totals.FutureExcluded, got.From, got.To}
	encoded, err := json.MarshalIndent(measurement, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join("..", "..", ".cache")
	if err = os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cache, "s1-measurement.json"), append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("sparse multi-year stats measurement: %s", encoded)
}
