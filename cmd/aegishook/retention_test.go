package main

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// retentionWorkerContext bounds every retention test so a stuck worker fails
// instead of hanging the package. The 15 s watchdog is reused from
// internal/service/policy_refresh_test.go, as is the async assertion cadence.
func retentionWorkerContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func receiveRetention[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-ctx.Done():
		t.Fatal("retention worker did not progress", ctx.Err())
		var zero T
		return zero
	}
}

// retentionTickSeam replaces the stdlib ticker with a manual channel so the
// tests drive ticks deterministically; production keeps the cited 60 s cadence.
func retentionTickSeam(t *testing.T) (chan time.Time, <-chan struct{}) {
	t.Helper()
	ticks, stopped := make(chan time.Time), make(chan struct{})
	previous := newRetentionTicker
	newRetentionTicker = func(interval time.Duration) (<-chan time.Time, func()) {
		if interval != 60*time.Second {
			t.Errorf("interval = %s; the retention worker must use the cited 60 s cadence", interval)
		}
		return ticks, func() { close(stopped) }
	}
	t.Cleanup(func() { newRetentionTicker = previous })
	return ticks, stopped
}

// retentionClockSeam advances the run clock so rows written at the real engine
// clock count as expired, without waiting out a 180-day horizon.
func retentionClockSeam(t *testing.T, offset time.Duration) {
	t.Helper()
	previous := retentionNow
	retentionNow = func(e *core.Engine) time.Time { return e.Clock().Add(offset) }
	t.Cleanup(func() { retentionNow = previous })
}

func retentionEngine(t *testing.T) *core.Engine {
	t.Helper()
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func unsetRetentionEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"TG_SENTRY_EVENTS_RETENTION_DAYS", "TG_SENTRY_AUDIT_RETENTION_DAYS"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func countRetentionAudits(t *testing.T, e *core.Engine, action string) int {
	t.Helper()
	all, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, a := range all {
		if a.Action == action {
			count++
		}
	}
	return count
}

// The serve-owned worker runs the real purge once at startup, then again on each
// tick, deleting rows that are past the adopted horizon without a manual call.
func TestRetentionWorkerPurgesExpiredRowsOnStartupAndTicks(t *testing.T) {
	unsetRetentionEnv(t)
	ticks, stopped := retentionTickSeam(t)
	retentionClockSeam(t, 400*24*time.Hour)
	e := retentionEngine(t)
	ctx := retentionWorkerContext(t)

	// Adoption at startup commits one retention.config audit at the engine clock.
	// The advanced run clock makes it expired, so the worker's own startup run must
	// delete it; the seam only forwards the real purge result for synchronization.
	runs := make(chan core.PurgeResult, 4)
	previous := purgeExpired
	purgeExpired = func(ctx context.Context, e *core.Engine, now time.Time) (core.PurgeResult, error) {
		result, err := e.PurgeExpired(ctx, now)
		runs <- result
		return result, err
	}
	t.Cleanup(func() { purgeExpired = previous })

	stop := startRetentionPurge(ctx, e)
	t.Cleanup(stop)

	first := receiveRetention(t, ctx, runs)
	if first.AuditEnvelopes < 1 {
		t.Fatalf("startup run purged %d audit envelopes, want the expired config audit", first.AuditEnvelopes)
	}
	if n := countRetentionAudits(t, e, "retention.config"); n != 0 {
		t.Fatalf("%d expired retention.config audits survived the startup run", n)
	}
	if n := countRetentionAudits(t, e, "retention.purge"); n != 1 {
		t.Fatalf("retention.purge receipts = %d, want 1", n)
	}

	// The next tick runs again with no manual call.
	select {
	case ticks <- time.Now():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	receiveRetention(t, ctx, runs)

	stop()
	receiveRetention(t, ctx, stopped)
}

// A failed run is logged without SQL text, content or credentials, and the next
// tick still runs; no hot retry loop.
func TestRetentionWorkerLogsSanitizedFailureAndRetriesNextTick(t *testing.T) {
	unsetRetentionEnv(t)
	ticks, _ := retentionTickSeam(t)
	e := retentionEngine(t)
	ctx := retentionWorkerContext(t)

	var logs bytes.Buffer
	previousSlog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousSlog) })

	adoptions := make(chan int32, 4)
	var adoptionAttempts atomic.Int32
	previousAdopt := adoptRetentionPolicy
	adoptRetentionPolicy = func(ctx context.Context, e *core.Engine) error {
		attempt := adoptionAttempts.Add(1)
		adoptions <- attempt
		if attempt == 1 {
			return errors.New("ADOPTION_SENTINEL: SQL content and credentials must stay private")
		}
		return previousAdopt(ctx, e)
	}
	t.Cleanup(func() { adoptRetentionPolicy = previousAdopt })

	calls := make(chan int32, 4)
	var attempts atomic.Int32
	previous := purgeExpired
	purgeExpired = func(ctx context.Context, e *core.Engine, now time.Time) (core.PurgeResult, error) {
		attempt := attempts.Add(1)
		if attempt == 1 {
			calls <- attempt
			return core.PurgeResult{}, errors.New("SENTINEL: DELETE FROM records WHERE payload LIKE 'secret'")
		}
		// Signal only after the real purge returns. Otherwise stop() can cancel
		// its transaction mid-flight; database/sql rolls back asynchronously,
		// and on Windows the still-open handle blocks TempDir removal.
		result, err := e.PurgeExpired(ctx, now)
		calls <- attempt
		return result, err
	}
	t.Cleanup(func() { purgeExpired = previous })

	stop := startRetentionPurge(ctx, e)
	t.Cleanup(stop)
	if first := receiveRetention(t, ctx, adoptions); first != 1 {
		t.Fatal("startup did not attempt policy adoption")
	}
	select {
	case ticks <- time.Now():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if next := receiveRetention(t, ctx, adoptions); next != 2 {
		t.Fatal("adoption failure was not retried on the next tick")
	}
	receiveRetention(t, ctx, calls)

	select {
	case ticks <- time.Now():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if second := receiveRetention(t, ctx, calls); second != 2 {
		t.Fatalf("second attempt = %d, want 2 after a failed first run", second)
	}
	stop()

	if adoptionAttempts.Load() != 2 || attempts.Load() != 2 {
		t.Fatal("adoption/purge attempts did not follow the two manual ticks")
	}
	if !strings.Contains(logs.String(), "retention policy adoption failed") || !strings.Contains(logs.String(), "retention purge failed") {
		t.Fatalf("sanitized adoption/purge failures not logged: %s", logs.String())
	}
	if strings.Contains(logs.String(), "SENTINEL") || strings.Contains(logs.String(), "DELETE FROM") {
		t.Fatalf("log leaked SQL error text: %s", logs.String())
	}
}

// Use the production stdlib ticker with virtual time, following
// internal/server/health_test.go and https://pkg.go.dev/testing/synctest.
// Database integration stays outside the bubble in the tests below.
func TestRetentionProductionTickerAndJoin(t *testing.T) {
	for _, retryAdoption := range []bool{false, true} {
		name := "startup-success"
		if retryAdoption {
			name = "startup-adoption-retry"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				previousAdopt, previousPurge, previousNow := adoptRetentionPolicy, purgeExpired, retentionNow
				defer func() { adoptRetentionPolicy, purgeExpired, retentionNow = previousAdopt, previousPurge, previousNow }()
				retentionNow = func(*core.Engine) time.Time { return time.Now() }
				var adoptions, purges atomic.Int32
				var adopted atomic.Bool
				adoptRetentionPolicy = func(context.Context, *core.Engine) error {
					attempt := adoptions.Add(1)
					if retryAdoption && attempt == 1 {
						return errors.New("adoption unavailable")
					}
					adopted.Store(true)
					return nil
				}
				var blockPurge atomic.Bool
				release := make(chan struct{})
				purgeExpired = func(ctx context.Context, _ *core.Engine, now time.Time) (core.PurgeResult, error) {
					purges.Add(1)
					if !adopted.Load() {
						t.Error("purge ran before policy adoption succeeded")
					}
					if now != time.Now() {
						t.Error("purge did not use the run clock")
					}
					if blockPurge.Load() {
						<-ctx.Done()
						<-release
					}
					return core.PurgeResult{}, nil
				}
				ctx, cancel := context.WithCancel(context.Background())
				stop := startRetentionPurge(ctx, nil)
				defer func() {
					cancel()
					select {
					case <-release:
					default:
						close(release)
					}
					stop()
				}()
				synctest.Wait()
				wantPurges := int32(1)
				if retryAdoption {
					wantPurges = 0
				}
				if adoptions.Load() != 1 || purges.Load() != wantPurges {
					t.Fatalf("startup adoption/purge = %d/%d, want 1/%d", adoptions.Load(), purges.Load(), wantPurges)
				}
				time.Sleep(60*time.Second - time.Nanosecond)
				synctest.Wait()
				if adoptions.Load() != 1 || purges.Load() != wantPurges {
					t.Fatal("worker ran before the literal 60-second cadence")
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				wantAdoptions := int32(1)
				if retryAdoption {
					wantAdoptions = 2
				}
				wantPurges++
				if adoptions.Load() != wantAdoptions || purges.Load() != wantPurges {
					t.Fatal("worker did not adopt then purge at 60 seconds")
				}
				blockPurge.Store(true)
				time.Sleep(60 * time.Second)
				synctest.Wait()
				if adoptions.Load() != wantAdoptions || purges.Load() != wantPurges+1 {
					t.Fatal("worker readopted policy or skipped the next purge")
				}
				done := make(chan struct{})
				go func() { stop(); close(done) }()
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("stop returned before the cancelled purge exited")
				default:
				}
				close(release)
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("stop did not join after the purge exited")
				}
			})
		})
	}
}

// Exercise the same startup and deferred shutdown path used by run, without
// sending process-wide signals to the test runner.
func TestServeStartsRetentionAndJoinsBeforeDatabaseClose(t *testing.T) {
	unsetRetentionEnv(t)
	ticks, _ := retentionTickSeam(t)
	retentionClockSeam(t, 400*24*time.Hour)
	dir := teststore.Dir(t, t.TempDir())
	previousArgs := os.Args
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"aegishook", "serve", "--data-dir", dir, "--agent-dir", t.TempDir(), "--addr", addr}
	t.Cleanup(func() { os.Args = previousArgs })
	watchdog := retentionWorkerContext(t)
	ctx, cancel := context.WithCancel(watchdog)
	runs := make(chan core.PurgeResult)
	engines := make(chan *core.Engine, 1)
	blocked, release := make(chan struct{}), make(chan struct{})
	previousPurge := purgeExpired
	var attempts int
	purgeExpired = func(ctx context.Context, e *core.Engine, now time.Time) (core.PurgeResult, error) {
		attempts++
		if attempts == 1 {
			engines <- e
		}
		if attempts == 3 {
			close(blocked)
			<-ctx.Done()
			<-release
			return core.PurgeResult{}, ctx.Err()
		}
		result, err := e.PurgeExpired(ctx, now)
		select {
		case runs <- result:
		case <-ctx.Done():
		}
		return result, err
	}
	t.Cleanup(func() { purgeExpired = previousPurge })
	done := make(chan struct{})
	var serveErr error
	go func() { defer close(done); serveErr = runWithContext(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-release:
		default:
			close(release)
		}
		receiveRetention(t, watchdog, done)
	})

	e := receiveRetention(t, watchdog, engines)
	if first := receiveRetention(t, watchdog, runs); first.AuditEnvelopes < 1 {
		t.Fatal("serve startup did not purge the expired configuration audit")
	}
	// Seed an expired row using the existing disposable fixture SQL pattern.
	payload := `{"id":"serve-expired","action":"serve-expired","createdAt":"1970-01-01T00:00:00Z"}`
	if _, err := teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES($1,'audit','serve-expired',$2)", "default", payload); err != nil {
		t.Fatal(err)
	}
	select {
	case ticks <- time.Now():
	case <-watchdog.Done():
		t.Fatal(watchdog.Err())
	}
	if next := receiveRetention(t, watchdog, runs); next.AuditEnvelopes != 1 || countRetentionAudits(t, e, "serve-expired") != 0 {
		t.Fatal("serve ticker did not delete the expired audit")
	}
	select {
	case ticks <- time.Now():
	case <-watchdog.Done():
		t.Fatal(watchdog.Err())
	}
	receiveRetention(t, watchdog, blocked)
	cancel()
	select {
	case <-done:
		t.Fatal("serve returned before its retention purge joined")
	case <-time.After(10 * time.Millisecond): // policy_refresh_test.go async assertion cadence.
	}
	if err := e.DB.Ping(); err != nil {
		t.Fatal("database closed before retention purge joined", err)
	}
	close(release)
	receiveRetention(t, watchdog, done)
	if serveErr != nil {
		t.Fatal(serveErr)
	}
	if err := e.DB.Ping(); err == nil {
		t.Fatal("serve returned without closing its database")
	}
}

func TestAdminCLIDoesNotStartRetentionWorker(t *testing.T) {
	unsetRetentionEnv(t)
	armed := make(chan struct{}, 1)
	previous := newRetentionTicker
	newRetentionTicker = func(time.Duration) (<-chan time.Time, func()) {
		armed <- struct{}{}
		return make(chan time.Time), func() {}
	}
	t.Cleanup(func() { newRetentionTicker = previous })
	dir := teststore.Dir(t, t.TempDir())
	if err := runAdminTest(t, "bind", "--data-dir", dir, "--issuer", "https://issuer.example", "--subject", "retention-cli"); err != nil {
		t.Fatal(err)
	}
	e, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if countRetentionAudits(t, e, "retention.config") != 0 {
		t.Fatal("CLI adopted retention policy")
	}
	select {
	case <-armed:
		t.Fatal("CLI started retention worker")
	default:
	}
}

// Opening the store, as CLI commands and tests do, must not start the worker;
// only the serve path wires startRetentionPurge.
func TestCoreOpenDoesNotStartRetentionWorker(t *testing.T) {
	unsetRetentionEnv(t)
	armed := make(chan struct{}, 4)
	previous := newRetentionTicker
	newRetentionTicker = func(time.Duration) (<-chan time.Time, func()) {
		armed <- struct{}{}
		return make(chan time.Time), func() {}
	}
	t.Cleanup(func() { newRetentionTicker = previous })

	e := retentionEngine(t)
	select {
	case <-armed:
		t.Fatal("core.Open started the retention purge worker")
	case <-time.After(50 * time.Millisecond):
	}

	// Positive control: the serve-owned worker does arm exactly this seam.
	// Wait for its startup purge to return before stop(), so cancellation never
	// interrupts a real transaction (see the retry test above).
	purged := make(chan struct{}, 1)
	previousPurge := purgeExpired
	purgeExpired = func(ctx context.Context, e *core.Engine, now time.Time) (core.PurgeResult, error) {
		result, err := e.PurgeExpired(ctx, now)
		purged <- struct{}{}
		return result, err
	}
	t.Cleanup(func() { purgeExpired = previousPurge })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startRetentionPurge(ctx, e)
	for _, ch := range []chan struct{}{armed, purged} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("serve retention worker never armed the ticker and ran its startup purge")
		}
	}
	stop()
}
