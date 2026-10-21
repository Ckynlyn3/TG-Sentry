package service

import (
	"aegishook/internal/core"
	"aegishook/internal/core/discovery"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixture sizes and modes reuse policy_refresh_test.go and the S7 CLI tests.
func serviceDiscoveryFixture(t *testing.T, endpoint string) (core.MachineOptions, func(int, *core.DiscoveryPolicy)) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	options := core.MachineOptions{Root: t.TempDir()}
	paths := core.MachinePaths(options.Root)
	if err := os.MkdirAll(filepath.Dir(paths.Connection), 0700); err != nil {
		t.Fatal(err)
	}
	node := strings.Repeat("b", 32)
	write := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(paths.Connection, core.ClientConnection{Endpoint: endpoint, NodeID: node, Token: strings.Repeat("a", 64), BundlePublicKey: public})
	return options, func(revision int, policy *core.DiscoveryPolicy) {
		t.Helper()
		payload, err := json.Marshal(core.PolicyBundle{NodeID: node, Revision: revision, Rules: []core.Rule{}, Discovery: policy})
		if err != nil {
			t.Fatal(err)
		}
		write(paths.Bundle, core.SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)})
	}
}

func serviceDiscoveryScan(t *testing.T, scan func(context.Context, string) (discovery.Report, error)) {
	t.Helper()
	previous := runServiceDiscovery
	runServiceDiscovery = scan
	t.Cleanup(func() { runServiceDiscovery = previous })
}

func serviceDiscoveryLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &output
}

func TestServiceDiscoveryDisabledAndUnavailableNeverScan(t *testing.T) {
	serviceDiscoveryScan(t, func(context.Context, string) (discovery.Report, error) {
		t.Fatal("disabled or unverified policy called scanner")
		return discovery.Report{}, nil
	})
	for _, policy := range []*core.DiscoveryPolicy{nil, {}, {Enabled: false, IntervalSeconds: 60}, {Enabled: true}} {
		options, write := serviceDiscoveryFixture(t, "http://127.0.0.1")
		write(1, policy)
		var runner discoveryRunner
		runner.refresh(context.Background(), options)
		if _, err := os.Stat(filepath.Join(core.MachinePaths(options.Root).Private, "discovery.lock")); !os.IsNotExist(err) {
			t.Fatal("disabled policy acquired scan lock")
		}
	}
	for _, missing := range []string{"credential", "policy", "invalid signature"} {
		t.Run(missing, func(t *testing.T) {
			options, write := serviceDiscoveryFixture(t, "http://127.0.0.1")
			write(1, &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: 60})
			paths := core.MachinePaths(options.Root)
			path := paths.Connection
			if missing == "policy" {
				path = paths.Bundle
			}
			if missing == "invalid signature" {
				if err := os.WriteFile(paths.Bundle, []byte(`{"payload":"e30=","signature":""}`), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			var runner discoveryRunner
			runner.refresh(context.Background(), options)
		})
	}
}

func TestServiceDiscoveryDueAndChangedSettings(t *testing.T) {
	options, write := serviceDiscoveryFixture(t, "http://127.0.0.1")
	now := time.Now()
	previous := discoveryNow
	discoveryNow = func() time.Time { return now }
	t.Cleanup(func() { discoveryNow = previous })
	calls := 0
	serviceDiscoveryScan(t, func(ctx context.Context, dir string) (discovery.Report, error) {
		calls++
		if dir != core.MachinePaths(options.Root).Private || ctx.Err() != nil {
			t.Fatal("scan lost machine private root or context")
		}
		return discovery.Report{Final: true}, nil
	})
	policy := &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: 60}
	write(1, policy)
	var runner discoveryRunner
	runner.refresh(context.Background(), options)
	if calls != 1 {
		t.Fatalf("initial due scan calls = %d", calls)
	}
	now = now.Add(policyRefreshInterval - time.Nanosecond)
	runner.refresh(context.Background(), options)
	write(2, policy) // Unrelated bundle revisions must not force discovery.
	runner.refresh(context.Background(), options)
	if calls != 1 {
		t.Fatalf("not due scan calls = %d", calls)
	}
	now = now.Add(time.Nanosecond)
	runner.refresh(context.Background(), options)
	if calls != 2 {
		t.Fatalf("exact interval scan calls = %d", calls)
	}
	write(3, &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: 120})
	runner.refresh(context.Background(), options)
	runner.refresh(context.Background(), options)
	if calls != 3 {
		t.Fatalf("changed settings scan calls = %d", calls)
	}
	write(4, nil)
	runner.refresh(context.Background(), options)
	write(5, policy)
	runner.refresh(context.Background(), options)
	if calls != 4 {
		t.Fatalf("re-enabled scan calls = %d", calls)
	}
	// A valid int interval need not fit in time.Duration seconds.
	write(6, &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: int(^uint(0) >> 1)})
	runner.refresh(context.Background(), options)
	now = now.Add(policyRefreshInterval)
	runner.refresh(context.Background(), options)
	if calls != 5 {
		t.Fatalf("large interval overflowed: calls = %d", calls)
	}
}

func TestServiceDiscoveryLockSkipsEnumerationAndMachineReport(t *testing.T) {
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		posts++
		if request.URL.Path != "/api/v1/client/discovery-reports" || request.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
			t.Error("machine reporting lost credential or endpoint")
		}
		report, err := discovery.DecodeReport(request.Body)
		if err != nil || report.NodeID != strings.Repeat("b", 32) || report.Scope != discovery.AllLocalAccounts || !report.Final {
			t.Error("report did not use enrolled machine identity and all-account scope")
		}
	}))
	defer server.Close()
	options, write := serviceDiscoveryFixture(t, server.URL)
	write(1, &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: 60})
	private := core.MachinePaths(options.Root).Private
	enumerations := 0
	serviceDiscoveryScan(t, func(ctx context.Context, dir string) (discovery.Report, error) {
		return core.RunDiscovery(ctx, dir, discovery.AllLocalAccounts, func(context.Context) ([]discovery.AccountHome, error) {
			enumerations++
			return []discovery.AccountHome{}, nil
		}, nil)
	})
	output := serviceDiscoveryLogs(t)
	lock, err := discovery.TryScanLock(filepath.Join(private, "discovery.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	var runner discoveryRunner
	runner.refresh(context.Background(), options)
	if enumerations != 0 || posts != 0 || !strings.Contains(output.String(), "machine discovery skipped") {
		t.Fatalf("lock contention: enumerations=%d posts=%d logs=%s", enumerations, posts, output)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	runner.refresh(context.Background(), options)
	if enumerations != 1 || posts != 1 {
		t.Fatalf("unlocked scan: enumerations=%d posts=%d", enumerations, posts)
	}
}

func TestServiceDiscoveryErrorDoesNotStopRefresh(t *testing.T) {
	ctx := policyRefreshContext(t)
	ticks, _ := policyRefreshClock(t)
	options, write := serviceDiscoveryFixture(t, "http://127.0.0.1")
	write(1, &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: 1})
	policyRefreshFetch(t, func(context.Context, core.MachineOptions) error { return nil })
	previous := discoveryNow
	now := time.Now()
	discoveryNow = func() time.Time { now = now.Add(policyRefreshInterval); return now }
	t.Cleanup(func() { discoveryNow = previous })
	calls := make(chan struct{})
	serviceDiscoveryScan(t, func(ctx context.Context, _ string) (discovery.Report, error) {
		select {
		case calls <- struct{}{}:
		case <-ctx.Done():
		}
		return discovery.Report{}, errors.New("SENTINEL_not_for_logs")
	})
	output := serviceDiscoveryLogs(t)
	stop := startPolicyRefresh(ctx, options)
	defer stop()
	receiveRefresh(t, ctx, calls)
	select {
	case ticks <- time.Now():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	receiveRefresh(t, ctx, calls)
	stop()
	if !strings.Contains(output.String(), "machine discovery failed") || strings.Contains(output.String(), "SENTINEL") {
		t.Fatalf("discovery failure not sanitized: %s", output)
	}
}

func TestServiceDiscoveryCancellationJoinsScan(t *testing.T) {
	watchdog := policyRefreshContext(t)
	_, stopped := policyRefreshClock(t)
	options, write := serviceDiscoveryFixture(t, "http://127.0.0.1")
	write(1, &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: 60})
	policyRefreshFetch(t, func(context.Context, core.MachineOptions) error { return nil })
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	serviceDiscoveryScan(t, func(ctx context.Context, _ string) (discovery.Report, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		return discovery.Report{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(watchdog)
	t.Cleanup(cancel)
	stop := startPolicyRefresh(ctx, options)
	t.Cleanup(stop)
	t.Cleanup(func() {
		cancel()
		select {
		case <-release:
		default:
			close(release)
		}
		receiveRefresh(t, watchdog, stopped)
	})
	receiveRefresh(t, watchdog, started)
	cancel()
	receiveRefresh(t, watchdog, cancelled)
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
		t.Error("stop returned before scan exited")
	case <-time.After(10 * time.Millisecond): // Existing policy_refresh_test.go join assertion cadence.
	}
	close(release)
	receiveRefresh(t, watchdog, done)
	receiveRefresh(t, watchdog, stopped)
}

func TestServiceDiscoveryCancelledAndRefreshFailureNeverScan(t *testing.T) {
	options, write := serviceDiscoveryFixture(t, "http://127.0.0.1")
	write(1, &core.DiscoveryPolicy{Enabled: true, IntervalSeconds: 60})
	serviceDiscoveryScan(t, func(context.Context, string) (discovery.Report, error) {
		t.Error("scan called after cancellation or rejected refresh")
		return discovery.Report{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var runner discoveryRunner
	runner.refresh(ctx, options)
	policyRefreshClock(t)
	called := make(chan struct{})
	policyRefreshFetch(t, func(context.Context, core.MachineOptions) error {
		close(called)
		return errors.New("rejected refresh")
	})
	watchdog := policyRefreshContext(t)
	stop := startPolicyRefresh(watchdog, options)
	defer stop()
	receiveRefresh(t, watchdog, called)
	stop()
}
