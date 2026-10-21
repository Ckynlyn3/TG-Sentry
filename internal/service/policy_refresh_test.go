package service

import (
	"aegishook/internal/core"
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

func policyRefreshContext(t *testing.T) context.Context {
	t.Helper()
	// Reuse MachineEnrolledContext's 15 s HTTP budget as the test watchdog.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func receiveRefresh[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-ctx.Done():
		t.Fatal("policy refresh did not complete", ctx.Err())
		var zero T
		return zero
	}
}

func policyRefreshClock(t *testing.T) (chan time.Time, <-chan struct{}) {
	t.Helper()
	ticks, stopped := make(chan time.Time), make(chan struct{})
	previous := newPolicyRefreshTicker
	newPolicyRefreshTicker = func(interval time.Duration) (<-chan time.Time, func()) {
		if interval != 60*time.Second {
			t.Errorf("interval = %s; DECISIONS #7 requires 60 s", interval)
		}
		return ticks, func() { close(stopped) }
	}
	t.Cleanup(func() { newPolicyRefreshTicker = previous })
	return ticks, stopped
}

func policyRefreshFetch(t *testing.T, fetch func(context.Context, core.MachineOptions) error) {
	t.Helper()
	previous := refreshMachinePolicy
	refreshMachinePolicy = fetch
	t.Cleanup(func() { refreshMachinePolicy = previous })
}

func TestPolicyRefreshImmediateTickErrorAndStop(t *testing.T) {
	ctx := policyRefreshContext(t)
	ticks, stopped := policyRefreshClock(t)
	calls := make(chan core.MachineOptions)
	policyRefreshFetch(t, func(ctx context.Context, options core.MachineOptions) error {
		select {
		case calls <- options:
		case <-ctx.Done():
			return ctx.Err()
		}
		return errors.New("fetch unavailable")
	})
	var logs bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousOutput) })
	options := core.MachineOptions{Root: t.TempDir()}
	stop := startPolicyRefresh(ctx, options)
	t.Cleanup(stop)
	if got := receiveRefresh(t, ctx, calls); got.Root != options.Root {
		t.Fatalf("immediate refresh options = %+v", got)
	}
	for range 2 {
		select {
		case ticks <- time.Now():
		case <-ctx.Done():
			t.Fatal("fetch failure stopped polling", ctx.Err())
		}
		receiveRefresh(t, ctx, calls)
	}
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	receiveRefresh(t, ctx, done)
	receiveRefresh(t, ctx, stopped)
	if !strings.Contains(logs.String(), "fetch unavailable") {
		t.Fatalf("refresh failure not logged: %s", &logs)
	}
}

func TestPolicyRefreshCancellationJoinsInFlightFetch(t *testing.T) {
	watchdog := policyRefreshContext(t)
	_, stopped := policyRefreshClock(t)
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	policyRefreshFetch(t, func(ctx context.Context, _ core.MachineOptions) error {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(watchdog)
	t.Cleanup(cancel)
	stop := startPolicyRefresh(ctx, core.MachineOptions{})
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
		t.Error("stop returned before the in-flight fetch exited")
	case <-time.After(10 * time.Millisecond): // Existing async assertion cadence: core/core_test.go.
	}
	close(release)
	receiveRefresh(t, watchdog, done)
	receiveRefresh(t, watchdog, stopped)
}

func TestPolicyRefreshCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	policyRefreshFetch(t, func(context.Context, core.MachineOptions) error {
		t.Error("fetch called after cancellation")
		return nil
	})
	stop := startPolicyRefresh(ctx, core.MachineOptions{})
	stop()
}

type refreshResponse struct {
	status int
	signed core.SignedPolicyBundle
	etag   string
}

func refreshBundle(t *testing.T, key ed25519.PrivateKey, node string, revision int, rules []core.Rule) core.SignedPolicyBundle {
	t.Helper()
	payload, err := json.Marshal(core.PolicyBundle{NodeID: node, Revision: revision, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return core.SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(key, payload)}
}

func TestPolicyRefreshVerifiedMachineCache(t *testing.T) {
	ctx := policyRefreshContext(t)
	ticks, _ := policyRefreshClock(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node, token := strings.Repeat("b", 32), strings.Repeat("a", 64)
	responses, requests := make(chan refreshResponse), make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/client/bundle" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("machine bundle request lost its path or authentication")
		}
		requests <- r.Header.Get("If-None-Match")
		select {
		case response := <-responses:
			w.Header().Set("ETag", response.etag)
			w.WriteHeader(response.status)
			if response.status == http.StatusOK {
				if err := json.NewEncoder(w).Encode(response.signed); err != nil {
					t.Error(err)
				}
			}
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	options := core.MachineOptions{Root: root, ValidatePath: func(string, bool) error { return nil }}
	// Only filesystem ownership is substituted for this isolated temporary root.
	// HTTP, signatures, node/revision checks and the OS cache lock remain real.
	paths := core.MachinePaths(options.Root)
	if err := os.MkdirAll(filepath.Dir(paths.Connection), 0700); err != nil {
		t.Fatal(err)
	}
	connection, err := json.Marshal(core.ClientConnection{Endpoint: server.URL, NodeID: node, Token: token, BundlePublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Connection, connection, 0600); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 1)
	policyRefreshFetch(t, func(ctx context.Context, options core.MachineOptions) error {
		err := core.MachineEnrolledContext(ctx, options)
		results <- err
		return err
	})
	stop := startPolicyRefresh(ctx, options)
	defer stop()
	v1 := refreshBundle(t, private, node, 1, []core.Rule{})
	v2 := refreshBundle(t, private, node, 2, []core.Rule{})
	tampered := v2
	tampered.Signature = make([]byte, ed25519.SignatureSize)
	conflict := core.SignedPolicyBundle{Payload: append(bytes.Clone(v2.Payload), ' ')}
	conflict.Signature = ed25519.Sign(private, conflict.Payload)
	cases := []struct {
		name     string
		response refreshResponse
		want     core.SignedPolicyBundle
		wantErr  bool
	}{
		{"initial", refreshResponse{200, v1, core.PolicyBundleETag(v1)}, v1, false},
		{"not modified", refreshResponse{304, core.SignedPolicyBundle{}, core.PolicyBundleETag(v1)}, v1, false},
		{"newer", refreshResponse{200, v2, core.PolicyBundleETag(v2)}, v2, false},
		{"tampered", refreshResponse{200, tampered, core.PolicyBundleETag(tampered)}, v2, true},
		{"rollback", refreshResponse{200, v1, core.PolicyBundleETag(v1)}, v2, true},
		{"same revision different bytes", refreshResponse{200, conflict, ""}, v2, true},
		{"wrong node", refreshResponse{200, refreshBundle(t, private, strings.Repeat("c", 32), 3, []core.Rule{}), ""}, v2, true},
		{"fetch failure", refreshResponse{503, core.SignedPolicyBundle{}, ""}, v2, true},
		{"recovers", refreshResponse{304, core.SignedPolicyBundle{}, core.PolicyBundleETag(v2)}, v2, false},
	}
	previousETag := ""
	var previousCache []byte
	for i, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if i != 0 {
				select {
				case ticks <- time.Now():
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if etag := receiveRefresh(t, ctx, requests); etag != previousETag {
				t.Fatalf("If-None-Match = %q, want %q", etag, previousETag)
			}
			select {
			case responses <- test.response:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err := receiveRefresh(t, ctx, results); (err != nil) != test.wantErr {
				t.Fatalf("refresh error = %v, want error = %v", err, test.wantErr)
			}
			cached, err := core.ReadPolicyBundle(paths.Bundle, public, node)
			if err != nil || !bytes.Equal(cached.Payload, test.want.Payload) || !bytes.Equal(cached.Signature, test.want.Signature) {
				t.Fatalf("verified cache changed unexpectedly: %v", err)
			}
			cacheBytes, err := os.ReadFile(paths.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			if (test.wantErr || test.response.status == 304) && !bytes.Equal(cacheBytes, previousCache) {
				t.Fatal("304 or rejected response rewrote the last verified cache")
			}
			previousETag, previousCache = core.PolicyBundleETag(cached), cacheBytes
		})
		if t.Failed() {
			return
		}
	}
}
