package server

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"testing/synctest"
	"time"
)

func TestHealthChecks(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := New(e, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("app")}}, "fixture-admin", "fixture-hook", t.TempDir())
	s.PublicURL = "https://console.example"
	h := s.Handler()
	check := func(origin, path, method string, status int, body string) {
		t.Helper()
		w := rbacRequest(h, nil, method, origin+path, "", "192.0.2.1:12345")
		if method == http.MethodHead {
			body = ""
		}
		if w.Code != status || w.Body.String() != body {
			t.Errorf("%s %s%s: got %d %q, want %d %q", method, origin, path, w.Code, w.Body.String(), status, body)
		}
		if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if w.Header().Get("Set-Cookie") != "" || len(s.sessions) != 0 {
			t.Error("health check created a session")
		}
	}
	for _, origin := range []string{"http://127.0.0.1:18790", s.PublicURL} {
		for _, path := range []string{"/livez", "/readyz"} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				check(origin, path, method, http.StatusOK, "ok")
			}
		}
	}
	// Existing store-failure injection: risk_stats_test.go closes the real pool.
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		check(s.PublicURL, "/livez", method, http.StatusOK, "ok")
		check(s.PublicURL, "/readyz", method, http.StatusServiceUnavailable, "not ready")
	}
}

func TestHealthChecksRejectOtherMethods(t *testing.T) {
	s, _ := sessionServer(t)
	s.UI = fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("app")}}
	h := s.Handler()
	for _, path := range []string{"/livez", "/readyz"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
			w := rbacRequest(h, nil, method, "http://127.0.0.1"+path, "", "127.0.0.1:12345")
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: got %d, want 405", method, path, w.Code)
			}
		}
	}
}

func TestReadinessDeadlineWithHeldConnection(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	// Both store backends use one connection; hold it so PingContext must wait.
	if got := e.DB.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("pool limit = %d, want 1", got)
	}
	conn, err := e.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	h := s.Handler()
	// Go's Context.WithTimeout example uses virtual time, not a wall-clock sleep:
	// https://pkg.go.dev/testing/synctest#example-package-ContextWithTimeout
	synctest.Test(t, func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/readyz", nil)
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			h.ServeHTTP(w, r.WithContext(ctx))
			close(done)
		}()
		// On failure, unblock PingContext and join the handler before teardown.
		defer func() { cancel(); <-done }()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("readiness returned before the held connection's deadline")
		default:
		}
		// This is the production connectivity budget in health.go.
		time.Sleep(5 * time.Second)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("readiness did not return within its 5s server deadline")
		}
		if ctx.Err() != nil {
			t.Fatalf("request context expired: %v", ctx.Err())
		}
		if w.Code != http.StatusServiceUnavailable || w.Body.String() != "not ready" {
			t.Fatalf("blocked readiness request: %d %q", w.Code, w.Body.String())
		}
	})
}

func TestReadinessUsesRequestContext(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := New(e, fstest.MapFS{}, "fixture-admin", "fixture-hook", t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/readyz", nil)
	ctx, cancel := context.WithDeadline(r.Context(), time.Now().Add(-time.Nanosecond))
	defer cancel()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r.WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != "not ready" {
		t.Fatalf("expired readiness request: %d %q", w.Code, w.Body.String())
	}
}
