package main

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// A long-lived stream (like the SSE endpoint) must end on shutdown, and serveHTTP must not
// return until that handler has exited — otherwise the caller's deferred engine close races it.
func TestServeHTTPDrainsLongLivedRequestsBeforeReturning(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	var handlerDone atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		time.Sleep(50 * time.Millisecond) // cleanup still running when Shutdown begins
		handlerDone.Store(true)
	})
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serveHTTP(ctx, listener, handler) }()

	res, err := http.Get("http://" + listener.Addr().String() + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	<-started
	begin := time.Now()
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serveHTTP returned %v, want clean drain", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP did not return after shutdown")
	}
	if !handlerDone.Load() {
		t.Fatal("serveHTTP returned before the in-flight handler finished")
	}
	if elapsed := time.Since(begin); elapsed >= 3*time.Second {
		t.Fatalf("stream held shutdown to its deadline (%s); request context was not cancelled", elapsed)
	}
}
