package main

import (
	"aegishook/internal/core"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretResolveDeadline(t *testing.T) {
	// #45 plan §§2–3: one resolver budget strictly below OpenClaw's 5000 ms.
	const providerTimeout = 5000 * time.Millisecond
	if secretResolveTimeout != core.ReviewHookBudget || secretResolveTimeout >= providerTimeout {
		t.Error("resolver does not reuse the shorter existing hook budget")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // No response: only the shared deadline can stop it.
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "connection.json")
	data, _ := json.Marshal(core.ClientConnection{Endpoint: srv.URL, Token: "synthetic-token", NodeID: strings.Repeat("a", 32)})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	// Reuse the existing gap between hook and provider budgets as an input delay.
	reader, writer := io.Pipe()
	defer reader.Close()
	go func() {
		defer writer.Close()
		timer := time.NewTimer(providerTimeout - core.ReviewHookBudget)
		defer timer.Stop()
		<-timer.C
		io.WriteString(writer, `{"protocolVersion":1,"provider":"tgsentry","ids":["delayed"]}`)
	}()
	var out bytes.Buffer
	started := time.Now()
	err := runSecretResolve([]string{"--connection", path, "--agent", "agent-label"}, reader, &out)
	elapsed := time.Since(started)
	t.Logf("delayed stdin plus HTTP: elapsed=%s resolver=%s provider=%s", elapsed, core.ReviewHookBudget, providerTimeout)
	if err == nil || out.Len() != 0 || elapsed >= providerTimeout {
		t.Fatal("delayed response did not fail closed within end-to-end budget")
	}
}

func TestSecretResolveContract(t *testing.T) {
	secret := "synthetic-resolver-value-45"
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Error("missing bearer")
		}
		if r.URL.Query().Get("agent") != "agent-label" {
			t.Error("agent source missing")
		}
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "denied") {
			w.WriteHeader(403)
			w.Write([]byte(secret))
			return
		}
		json.NewEncoder(w).Encode(core.ResolvedCredential{ID: r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], Env: "FIXTURE_KEY", Value: secret})
	}))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "connection.json")
	data, _ := json.Marshal(core.ClientConnection{Endpoint: srv.URL, Token: "synthetic-token", NodeID: strings.Repeat("a", 32)})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"secret-resolve", "--connection", path, "--agent", "agent-label"}
	var out bytes.Buffer
	err := runClient(args, strings.NewReader(`{"protocolVersion":1,"provider":"tgsentry","ids":["first","second"]}`), &out)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		ProtocolVersion int               `json:"protocolVersion"`
		Values          map[string]string `json:"values"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.ProtocolVersion != 1 || result.Values["first"] != secret || result.Values["second"] != secret || len(paths) != 2 {
		t.Fatal("batched protocol response")
	}
	for _, input := range []string{`not-json`, `{"protocolVersion":2,"provider":"tgsentry","ids":["first"]}`, `{"protocolVersion":1,"provider":"tgsentry","ids":["../bad"]}`, `{"protocolVersion":1,"provider":"tgsentry","ids":["denied"]}`, strings.Repeat("x", (1<<20)+1)} {
		out.Reset()
		err := runClient(args, strings.NewReader(input), &out)
		if err == nil {
			t.Fatal("invalid/denied request accepted")
		}
		if out.Len() != 0 || strings.Contains(err.Error(), secret) {
			t.Fatal("error leaked plaintext")
		}
	}
	out.Reset()
	if err := runClient([]string{"secret-resolve", "--connection", path}, strings.NewReader(`{"protocolVersion":1,"provider":"tgsentry","ids":["first"]}`), &out); err == nil || out.Len() != 0 {
		t.Fatal("implicit agent allowed")
	}
}
