package bridge

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"aegishook/internal/core"
	"aegishook/internal/server"
)

func TestPromptSecretSurvivesMarkerCache(t *testing.T) {
	e, path, cwd := fixture(t) // Real bridge -> httptest server -> engine/store.
	candidate := bridgeSecretFixture()
	handler := server.New(e, fstest.MapFS{}, "admin-fixture", "hook-fixture", t.TempDir()).Handler()
	var mu sync.Mutex
	var requests []json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/reviews" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error("could not capture bridge request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			mu.Lock()
			requests = append(requests, json.RawMessage(body))
			mu.Unlock()
		}
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	if err := os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "hook-fixture"}), 0600); err != nil {
		t.Fatal(err)
	}
	// Codex prompt submission is observational, so it still writes the cache
	// after the server rejects the prompt-turn review. PreToolUse must block.
	prompt := native("codex", cwd, "", "", "UserPromptSubmit", nil)
	prompt["prompt"] = "Use " + candidate
	if code, _, _ := invoke("codex", path, prompt); code != 0 {
		t.Fatal("observational prompt hook failed")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "context-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("missing prompt cache")
	}
	cache, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var saved cachedPrompt
	if json.Unmarshal(cache, &saved) != nil || saved.UserMessage != "[REDACTED]" || saved.PromptScan == nil {
		t.Fatal("prompt cache lost marker or finding metadata")
	}
	pre := native("codex", cwd, "prompt-secret-call", "Read", "PreToolUse", map[string]any{"path": "fixture"})
	code, out, log := invoke("codex", path, pre)
	if code != 2 {
		t.Fatal("cached prompt finding did not block pre-tool execution")
	}
	review, err := e.Review(hash(hash("codex", "session", cwd), "prompt-secret-call"))
	if err != nil || review.Decision != "reject" || review.RuleID != "R_SECRET_GITHUB_PAT" || review.SensitiveInfo == nil || len(review.SensitiveInfo.Findings) != 1 {
		t.Fatal("cached prompt finding did not reach deterministic sensitive review")
	}
	if review.SensitiveInfo.Findings[0].EntityType != "github-pat" {
		t.Fatal("prompt finding attribution lost")
	}
	page, err := e.RiskEvents(0, "", core.RiskEventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range page.Items {
		found = found || event.Data.FindingInfo.UID == review.ID
	}
	if !found {
		t.Fatal("cached prompt hit did not emit the existing secret risk event")
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	captured := append([]json.RawMessage(nil), requests...)
	mu.Unlock()
	if len(captured) != 2 { // Prompt turn plus pre-tool request, as in the existing bridge test.
		t.Fatal("prompt handoff requests not exercised")
	}
	for _, body := range captured {
		var request struct {
			UserMessage string      `json:"userMessage"`
			PromptScan  *promptScan `json:"prompt_scan"`
		}
		if json.Unmarshal(body, &request) != nil || request.UserMessage != "[REDACTED]" || request.PromptScan == nil {
			t.Fatal("actual request lost marker or prompt scan metadata")
		}
	}
	for _, value := range []any{string(cache), captured, review, audits, page, out, log} {
		if strings.Contains(string(mustJSON(value)), candidate) {
			t.Fatal("prompt secret escaped marker handoff")
		}
	}
}
