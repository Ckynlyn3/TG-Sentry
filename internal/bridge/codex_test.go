package bridge

import (
	"aegishook/internal/core"
	"bytes"
	"context"
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

// Field-table fixture, not an undocumented exec_command payload:
// https://learn.chatgpt.com/docs/hooks#common-input-fields and #pretooluse.
// The docs provide field tables, but no complete PreToolUse stdin example.
func codexPayload(cwd, call, command string) map[string]any {
	return map[string]any{
		"session_id": "thr_123", "transcript_path": filepath.Join(cwd, "rollout.jsonl"),
		"cwd": cwd, "hook_event_name": "PreToolUse", "permission_mode": "default",
		"turn_id": "turn_fixture", "tool_name": "Bash", "tool_use_id": call,
		"tool_input": map[string]any{"command": command},
	}
}

func TestCodexNativeDeniedCommandAndAllow(t *testing.T) {
	for _, tc := range []struct {
		command string
		deny    bool
	}{{"passwd fixture", true}, {"pwd", false}} {
		t.Run(tc.command, func(t *testing.T) {
			e, path, cwd := fixture(t)
			// Existing rule-first precedent: core/review_path_test.go.
			if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), core.Rule{ID: "U_CODEX_PWD", Name: "fixture pwd", Enabled: true, Decision: "approve", Matcher: "regex", Target: "arguments", Tool: "Bash", Field: "command", Pattern: "^pwd$"}); err != nil {
				t.Fatal(err)
			}
			code, output, log := invoke("codex", path, codexPayload(cwd, "call", tc.command))
			if tc.deny {
				// Codex documents exactly the same deny envelope and exit 2 as Claude.
				assertClaudeDeny(t, code, output)
				// Compare to the verbatim vendor #pretooluse output example.
				data, err := os.ReadFile("testdata/codex/deny.json")
				if err != nil {
					t.Fatal(err)
				}
				var vendor, got map[string]any
				if json.Unmarshal(data, &vendor) != nil || json.Unmarshal([]byte(output), &got) != nil {
					t.Fatal("invalid deny JSON")
				}
				vendor["hookSpecificOutput"].(map[string]any)["permissionDecisionReason"] = got["hookSpecificOutput"].(map[string]any)["permissionDecisionReason"]
				if !bytes.Equal(mustJSON(vendor), mustJSON(got)) {
					t.Fatal("deny differs from vendor contract", output)
				}
			} else if code != 0 || strings.TrimSpace(output) != "{}" {
				t.Fatal(code, output, log)
			}
			reviews, err := e.Reviews()
			if err != nil || len(reviews) != 1 {
				t.Fatal(reviews, err)
			}
			want := "awaiting_execution"
			if tc.deny {
				want = "not_executed"
			}
			if reviews[0].Execution != want || reviews[0].Agent != "codex" {
				t.Fatal(reviews)
			}
		})
	}
}

func TestCodexUnknownEventDeniesBeforeConfig(t *testing.T) {
	for _, config := range []string{"available", "unavailable"} {
		t.Run(config, func(t *testing.T) {
			e, path, cwd := fixture(t)
			if config == "unavailable" {
				path = filepath.Join(t.TempDir(), "missing.json")
			}
			payload := codexPayload(cwd, "call", "pwd")
			payload["hook_event_name"] = "PreToolUseTypo"
			code, output, _ := invoke("codex", path, payload)
			assertClaudeDeny(t, code, output)
			if !strings.Contains(output, "unsupported Codex hook event") {
				t.Fatal("unknown event was not rejected before config access", output)
			}
			instances, err := e.Instances()
			if err != nil || len(instances) != 0 {
				t.Fatal("unknown event reached control plane", instances, err)
			}
		})
	}
}

func TestCodexRecognizedPassiveEventsRemainAdvisory(t *testing.T) {
	// Keep the passive subset of core.hookEvents("codex") advisory on failure.
	for _, event := range []string{"SessionStart", "UserPromptSubmit", "PostToolUse", "SessionEnd"} {
		t.Run(event, func(t *testing.T) {
			payload := codexPayload(t.TempDir(), "call", "pwd")
			payload["hook_event_name"] = event
			code, output, log := invoke("codex", filepath.Join(t.TempDir(), "missing.json"), payload)
			if code != 1 || output != "" || log == "" {
				t.Fatal("recognized passive event no longer advisory", code, output, log)
			}
		})
	}
}

func TestCodexControlPlaneDownDenies(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "fixture"}), 0600); err != nil {
		t.Fatal(err)
	}
	code, output, _ := invoke("codex", path, codexPayload(t.TempDir(), "call", "pwd"))
	assertClaudeDeny(t, code, output)
}

func TestCodexAggregateDeadlineDeniesBeforeHostTimeout(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	type result struct {
		code   int
		output string
	}
	done := make(chan result, 1)
	go func() {
		var out, log bytes.Buffer
		code := Run("codex", filepath.Join(t.TempDir(), "missing.json"), reader, &out, &log)
		done <- result{code, out.String()}
	}()
	select {
	case got := <-done:
		assertClaudeDeny(t, got.code, got.output)
	case <-time.After(5 * time.Second): // Existing AgentSentry host-hook budget.
		t.Fatal("Codex bridge did not deny before the host timeout")
	}
}

// Verbatim stdin example from https://learn.chatgpt.com/docs/hooks#sessionend.
func TestCodexVendorSessionEndFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/codex/session-end.json")
	if err != nil {
		t.Fatal(err)
	}
	cwd := "/workspace"
	if !filepath.IsAbs(cwd) {
		// The saved vendor fixture stays verbatim; only adapt its Unix path on Windows.
		cwd = t.TempDir()
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		payload["cwd"] = cwd
		data = mustJSON(payload)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/api/v1/instances/" + hash("codex", "thr_123", cwd) + "/shutdown"
		if r.URL.Path != want || r.Method != "POST" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "fixture"}), 0600); err != nil {
		t.Fatal(err)
	}
	var out, log bytes.Buffer
	if code := Run("codex", path, bytes.NewReader(data), &out, &log); code != 0 {
		t.Fatal(code, out.String(), log.String())
	}
}
