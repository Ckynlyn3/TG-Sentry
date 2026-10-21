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
	"runtime"
	"strings"
	"testing"
	"time"
)

// JSON examples from https://cursor.com/docs/hooks.md, Reference / Common schema
// and Hook events. Placeholder paths/commands are substituted; no vendor or shell
// executable is invoked. The original examples and source hash are in docs/remote-clients.md.
func cursorPayload(cwd, event string) map[string]any {
	return map[string]any{"conversation_id": "conversation", "generation_id": "generation", "hook_event_name": event, "cursor_version": "1.7.2", "workspace_roots": []any{cwd}}
}

func cursorTool(cwd, call, event, tool string, args map[string]any) map[string]any {
	p := cursorPayload(cwd, event)
	p["cwd"], p["tool_use_id"], p["tool_name"], p["tool_input"] = cwd, call, tool, args
	return p
}

func assertCursorDecision(t *testing.T, code int, output string, deny bool) {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatal(err, output)
	}
	wantCode, wantPermission := 0, "allow"
	if deny {
		wantCode, wantPermission = 2, "deny"
	}
	if code != wantCode || response["permission"] != wantPermission {
		t.Fatalf("not a native decision: exit=%d output=%s", code, output)
	}
	if deny && response["user_message"] == "" {
		t.Fatal("denial has no reason")
	}
}

func TestCursorNativeDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, tool string
		args       map[string]any
		deny       bool
	}{
		{"shell_denied", "Shell", map[string]any{"command": "passwd fixture"}, true},
		{"shell_allowed", "Shell", map[string]any{"command": "pwd"}, false},
		{"mcp_denied", "MCP", map[string]any{"tool_name": "reset_password", "tool_input": "{}", "mcp_server_name": "linear"}, true},
		{"read_allowed", "Read", map[string]any{"file_path": "README.md"}, false},
		{"edit_denied", "Write", map[string]any{"file_path": "/etc/passwd", "content": "fixture"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, path, cwd := fixture(t)
			// Policy setup is explicit: benign shell is NOT automatically safe.
			for _, rule := range []core.Rule{
				{ID: "U_PWD", Name: "fixture pwd", Enabled: true, Tool: "Bash", Decision: "approve", Matcher: "regex", Target: "arguments", Field: "command", Pattern: "^pwd$"},
				{ID: "U_MCP", Name: "fixture MCP deny", Enabled: true, Tool: "MCP", Decision: "reject", Matcher: "contains", Target: "arguments", Field: "mcp_server_name", Pattern: "linear"},
			} {
				if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
					t.Fatal(err)
				}
			}
			p := cursorTool(cwd, "abc123", "preToolUse", tc.tool, tc.args)
			code, output, log := invoke("cursor", path, p)
			assertCursorDecision(t, code, output, tc.deny)
			reviews, err := e.Reviews()
			if err != nil || len(reviews) != 1 || reviews[0].Agent != "cursor" {
				t.Fatal("missing Cursor review", reviews, err, log)
			}
		})
	}
}

func TestCursorGenericToolAndResult(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			e, path, cwd := fixture(t)
			p := cursorTool(cwd, "abc123", "preToolUse", "Read", map[string]any{"file_path": "README.md"})
			code, out, _ := invoke("cursor", path, p)
			assertCursorDecision(t, code, out, false)
			post := cursorTool(cwd, "abc123", "postToolUse", "Read", p["tool_input"].(map[string]any))
			post["tool_output"] = `{"exitCode":0,"stdout":"All tests passed"}`
			want := "succeeded"
			if failed {
				post["hook_event_name"], post["error_message"], post["failure_type"] = "postToolUseFailure", "fixture error", "error"
				want = "failed"
			}
			if code, _, log := invoke("cursor", path, post); code != 0 {
				t.Fatal(log)
			}
			r, err := e.Review(hash(hash("cursor", "conversation", cwd), "abc123"))
			if err != nil || r.Execution != want {
				t.Fatal(r, err)
			}
			code, out, _ = invoke("cursor", path, p)
			assertCursorDecision(t, code, out, true)
		})
	}
}

func TestCursorFailuresDenyWithinBudget(t *testing.T) {
	for _, mode := range []string{"down", "bad_json", "missing_fields", "wrong_id", "trailing_json", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			cwd := t.TempDir()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				if mode == "timeout" {
					<-r.Context().Done()
					return
				}
				if r.URL.Path != "/api/v1/reviews" {
					w.Write([]byte(`{}`))
					return
				}
				if mode == "bad_json" {
					w.Write([]byte(`{"decision":`))
					return
				}
				v := map[string]any{"id": hash(hash("cursor", "conversation", cwd), "abc123"), "decision": "approve", "comment": "allowed", "ruleId": "A7", "execution": "awaiting_execution", "deadline": time.Now().Add(time.Minute)}
				if mode == "missing_fields" {
					delete(v, "ruleId")
				}
				if mode == "wrong_id" {
					v["id"] = "wrong"
				}
				json.NewEncoder(w).Encode(v)
				if mode == "trailing_json" {
					w.Write([]byte(`{}`))
				}
			}))
			defer srv.Close()
			if mode == "down" {
				srv.Close()
			}
			path := filepath.Join(t.TempDir(), "connection.json")
			if err := os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "fixture"}), 0600); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			code, out, _ := invoke("cursor", path, cursorTool(cwd, "abc123", "preToolUse", "Read", map[string]any{"file_path": "README.md"}))
			assertCursorDecision(t, code, out, true)
			if elapsed := time.Since(start); elapsed >= 5*time.Second { // Existing generated hook budget.
				t.Fatalf("hook budget exceeded: %s", elapsed)
			}
		})
	}
}

func TestCursorMalformedStdinNativeDenial(t *testing.T) {
	for _, input := range []string{"null", "not JSON", `{} {}`, `{"hook_event_name":"preToolUse"}`} {
		var out, log bytes.Buffer
		code := Run("cursor", "missing", strings.NewReader(input), &out, &log)
		assertCursorDecision(t, code, out.String(), true)
	}
}

func TestCursorHumanApprovalRetryBinding(t *testing.T) {
	e, path, cwd := fixture(t)
	p := cursorTool(cwd, "abc123", "preToolUse", "Shell", map[string]any{"command": "echo fixture", "working_directory": cwd})
	code, out, _ := invoke("cursor", path, p)
	assertCursorDecision(t, code, out, true)
	if !strings.Contains(out, "retry after approval") {
		t.Fatal("missing human approval retry instruction", out)
	}
	rs, err := e.Reviews()
	if err != nil || len(rs) != 1 || rs[0].ReviewPath != "human" || rs[0].Decision != "pending" {
		t.Fatal(rs, err)
	}
	if _, err = e.Decide(core.WithActor(context.Background(), core.SystemActor("test")), rs[0].ID, "wrong-digest", "approve", ""); err == nil {
		t.Fatal("wrong digest approved")
	}
	if _, err = e.Decide(core.WithActor(context.Background(), core.SystemActor("test")), rs[0].ID, rs[0].Digest, "approve", ""); err != nil {
		t.Fatal(err)
	}
	code, out, _ = invoke("cursor", path, p)
	assertCursorDecision(t, code, out, false)
	changed := cursorTool(cwd, "abc123", "preToolUse", "Shell", map[string]any{"command": "echo changed", "working_directory": cwd})
	code, out, _ = invoke("cursor", path, changed)
	assertCursorDecision(t, code, out, true)
	other := cursorTool(cwd, "another", "preToolUse", "Shell", p["tool_input"].(map[string]any))
	code, out, _ = invoke("cursor", path, other)
	assertCursorDecision(t, code, out, true)
	post := cursorTool(cwd, "abc123", "postToolUse", "Shell", p["tool_input"].(map[string]any))
	post["tool_output"] = `{"exitCode":0,"stdout":"fixture"}`
	if code, _, log := invoke("cursor", path, post); code != 0 {
		t.Fatal(log)
	}
	code, out, _ = invoke("cursor", path, p)
	assertCursorDecision(t, code, out, true)
}

func TestCursorPromptAndObservations(t *testing.T) {
	e, path, cwd := fixture(t)
	prompt := cursorPayload(cwd, "beforeSubmitPrompt")
	prompt["prompt"] = "fixture token=do-not-save"
	code, out, log := invoke("cursor", path, prompt)
	if code != 0 || strings.TrimSpace(out) != `{"continue":true}` {
		t.Fatal(code, out, log)
	}
	p := cursorTool(cwd, "read", "preToolUse", "Read", map[string]any{"file_path": "README.md"})
	code, out, _ = invoke("cursor", path, p)
	assertCursorDecision(t, code, out, false)
	rs, _ := e.Reviews()
	if len(rs) != 2 {
		t.Fatal("expected separate prompt and tool reviews", len(rs))
	}
	promptExists, toolExists := false, false
	for _, review := range rs {
		if review.ToolName == "prompt_turn" {
			promptExists = true
		} else if review.CallID == "read" {
			toolExists = true
		}
		if strings.Contains(review.UserMessage, "do-not-save") || !strings.Contains(review.UserMessage, "REDACTED") {
			t.Fatal("prompt context not captured/redacted")
		}
	}
	if !promptExists || !toolExists {
		t.Fatal("expected prompt_turn and tool-call surfaces")
	}
	for _, event := range []string{"sessionStart", "afterFileEdit", "afterAgentResponse", "stop"} {
		observation := cursorPayload(cwd, event)
		// An undocumented injected call ID must not forge an edit result.
		observation["tool_use_id"] = "read"
		observation["text"] = "response fixture"
		observation["file_path"] = filepath.Join(cwd, "README.md")
		observation["edits"] = []any{map[string]any{"old_string": "before", "new_string": "after"}}
		if code, _, log := invoke("cursor", path, observation); code != 0 {
			t.Fatal(event, log)
		}
	}
	r, _ := e.Review(rs[0].ID)
	if r.Execution != "awaiting_execution" {
		t.Fatal("uncorrelated observation forged a result", r)
	}
	instances, _ := e.Instances()
	if len(instances) != 1 || instances[0].State == "disconnected" {
		t.Fatal("stop ended the conversation", instances)
	}
	if code, _, log := invoke("cursor", path, cursorPayload(cwd, "sessionEnd")); code != 0 {
		t.Fatal(log)
	}
	instances, _ = e.Instances()
	if instances[0].State != "disconnected" {
		t.Fatal(instances)
	}
}

func TestCursorRejectsMalformedNativeContracts(t *testing.T) {
	for _, tc := range []struct {
		name, event string
		fields      map[string]any
	}{
		{"unknown_event", "beforeShellExecutionTypo", nil},
		{"missing_conversation", "preToolUse", map[string]any{"conversation_id": ""}},
		{"relative_cwd", "preToolUse", map[string]any{"cwd": "relative"}},
		{"missing_call", "preToolUse", map[string]any{"tool_use_id": ""}},
		{"missing_tool", "preToolUse", map[string]any{"tool_name": ""}},
		{"array_args", "preToolUse", map[string]any{"tool_input": []any{}}},
		{"null_args", "preToolUse", map[string]any{"tool_input": nil}},
		{"invalid_working_dir", "preToolUse", map[string]any{"tool_input": map[string]any{"command": "pwd", "working_directory": false}}},
		{"relative_working_dir", "preToolUse", map[string]any{"tool_input": map[string]any{"command": "pwd", "working_directory": "relative"}}},
		{"bad_tool_output", "postToolUse", map[string]any{"tool_output": "not JSON"}},
		{"non_string_output", "postToolUse", map[string]any{"tool_output": map[string]any{}}},
		{"bad_prompt", "beforeSubmitPrompt", map[string]any{"prompt": false}},
		{"invalid_failure_type", "postToolUseFailure", map[string]any{"failure_type": "unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			p := cursorTool(cwd, "call", tc.event, "Shell", map[string]any{"command": "pwd"})
			for k, v := range tc.fields {
				p[k] = v
			}
			if _, err := normalizeCursor(p); err == nil {
				t.Fatal("malformed native contract normalized", tc.name)
			}
			code, out, _ := invoke("cursor", "missing-config", p)
			assertCursorDecision(t, code, out, true)
		})
	}
}

func TestCursorSlowStdinFailsClosed(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var out, log bytes.Buffer
	start := time.Now()
	code := Run("cursor", "missing", reader, &out, &log)
	assertCursorDecision(t, code, out.String(), true)
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatal("Cursor input exceeded generated hook budget", elapsed)
	}
}

func TestCursorSignedBundleRequiredBeforePermit(t *testing.T) {
	e, path, cwd := fixture(t)
	// The credentials below are generated disposable test identities, not host credentials.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var original Config
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	key, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "cursor fixture")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := e.EnrollClient(key.Code, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	connection.Endpoint = original.Endpoint
	write := func() {
		t.Helper()
		if err := os.WriteFile(path, mustJSON(connection), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := cursorTool(cwd, "bundle", "preToolUse", "Read", map[string]any{"file_path": "README.md"})
	write()
	code, out, _ := invoke("cursor", path, p)
	assertCursorDecision(t, code, out, false)
	cache := filepath.Join(filepath.Dir(path), "bundle.json")
	trusted, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal("Cursor skipped signed bundle fetch", err)
	}
	if err := os.WriteFile(cache, []byte(`{"payload":null,"signature":"tampered"}`), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = invoke("cursor", path, p)
	assertCursorDecision(t, code, out, true)
	if err := os.WriteFile(cache, trusted, 0600); err != nil {
		t.Fatal(err)
	}
	connection.Endpoint = "http://127.0.0.1:1"
	write()
	code, out, _ = invoke("cursor", path, p)
	assertCursorDecision(t, code, out, true) // Cached allow never becomes offline authority.
	connection.Endpoint, connection.BundlePublicKey = original.Endpoint, nil
	write()
	code, out, _ = invoke("cursor", path, p)
	assertCursorDecision(t, code, out, true)
}

func TestCursorPromptCaptureFailureMirrorsExistingPath(t *testing.T) {
	_, path, cwd := fixture(t)
	p := cursorPayload(cwd, "beforeSubmitPrompt")
	p["prompt"] = "fixture"
	contextPath := filepath.Join(filepath.Dir(path), "context-"+hash("cursor", "conversation", cwd)+".json")
	if err := os.Mkdir(contextPath, 0700); err != nil {
		t.Fatal(err)
	}
	code, out, _ := invoke("cursor", path, p)
	if code != 1 || out != "" {
		t.Fatal("capture failure differs from UserPromptSubmit or emitted continue", code, out)
	}
	code, out, _ = invoke("cursor", "missing-config", p)
	assertCursorDecision(t, code, out, true) // Unavailable prompt policy cannot authorize submission.
}

func TestCursorPermissionDeniedReportsNotExecuted(t *testing.T) {
	e, path, cwd := fixture(t)
	args := map[string]any{"command": "passwd fixture"}
	p := cursorTool(cwd, "denied", "preToolUse", "Shell", args)
	code, out, _ := invoke("cursor", path, p)
	assertCursorDecision(t, code, out, true)
	post := cursorTool(cwd, "denied", "postToolUseFailure", "Shell", args)
	post["failure_type"], post["error_message"], post["is_interrupt"] = "permission_denied", "denied by hook", false
	if code, _, log := invoke("cursor", path, post); code != 0 {
		t.Fatal("permission denial reported as executed failure", log)
	}
	r, err := e.Review(hash(hash("cursor", "conversation", cwd), "denied"))
	if err != nil || r.Decision != "reject" || r.Execution != "not_executed" {
		t.Fatal(r, err)
	}
}
