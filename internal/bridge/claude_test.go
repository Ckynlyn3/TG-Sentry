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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Vendor stdin shape: https://code.claude.com/docs/en/hooks#pretooluse-input
// Commands are payload data only; this test never executes a shell.
func claudePayload(cwd, call, tool string, args map[string]any) map[string]any {
	return map[string]any{
		"session_id": "abc123", "transcript_path": filepath.Join(cwd, "transcript.jsonl"),
		"cwd": cwd, "permission_mode": "default", "hook_event_name": "PreToolUse",
		"tool_name": tool, "tool_input": args, "tool_use_id": call,
	}
}

func assertClaudeDeny(t *testing.T, code int, output string) {
	t.Helper()
	var response struct {
		Hook struct {
			Event    string `json:"hookEventName"`
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatal(err, output)
	}
	if code != 2 || response.Hook.Event != "PreToolUse" || response.Hook.Decision != "deny" || response.Hook.Reason == "" {
		t.Fatalf("not a native blocking response: exit=%d output=%s", code, output)
	}
}

func TestClaudePreToolUseNativeDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, tool string
		args       map[string]any
		deny       bool
	}{
		{"denied_bash", "Bash", map[string]any{"command": "passwd fixture", "description": "Change password", "timeout": 120000}, true},
		{"benign_read", "Read", map[string]any{"file_path": "README.md"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, path, cwd := fixture(t)
			code, output, log := invoke("claude", path, claudePayload(cwd, tc.name, tc.tool, tc.args))
			if tc.deny {
				assertClaudeDeny(t, code, output)
			} else if code != 0 || strings.TrimSpace(output) != "{}" {
				t.Fatal(code, output, log)
			}
			reviews, err := e.Reviews()
			if err != nil || len(reviews) != 1 || reviews[0].Execution != map[bool]string{true: "not_executed", false: "awaiting_execution"}[tc.deny] {
				t.Fatal("incorrect execution state", reviews, err)
			}
		})
	}
}

func TestClaudePreToolUseFailuresDeny(t *testing.T) {
	for _, tc := range []string{"control_plane_down", "decision_timeout", "malformed_json", "missing_fields", "unknown_decision", "wrong_call", "trailing_json", "already_executed"} {
		t.Run(tc, func(t *testing.T) {
			cwd, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				if r.URL.Path != "/api/v1/reviews" {
					w.Write([]byte(`{}`))
					return
				}
				if tc == "decision_timeout" {
					<-r.Context().Done()
					return
				}
				if tc == "malformed_json" {
					w.Write([]byte(`{"decision":`))
					return
				}
				v := map[string]any{"id": hash(hash("claude", "abc123", cwd), "call"), "decision": "approve", "comment": "allowed", "ruleId": "A7", "execution": "awaiting_execution", "deadline": time.Now().Add(time.Minute)}
				switch tc {
				case "missing_fields":
					delete(v, "ruleId")
				case "unknown_decision":
					v["decision"] = "allow"
				case "wrong_call":
					v["id"] = "other-call"
				case "already_executed":
					v["execution"] = "succeeded"
				}
				json.NewEncoder(w).Encode(v)
				if tc == "trailing_json" {
					w.Write([]byte(`{}`))
				}
			}))
			defer srv.Close()
			if tc == "control_plane_down" {
				srv.Close()
			}
			path := filepath.Join(t.TempDir(), "connection.json")
			if err := os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "fixture"}), 0600); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			code, output, _ := invoke("claude", path, claudePayload(cwd, "call", "Read", map[string]any{"file_path": "README.md"}))
			assertClaudeDeny(t, code, output)
			if elapsed := time.Since(start); elapsed >= 5*time.Second {
				t.Fatalf("bridge exceeded generated hook budget: %s", elapsed)
			}
		})
	}
}

func TestClaudeHumanApprovalRetryBinding(t *testing.T) {
	e, path, cwd := fixture(t)
	payload := claudePayload(cwd, "human", "Bash", map[string]any{"command": "echo fixture"})
	type result struct {
		code   int
		output string
	}
	done := make(chan result, 1)
	go func() {
		code, output, _ := invoke("claude", path, payload)
		done <- result{code, output}
	}()
	select {
	case got := <-done:
		assertClaudeDeny(t, got.code, got.output)
		if !strings.Contains(got.output, "pending approval in TG-Sentry console; retry after approval") {
			t.Fatal("missing retry instruction", got.output)
		}
	case <-time.After(5 * time.Second):
		// Release the legacy polling implementation when proving RED.
		rs, _ := e.Reviews()
		for _, r := range rs {
			e.Disconnect(r.InstanceID)
		}
		<-done
		t.Fatal("human approval blocked beyond hook budget")
	}
	rs, err := e.Reviews()
	if err != nil || len(rs) != 1 || !rs[0].NeedsHuman || rs[0].Decision != "pending" {
		t.Fatal("pending review was not preserved", rs, err)
	}
	r := rs[0]
	if _, err = e.Decide(core.WithActor(context.Background(), core.SystemActor("test")), r.ID, "wrong-digest", "approve", ""); err == nil {
		t.Fatal("wrong digest approved")
	}
	if _, err = e.Decide(core.WithActor(context.Background(), core.SystemActor("test")), r.ID, r.Digest, "approve", ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, call, command string
		deny                bool
	}{
		{"identical_retry", "human", "echo fixture", false},
		{"changed_arguments", "human", "echo changed", true},
		{"changed_call_id", "other", "echo fixture", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, output, log := invoke("claude", path, claudePayload(cwd, tc.call, "Bash", map[string]any{"command": tc.command}))
			if tc.deny {
				assertClaudeDeny(t, code, output)
			} else if code != 0 || strings.TrimSpace(output) != "{}" {
				t.Fatal(code, output, log)
			}
		})
	}
	post := claudePayload(cwd, "human", "Bash", nil)
	post["hook_event_name"] = "PostToolUse"
	post["tool_response"] = map[string]any{"stdout": "fixture", "exit_code": 0}
	if code, _, log := invoke("claude", path, post); code != 0 {
		t.Fatal(log)
	}
	code, output, _ := invoke("claude", path, payload)
	assertClaudeDeny(t, code, output)
}

func TestClaudePreToolUseAggregateDeadline(t *testing.T) {
	cwd := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "fixture"}), 0600); err != nil {
		t.Fatal(err)
	}
	var out, log bytes.Buffer
	start := time.Now()
	code := Run("claude", path, bytes.NewReader(mustJSON(claudePayload(cwd, "call", "Read", map[string]any{"file_path": "README.md"}))), &out, &log)
	assertClaudeDeny(t, code, out.String())
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("registration retries exceeded hook budget: %s", elapsed)
	}
}

func TestClaudeGrokEnvironmentCannotBypassReview(t *testing.T) {
	t.Setenv("GROK_HOOK_EVENT", "PreToolUse")
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, mustJSON(Config{Endpoint: "http://127.0.0.1:1", Token: "fixture"}), 0600); err != nil {
		t.Fatal(err)
	}
	code, output, _ := invoke("claude", path, claudePayload(t.TempDir(), "denied", "Bash", map[string]any{"command": "passwd fixture"}))
	assertClaudeDeny(t, code, output)
}

func assertClaudeLocalIOBounded(t *testing.T, path string, input io.Reader) string {
	t.Helper()
	type result struct {
		code   int
		output string
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		var out, log bytes.Buffer
		code := Run("claude", path, input, &out, &log)
		done <- result{code, out.String()}
	}()
	select {
	case got := <-done:
		assertClaudeDeny(t, got.code, got.output)
		t.Logf("local I/O denied after %s", time.Since(start))
		return got.output
	case <-time.After(5 * time.Second): // Existing generated command-hook budget.
		t.Fatal("local I/O exceeded hook budget")
		return ""
	}
}

func TestClaudeFIFOConnectionFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX FIFOs")
	}
	path := filepath.Join(t.TempDir(), "connection.json")
	if output, err := exec.Command("mkfifo", path).CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	// Release the old blocking ReadFile after RED without leaving a stuck reader.
	t.Cleanup(func() {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			f.Close()
		}
	})
	output := assertClaudeLocalIOBounded(t, path, bytes.NewReader(mustJSON(claudePayload(t.TempDir(), "fifo", "Bash", map[string]any{"command": "passwd fixture"}))))
	if !strings.Contains(output, "无法读取 Hook 连接配置") {
		t.Fatal("FIFO was not refused as a connection file", output)
	}
}

func TestClaudeSlowStdinFailsClosed(t *testing.T) {
	for _, stage := range []string{"first_decode", "trailing_eof"} {
		t.Run(stage, func(t *testing.T) {
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			var input io.Reader = reader
			if stage == "trailing_eof" {
				input = io.MultiReader(bytes.NewReader(mustJSON(claudePayload(t.TempDir(), "slow", "Bash", map[string]any{"command": "passwd fixture"}))), reader)
			}
			assertClaudeLocalIOBounded(t, filepath.Join(t.TempDir(), "missing.json"), input)
		})
	}
}

func TestReadConnectionFollowsSymlinkToRegularFileOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink and FIFO creation need POSIX semantics")
	}
	dir := t.TempDir()
	regular, fifo := filepath.Join(dir, "regular.json"), filepath.Join(dir, "fifo")
	if err := os.WriteFile(regular, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("mkfifo", fifo).CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	toRegular, toFIFO := filepath.Join(dir, "to-regular"), filepath.Join(dir, "to-fifo")
	if err := os.Symlink(regular, toRegular); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, toFIFO); err != nil {
		t.Fatal(err)
	}
	if data, err := readConnection(toRegular); err != nil || string(data) != `{}` {
		t.Fatal("symlink to a regular connection file was refused", err)
	}
	if _, err := readConnection(toFIFO); err == nil {
		t.Fatal("symlink to a FIFO was accepted")
	}
}
