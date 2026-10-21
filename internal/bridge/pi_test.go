package bridge

import (
	"aegishook/internal/core"
	"aegishook/internal/server"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
)

// Pi's native event fields are the subprocess contract; only the bridge maps
// them onto the shared review/result lifecycle (adapter/index.ts).
func piEvent(cwd, call, tool, event string, input map[string]any) map[string]any {
	return map[string]any{"hook_event_name": event, "sessionId": "pi-session", "cwd": cwd, "toolCallId": call, "toolName": tool, "input": input}
}

func TestPiMappingLifecycleAndResults(t *testing.T) {
	e, connection, cwd := fixture(t)
	for _, tc := range []struct {
		call, tool, state string
		input             map[string]any
		isError           bool
		code              int
	}{
		{"read", "read", "succeeded", map[string]any{"path": "README.md"}, false, 0},
		{"failed", "read", "failed", map[string]any{"path": "README.md"}, true, 0},
		{"deny", "bash", "not_executed", map[string]any{"command": "passwd fixture"}, true, 2},
	} {
		t.Run(tc.call, func(t *testing.T) {
			code, output, log := invoke("pi", connection, piEvent(cwd, tc.call, tc.tool, "tool_call", tc.input))
			var decision struct{ Decision, Comment string }
			if json.Unmarshal([]byte(output), &decision) != nil || code != tc.code || decision.Comment == "" || decision.Decision != map[int]string{0: "approve", 2: "reject"}[tc.code] {
				t.Fatal(code, output, log)
			}
			post := piEvent(cwd, tc.call, tc.tool, "tool_execution_end", nil)
			post["result"], post["isError"] = map[string]any{"content": "fixture result"}, tc.isError
			if tc.state == "not_executed" {
				post["executionState"] = tc.state
			}
			if code, output, log := invoke("pi", connection, post); code != 0 {
				t.Fatal(code, output, log)
			}
			r, err := e.Review(hash(hash("pi", "pi-session", cwd), tc.call))
			if err != nil || r.Agent != "pi" || r.ToolName != tc.tool || r.Execution != tc.state || (tc.state != "not_executed" && !strings.Contains(r.Result, "fixture result")) {
				t.Fatal(r, err)
			}
		})
	}
	if code, output, log := invoke("pi", connection, piEvent(cwd, "", "", "session_shutdown", nil)); code != 0 {
		t.Fatal(code, output, log)
	}
	instances, _ := e.Instances()
	if len(instances) != 1 || instances[0].SessionID != "pi-session" || instances[0].State != "disconnected" {
		t.Fatal(instances)
	}
}

func TestPiSignedCacheDeniesOfflineAndNeverPermits(t *testing.T) {
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	key, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), "Pi fixture")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), core.Rule{ID: "U_PI_OFFLINE", Name: "cached deny", Enabled: true, Decision: "reject", Matcher: "contains", Pattern: "pi-protected"}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.New(e, fstest.MapFS{}, "admin", "legacy", t.TempDir()).Handler())
	defer srv.Close()
	conn.Endpoint = srv.URL
	connection := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(connection, mustJSON(conn), 0600); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	call := func(id, path string) (int, string, string) {
		return invoke("pi", connection, piEvent(cwd, id, "read", "tool_call", map[string]any{"path": path}))
	}
	if code, output, log := call("online", "README.md"); code != 0 {
		t.Fatal(code, output, log)
	}
	cache := filepath.Join(filepath.Dir(connection), "bundle.json")
	before, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal("signed bundle not cached", err)
	}
	srv.Close()
	if code, output, log := call("offline-deny", "pi-protected"); code != 2 || !strings.Contains(output, "U_PI_OFFLINE") || !strings.Contains(log, "cached policy") {
		t.Fatal(code, output, log)
	}
	if code, output, log := call("offline-permit", "README.md"); code != 2 || strings.Contains(output, `"decision":"approve"`) {
		t.Fatal(code, output, log)
	}
	after, err := os.ReadFile(cache)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("offline call replaced cache", err)
	}
}

func TestPiMalformedInputFailsClosedBeforeNetwork(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `{`, `{} {}`, `{"hook_event_name":"PreToolUse"}`, `{"hook_event_name":"tool_call","sessionId":"s","cwd":"/","toolCallId":"c","toolName":"read","input":[]}`, `{"hook_event_name":"tool_execution_end","isError":"false"}`} {
		var output, log bytes.Buffer
		if code := Run("pi", "missing-config", strings.NewReader(input), &output, &log); code != 2 || !strings.Contains(output.String(), `"decision":"reject"`) {
			t.Fatal(code, output.String(), log.String())
		}
	}
}

func TestPiResultValidationAndNativeIdentity(t *testing.T) {
	for _, state := range []any{nil, false, "", "pending", "failed"} {
		payload := piEvent("/fixture", "call", "read", "tool_execution_end", nil)
		payload["result"], payload["isError"], payload["executionState"] = "result", false, state
		if _, err := normalizePi(payload); err == nil {
			t.Fatalf("accepted invalid result state %v", state)
		}
	}
	payload := piEvent("/fixture", "call", "read", "tool_call", map[string]any{})
	payload["session_id"], payload["tool_use_id"], payload["tool_name"] = "wrong-session", "wrong-call", "wrong-tool"
	mapped, err := normalizePi(payload)
	if err != nil || mapped["session_id"] != "pi-session" || mapped["tool_use_id"] != "call" || mapped["tool_name"] != "read" {
		t.Fatal("native identity overwritten", mapped, err)
	}
}

func TestPiHeartbeatPreservesActivityState(t *testing.T) {
	e, connection, cwd := fixture(t)
	for _, state := range []string{"running", "awaiting_review", "idle"} {
		payload := piEvent(cwd, "", "", "session_start", nil)
		payload["state"] = state
		if code, output, log := invoke("pi", connection, payload); code != 0 {
			t.Fatal(code, output, log)
		}
		instances, err := e.Instances()
		if err != nil || len(instances) != 1 || instances[0].State != state {
			t.Fatalf("heartbeat state: want %s, got %+v (%v)", state, instances, err)
		}
	}
	payload := piEvent(cwd, "", "", "session_start", nil)
	payload["state"] = "unrecognized"
	if _, err := normalizePi(payload); err == nil {
		t.Fatal("accepted invalid heartbeat state")
	}
}
