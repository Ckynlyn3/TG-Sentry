package main

import (
	"aegishook/internal/bridge"
	"aegishook/internal/core"
	"aegishook/internal/server"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// Build the actual executable and pass native Claude payloads through its stdin.
// The server uses the real handler and disposable SQLite/Postgres, never a mock verdict.
func TestRuntimeBridgeBinary(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "aegishook")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := server.New(e, fstest.MapFS{}, "fixture-admin", "fixture-local", t.TempDir())
	live := httptest.NewServer(s.Handler())
	defer live.Close()
	enroll := func(name string) core.ClientConnection {
		t.Helper()
		key, err := e.CreateEnrollment(core.WithActor(context.Background(), core.SystemActor("test")), name)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := e.EnrollClient(key.Code, runtime.GOOS)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	a, b := enroll("A"), enroll("B")
	// The bridge supplies the enrolled host's native platform.
	cwd := t.TempDir()
	rule := core.Rule{ID: "U_BOUND", Name: "bound deny", ScopeOnly: true, Enabled: true, Decision: "reject", Matcher: "contains", Target: "arguments", Field: "file_path", Pattern: "protected.txt"}
	if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
		t.Fatal(err)
	}
	if err := e.SaveScope(core.WithActor(context.Background(), core.SystemActor("test")), core.Scope{ID: "A", Name: "A policy", NodeID: a.NodeID, Platform: runtime.GOOS, Project: cwd, RuleIDs: []string{rule.ID}}); err != nil {
		t.Fatal(err)
	}
	run := func(name string, cfg bridge.Config, tool string, args map[string]any, want int) {
		t.Helper()
		connection := filepath.Join(t.TempDir(), "connection.json")
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(connection, data, 0600); err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "runtime-session", "cwd": cwd, "tool_use_id": core.ID(), "tool_name": tool, "tool_input": args})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "hook", "--agent", "claude", "--connection", connection)
		cmd.Stdin = bytes.NewReader(payload)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		started := time.Now()
		err = cmd.Run()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		if code != want {
			t.Fatalf("%s: exit=%d stdout=%s stderr=%s", name, code, out.String(), stderr.String())
		}
		var response map[string]any
		if err := json.Unmarshal(out.Bytes(), &response); err != nil {
			t.Fatalf("%s: invalid native verdict: %v", name, err)
		}
		if want == 0 && len(response) != 0 {
			t.Fatalf("%s: permit bypasses Claude permissions: %s", name, out.String())
		}
		if want == 2 && !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
			t.Fatalf("%s: no explicit denial: %s", name, out.String())
		}
		// Vendor hook timeout is 5 seconds; bridge's existing total budget is 4.5 seconds.
		if time.Since(started) >= 5*time.Second {
			t.Fatalf("%s: exceeded native hook budget", name)
		}
		t.Logf("%s: exit %d, native verdict verified", name, code)
	}
	cfg := bridge.Config{Endpoint: live.URL, Token: a.Token, NodeID: a.NodeID, BundlePublicKey: a.BundlePublicKey}
	run("valid benign", cfg, "Read", map[string]any{"file_path": "README.md"}, 0)
	run("bound denied", cfg, "Read", map[string]any{"file_path": "protected.txt"}, 2)
	run("other policy allowed", bridge.Config{Endpoint: live.URL, Token: b.Token, NodeID: b.NodeID, BundlePublicKey: b.BundlePublicKey}, "Read", map[string]any{"file_path": "protected.txt"}, 0)
	run("global deny A", cfg, "Bash", map[string]any{"command": "redis-cli FLUSHALL"}, 2)
	run("global deny B", bridge.Config{Endpoint: live.URL, Token: b.Token, NodeID: b.NodeID, BundlePublicKey: b.BundlePublicKey}, "Bash", map[string]any{"command": "redis-cli FLUSHALL"}, 2)
	invalid := cfg
	invalid.Token = "invalid"
	run("invalid credential", invalid, "Read", map[string]any{"file_path": "README.md"}, 2)
	forged := cfg
	forged.Token = b.Token
	run("other device credential", forged, "Read", map[string]any{"file_path": "README.md"}, 2)
	forged = cfg
	forged.NodeID = b.NodeID
	run("other device ID", forged, "Read", map[string]any{"file_path": "README.md"}, 2)
	run("legacy local allowed", bridge.Config{Endpoint: live.URL, Token: "fixture-local"}, "Read", map[string]any{"file_path": "README.md"}, 0)
	// Device identity in the risk event must come from enrollment, not the hook.
	events, err := e.RiskEvents(20, "", core.RiskEventFilter{Agent: a.NodeID + "/claude"})
	if err != nil || len(events.Items) == 0 {
		t.Fatalf("missing enrolled risk events: %v", err)
	}
	for _, event := range events.Items {
		if event.Data.Actor.AppUID != a.NodeID+"/claude" {
			t.Fatal("risk event identity mismatch")
		}
	}
	live.Close()
	run("control plane down", cfg, "Read", map[string]any{"file_path": "README.md"}, 2)
}
