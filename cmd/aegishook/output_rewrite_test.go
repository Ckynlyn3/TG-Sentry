package main

import (
	"aegishook/internal/bridge"
	"aegishook/internal/core"
	"aegishook/internal/server"
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRuntimeToolOutputOperation(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "aegishook")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if _, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatal("build runtime fixture failed")
	}
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Register(core.Instance{ID: "output-runtime", Agent: "claude", SessionID: "output-runtime", Cwd: t.TempDir(), HookVersion: core.Version}); err != nil {
		t.Fatal(err)
	}
	review, err := e.Submit(core.ReviewInput{InstanceID: "output-runtime", CallID: "call", ToolName: "Read", Arguments: map[string]any{"file_path": "README.md"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), core.Rule{ID: "U_OUTPUT", Name: "Output fixture", Matcher: "contains", Pattern: "private-fixture", Decision: "redact", Enabled: true, Categories: []string{core.SensitiveInfoCategory}}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.New(e, fstest.MapFS{}, "fixture-admin", "fixture-local", t.TempDir()).Handler())
	defer srv.Close()
	connection := filepath.Join(t.TempDir(), "connection.json")
	cfg, _ := json.Marshal(bridge.Config{Endpoint: srv.URL, Token: "fixture-local"})
	if err = os.WriteFile(connection, cfg, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, outcome, text string }{{"benign", "unchanged", ""}, {"😀 private-fixture suffix", "rewritten", "😀 [CUSTOM] suffix"}} {
		body, _ := json.Marshal(core.ToolOutputRequest{Operation: "transform_tool_output", Text: tc.input})
		command := exec.Command(binary, "hook", "--connection", connection, "--review-id", review.ID)
		command.Stdin = bytes.NewReader(body)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		reply, decodeErr := core.DecodeToolOutputResponse(stdout.Bytes())
		if err != nil || decodeErr != nil || stderr.Len() != 0 || reply.Outcome != tc.outcome || reply.Text != nil && *reply.Text != tc.text {
			t.Fatal("binary did not return the separate transform operation")
		}
	}
	command := exec.Command(binary, "hook", "--connection", connection, "--review-id", review.ID)
	command.Stdin = strings.NewReader(`{"operation":"transform_tool_output","text":"private-fixture"} trailing`)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if command.Run() == nil || stdout.Len() != 0 || strings.TrimSpace(stderr.String()) != "Tool output transformation unavailable" {
		t.Fatal("binary malformed-input fallback leaked data or denied session")
	}
}
