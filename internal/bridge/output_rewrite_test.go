package bridge

import (
	"aegishook/internal/core"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransformToolOutputBridge(t *testing.T) {
	e, connection, cwd := fixture(t)
	if code, _, _ := invoke("claude", connection, native("claude", cwd, "rewrite", "Read", "PreToolUse", map[string]any{"file_path": "README.md"})); code != 0 {
		t.Fatal("review setup failed")
	}
	id := hash(hash("claude", "session", cwd), "rewrite")
	rule := core.Rule{ID: "U_OUTPUT", Name: "Output fixture", Matcher: "contains", Pattern: "private-fixture", Decision: "redact", Enabled: true, Tool: "Read", Categories: []string{core.SensitiveInfoCategory}}
	if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("test")), rule); err != nil {
		t.Fatal(err)
	}
	var output, log bytes.Buffer
	code := RunToolOutput(connection, id, strings.NewReader(`{"operation":"transform_tool_output","text":"😀 private-fixture suffix"}`), &output, &log)
	response, err := core.DecodeToolOutputResponse(output.Bytes())
	if code != 0 || err != nil || response.Outcome != "rewritten" || response.Text == nil || *response.Text != "😀 [CUSTOM] suffix" || log.Len() != 0 {
		t.Fatal("bridge did not emit original-leaf replacement")
	}
	saved, err := e.Review(id)
	if err != nil || saved.Execution != "awaiting_execution" {
		t.Fatal("bridge rewrite changed terminal execution")
	}
}

func TestTransformToolOutputBridgeMalformedReplies(t *testing.T) {
	for _, body := range []string{`{"ok":true}`, `{"outcome":"withheld","text":"raw-fixture"}`, `{"outcome":"rewritten","text":null}`, `{"outcome":"unchanged"} {}`, `{"outcome":"unchanged"}` + strings.Repeat(" ", core.ToolOutputJSONBytes)} {
		t.Run("reply", func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/api/v1/reviews/"+strings.Repeat("a", 64)+"/transform-tool-output" || r.Header.Get("Authorization") != "Bearer synthetic-test-only" {
					t.Error("wrong authenticated operation")
				}
				var payload map[string]string
				if json.NewDecoder(r.Body).Decode(&payload) != nil || len(payload) != 2 || payload["text"] != "private-fixture" {
					t.Error("wire is not the two-field request")
				}
				w.Write([]byte(body))
			}))
			defer srv.Close()
			connection := filepath.Join(t.TempDir(), "connection.json")
			if err := os.WriteFile(connection, mustJSON(Config{Endpoint: srv.URL, Token: "synthetic-test-only"}), 0600); err != nil {
				t.Fatal(err)
			}
			var output, log bytes.Buffer
			code := RunToolOutput(connection, strings.Repeat("a", 64), strings.NewReader(`{"operation":"transform_tool_output","text":"private-fixture"}`), &output, &log)
			if code != 1 || output.Len() != 0 || strings.TrimSpace(log.String()) != "Tool output transformation unavailable" {
				t.Fatal("invalid bridge reply leaked data or became success")
			}
		})
	}
}

func TestTransformToolOutputBridgeInvalidInputs(t *testing.T) {
	for _, tc := range []struct{ connection, id, body string }{{"missing", strings.Repeat("a", 64), `{}`}, {"missing", "../result", `{"operation":"transform_tool_output","text":""}`}, {"missing", strings.Repeat("a", 64), strings.Repeat("x", core.ToolOutputJSONBytes+1)}} {
		var output, log bytes.Buffer
		if RunToolOutput(tc.connection, tc.id, strings.NewReader(tc.body), &output, &log) != 1 || output.Len() != 0 || strings.TrimSpace(log.String()) != "Tool output transformation unavailable" {
			t.Fatal("invalid transform invocation became session denial or leaked data")
		}
	}
}
