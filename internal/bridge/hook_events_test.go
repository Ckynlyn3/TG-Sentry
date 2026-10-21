package bridge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Installer contracts: core/install_agents.go:hookEvents and
// core/cursor_install.go:cursorHookEvents. OpenCode translates native plugin
// callbacks into these bridge names in adapter/opencode.mjs.
var registeredHookEvents = map[string][]string{
	"claude":   {"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit", "PostToolUseFailure"},
	"codex":    {"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit"},
	"grok":     {"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit", "PostToolUseFailure"},
	"opencode": {"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit", "PostToolUseFailure"},
	"cursor":   {"beforeSubmitPrompt", "preToolUse", "postToolUse", "postToolUseFailure", "afterAgentResponse", "stop", "afterFileEdit", "sessionStart", "sessionEnd"},
}

// Names transcribed independently from the vendor catalogs cited by hook_events.go.
// These are recognized, not newly implemented enforcement/correlation handlers.
var documentedExtraHookEvents = map[string][]string{
	"claude":   {"Setup", "UserPromptExpansion", "PermissionRequest", "PermissionDenied", "PostToolBatch", "Notification", "MessageDisplay", "SubagentStart", "SubagentStop", "TaskCreated", "TaskCompleted", "Stop", "StopFailure", "TeammateIdle", "InstructionsLoaded", "ConfigChange", "CwdChanged", "DirectoryAdded", "FileChanged", "WorktreeCreate", "WorktreeRemove", "PreCompact", "PostCompact", "PreModelSwitch", "PostModelSwitch", "Elicitation", "ElicitationResult"},
	"codex":    {"SubagentStart", "SubagentStop", "PermissionRequest", "PreCompact", "PostCompact", "Stop", "Interrupt"},
	"grok":     {"PermissionDenied", "Stop", "StopFailure", "Notification", "SubagentStart", "SubagentStop", "PreCompact", "PostCompact"},
	"opencode": {"chat.message", "command.executed", "file.edited", "file.watcher.updated", "installation.updated", "lsp.client.diagnostics", "lsp.updated", "message.part.removed", "message.part.updated", "message.removed", "message.updated", "permission.asked", "permission.replied", "server.connected", "session.created", "session.compacted", "session.deleted", "session.diff", "session.error", "session.idle", "session.status", "session.updated", "shell.env", "tool.execute.after", "tool.execute.before", "tui.prompt.append", "tui.command.execute", "tui.toast.show", "experimental.session.compacting"},
	"cursor":   {"subagentStart", "subagentStop", "beforeShellExecution", "afterShellExecution", "beforeMCPExecution", "afterMCPExecution", "beforeReadFile", "beforeTabFileRead", "afterTabFileEdit", "afterAgentThought", "preCompact", "workspaceOpen"},
}

func eventConfig(t *testing.T, requests *atomic.Int32) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, mustJSON(Config{Endpoint: srv.URL, Token: "fixture"}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func eventPayload(agent, cwd, event string) map[string]any {
	if agent == "cursor" {
		p := cursorTool(cwd, "call", event, "Read", map[string]any{"file_path": "README.md"})
		p["prompt"], p["tool_output"], p["failure_type"] = "fixture", `{}`, "error"
		return p
	}
	return native(agent, cwd, "call", "Read", event, map[string]any{"file_path": "README.md"})
}

func assertNativeEventDeny(t *testing.T, agent string, code int, output string) {
	t.Helper()
	switch agent {
	case "claude", "codex":
		assertClaudeDeny(t, code, output)
	case "cursor":
		assertCursorDecision(t, code, output, true)
	default:
		var response map[string]any
		if err := json.Unmarshal([]byte(output), &response); err != nil {
			t.Fatal(err, output)
		}
		decision, reason := "deny", "reason"
		if agent == "opencode" {
			decision, reason = "reject", "comment"
		}
		if code != 2 || response["decision"] != decision || response[reason] == "" || response[reason] == nil {
			t.Fatal("not a native denial", code, output)
		}
	}
}

func TestAllFamiliesUnknownEventDeniesBeforeConfig(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "grok", "opencode", "cursor"} {
		for _, available := range []bool{true, false} {
			name := agent + "/unavailable"
			if available {
				name = agent + "/available"
			}
			t.Run(name, func(t *testing.T) {
				var requests atomic.Int32
				path := filepath.Join(t.TempDir(), "missing.json")
				if available {
					path = eventConfig(t, &requests)
				}
				code, output, log := invoke(agent, path, eventPayload(agent, t.TempDir(), "PreToolUseTypo"))
				assertNativeEventDeny(t, agent, code, output)
				if !strings.Contains(log, "unsupported "+displayHookFamily(agent)+" hook event") {
					t.Fatal("unknown event did not fail before config access", code, output, log)
				}
				if requests.Load() != 0 {
					t.Fatal("unknown event reached control plane")
				}
			})
		}
	}
}

func displayHookFamily(agent string) string {
	return map[string]string{"claude": "Claude Code", "codex": "Codex", "grok": "Grok Build", "opencode": "OpenCode", "cursor": "Cursor"}[agent]
}

func TestAllFamiliesRejectMalformedAndCrossFamilyEvents(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "grok", "opencode", "cursor"} {
		t.Run(agent, func(t *testing.T) {
			wrongCase := "preToolUse"
			if agent == "cursor" {
				wrongCase = "PreToolUse"
			}
			for _, event := range []any{"", nil, false, []any{"PreToolUse"}, wrongCase, "SessionStartTypo"} {
				code, output, _ := invoke(agent, "missing-config", map[string]any{"hook_event_name": event})
				assertNativeEventDeny(t, agent, code, output)
			}
		})
	}
	code, output, _ := invoke("codex", "missing-config", map[string]any{"hook_event_name": "PostToolUseFailure"})
	assertClaudeDeny(t, code, output) // Not a documented Codex event.
}

func TestAllFamiliesRegisteredEventsKeepExistingFailureBehavior(t *testing.T) {
	for agent, events := range registeredHookEvents {
		for _, event := range events {
			t.Run(agent+"/"+event, func(t *testing.T) {
				code, output, log := invoke(agent, filepath.Join(t.TempDir(), "missing.json"), eventPayload(agent, t.TempDir(), event))
				if (agent == "claude" && event == "UserPromptSubmit") || (agent == "cursor" && event == "beforeSubmitPrompt") {
					if code != 2 || log == "" || !strings.Contains(output, map[string]string{"claude": `"decision":"block"`, "cursor": `"permission":"deny"`}[agent]) {
						t.Fatal("blocking prompt event failed open", code, output, log)
					}
				} else if event == "PreToolUse" || event == "preToolUse" {
					assertNativeEventDeny(t, agent, code, output)
				} else if code != 1 || output != "" || log == "" {
					t.Fatal("registered passive event no longer advisory", code, output, log)
				}
			})
		}
	}
}

func TestAllFamiliesRegisteredSessionStartStillRegisters(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "grok", "opencode", "cursor"} {
		t.Run(agent, func(t *testing.T) {
			var requests atomic.Int32
			path := eventConfig(t, &requests)
			event := "SessionStart"
			if agent == "cursor" {
				event = "sessionStart"
			}
			code, output, log := invoke(agent, path, eventPayload(agent, t.TempDir(), event))
			if code != 0 || strings.TrimSpace(output) != "{}" || requests.Load() != 1 {
				t.Fatal("registered passive event changed", code, output, log, requests.Load())
			}
		})
	}
}

func TestAllFamiliesDocumentedExtraEventsAreNoops(t *testing.T) {
	for agent, events := range documentedExtraHookEvents {
		t.Run(agent, func(t *testing.T) {
			var requests atomic.Int32
			path := eventConfig(t, &requests)
			for _, event := range events {
				for _, connection := range []string{path, filepath.Join(t.TempDir(), "missing.json")} {
					// Native extras have different schemas (e.g. Cursor workspaceOpen
					// has no conversation); do not require managed tool-event fields.
					code, output, log := invoke(agent, connection, map[string]any{"hook_event_name": event})
					if code != 0 || output != "" {
						t.Fatal("documented extra event was not a no-op", event, code, output, log)
					}
				}
			}
			if requests.Load() != 0 {
				t.Fatal("documented extra event reached control plane")
			}
		})
	}
}
