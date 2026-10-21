package bridge

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"path/filepath"
)

// Native contracts: https://cursor.com/docs/hooks.md#common-schema and
// #hook-events. Thin normalization follows cc-safety-net src/hosts/cursor/hook.ts
// at 9ef6d15eeb32ee9aec43d667631a6e9a0aad7da2; no vendor code is executed.
func normalizeCursor(m map[string]any) (map[string]any, error) {
	event := eventName(m)
	cwd := text(m, "cwd")
	if cwd == "" {
		if roots, ok := m["workspace_roots"].([]any); ok && len(roots) > 0 {
			cwd, _ = roots[0].(string)
		}
	}
	n := map[string]any{"session_id": text(m, "conversation_id"), "cwd": cwd, "agent_version": text(m, "cursor_version")}
	if n["session_id"] == "" || !filepath.IsAbs(cwd) {
		return nil, errors.New("Cursor requires conversation_id and an absolute cwd/workspace root")
	}
	switch event {
	case "preToolUse", "postToolUse", "postToolUseFailure":
		return cursorToolEvent(m, n, event)
	case "beforeSubmitPrompt":
		prompt, ok := m["prompt"].(string)
		if !ok {
			return nil, errors.New("Cursor beforeSubmitPrompt requires a prompt string")
		}
		// Prompt policy is outside this adapter: mirror UserPromptSubmit capture.
		n["hook_event_name"], n["prompt"] = "UserPromptSubmit", prompt
	case "afterFileEdit":
		// No native call ID: reuse the existing unknown-result observation path.
		n["hook_event_name"] = "PostToolUse"
	case "sessionEnd":
		n["hook_event_name"] = "SessionEnd"
	case "sessionStart", "afterAgentResponse", "stop":
		// stop ends a generation, not the conversation. Only sessionEnd shuts down.
		// Like existing SessionStart hooks, these record instance liveness only.
		n["hook_event_name"] = "SessionStart"
	default:
		return nil, errors.New("unsupported Cursor hook event")
	}
	return n, nil
}

func cursorToolEvent(m, n map[string]any, event string) (map[string]any, error) {
	tool, call := text(m, "tool_name"), text(m, "tool_use_id")
	args, ok := m["tool_input"].(map[string]any)
	if tool == "" || call == "" || !ok || args == nil || !filepath.IsAbs(text(m, "cwd")) {
		return nil, errors.New("Cursor tool event requires tool_name, tool_use_id and tool_input object")
	}
	if tool == "Shell" {
		tool = "Bash" // Existing script capture and command detector alias.
		if value, present := args["working_directory"]; present {
			cwd, ok := value.(string)
			if !ok || !filepath.IsAbs(cwd) {
				return nil, errors.New("Cursor working_directory must be absolute")
			}
			n["cwd"] = cwd
		}
	}
	n["tool_name"], n["tool_use_id"], n["tool_input"] = tool, call, maps.Clone(args)
	switch event {
	case "preToolUse":
		n["hook_event_name"] = "PreToolUse"
	case "postToolUse":
		n["hook_event_name"] = "PostToolUse"
		output, ok := m["tool_output"].(string)
		var result any
		if !ok || json.Unmarshal([]byte(output), &result) != nil {
			return nil, errors.New("Cursor tool_output must contain serialized JSON")
		}
		n["tool_response"] = result
	case "postToolUseFailure":
		failure := text(m, "failure_type")
		if !contains(failure, "timeout", "error", "permission_denied") {
			return nil, errors.New("Cursor failure_type must be timeout, error or permission_denied")
		}
		n["hook_event_name"], n["error"], n["failure_type"] = "PostToolUseFailure", text(m, "error_message"), failure
	}
	return n, nil
}

func cursorDecisionOutput(decision, reason string, out io.Writer) {
	response := map[string]any{"permission": map[string]string{"approve": "allow", "reject": "deny"}[decision]}
	if decision != "approve" {
		response["user_message"], response["agent_message"] = reason, reason
	}
	json.NewEncoder(out).Encode(response)
}
