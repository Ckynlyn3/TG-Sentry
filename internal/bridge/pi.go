package bridge

import "errors"

// Pi 1.3.0 ExtensionAPI tool_call / tool_execution_end fields:
// node_modules/@earendil-works/pi-coding-agent/dist/core/extensions/types.d.ts.
// Translate once, then reuse the bridge's signed cache, polling and result flow.
func normalizePi(m map[string]any) (map[string]any, error) {
	out := map[string]any{
		"session_id": text(m, "sessionId"), "cwd": text(m, "cwd"),
		"tool_use_id": text(m, "toolCallId"), "tool_name": text(m, "toolName"),
		"userMessage": text(m, "userMessage"),
	}
	switch eventName(m) {
	case "session_start":
		state := "idle"
		if raw, exists := m["state"]; exists {
			value, ok := raw.(string)
			if !ok || !contains(value, "idle", "running", "awaiting_review") {
				return nil, errors.New("invalid Pi activity state")
			}
			state = value
		}
		out["hook_event_name"], out["state"] = "SessionStart", state
	case "session_shutdown":
		out["hook_event_name"] = "SessionEnd"
	case "tool_call":
		args, ok := m["input"].(map[string]any)
		if !ok || args == nil || text(m, "toolCallId") == "" || text(m, "toolName") == "" {
			return nil, errors.New("invalid Pi tool call")
		}
		out["hook_event_name"], out["tool_input"] = "PreToolUse", args
	case "tool_execution_end":
		failed, ok := m["isError"].(bool)
		if !ok || text(m, "toolCallId") == "" {
			return nil, errors.New("invalid Pi tool result")
		}
		state := "succeeded"
		if failed {
			state = "failed"
		}
		if raw, exists := m["executionState"]; exists {
			value, ok := raw.(string)
			if !ok || (value != state && value != "not_executed") {
				return nil, errors.New("invalid Pi execution state")
			}
			state = value
		}
		if _, exists := m["result"]; !exists {
			return nil, errors.New("missing Pi tool result")
		}
		out["hook_event_name"], out["executionState"] = "PostToolUse", state
		out["tool_response"] = m["result"]
	}
	return out, nil
}
