package core

import "path/filepath"

// Cursor's native flat command schema, event names and failClosed option:
// https://cursor.com/docs/hooks.md#configuration-file
// https://cursor.com/docs/hooks.md#per-script-configuration-options
func cursorHookEvents() []string {
	return []string{"beforeSubmitPrompt", "preToolUse", "postToolUse", "postToolUseFailure", "afterAgentResponse", "stop", "afterFileEdit", "sessionStart", "sessionEnd"}
}

func cursorHookGroup(command string) map[string]any {
	// Reuse the existing AgentSentry-derived 5-second command-hook budget,
	// not Cursor's unspecified platform default (remote-clients.md).
	return map[string]any{"command": command, "timeout": 5, "failClosed": true}
}

// CursorEnterprisePath is a deployment destination, never an installer write target.
// https://cursor.com/docs/hooks.md#configuration and #mdm-distribution
func CursorEnterprisePath(platform string) string {
	switch platform {
	case "windows":
		return `C:\ProgramData\Cursor\hooks.json`
	case "darwin":
		return "/Library/Application Support/Cursor/hooks.json"
	default:
		return "/etc/cursor/hooks.json"
	}
}

func cursorStagingPath(dir string) string {
	return filepath.Join(dir, "managed", "cursor", "hooks.json")
}
