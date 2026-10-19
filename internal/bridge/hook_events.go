package bridge

// handled mirrors core.hookEvents / core.cursorHookEvents, including OpenCode's
// translated bridge contract (adapter/opencode.mjs), not its raw plugin schema.
// advisory names are documented but not installed/handled: recognize them as
// no-ops, never reinterpret their different payloads as tool reviews or results.
var familyHookEvents = map[string]struct{ handled, advisory []string }{
	// https://code.claude.com/docs/en/hooks#hook-lifecycle
	"claude": {
		handled: []string{"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit", "PostToolUseFailure"},
		advisory: []string{
			"Setup", "UserPromptExpansion", "PermissionRequest", "PermissionDenied", "PostToolBatch",
			"Notification", "MessageDisplay", "SubagentStart", "SubagentStop", "TaskCreated", "TaskCompleted",
			"Stop", "StopFailure", "TeammateIdle", "InstructionsLoaded", "ConfigChange", "CwdChanged",
			"DirectoryAdded", "FileChanged", "WorktreeCreate", "WorktreeRemove", "PreCompact", "PostCompact",
			"PreModelSwitch", "PostModelSwitch", "Elicitation", "ElicitationResult",
		},
	},
	// https://learn.chatgpt.com/docs/hooks#supported-events
	"codex": {
		handled:  []string{"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit"},
		advisory: []string{"SubagentStart", "SubagentStop", "PermissionRequest", "PreCompact", "PostCompact", "Stop", "Interrupt"},
	},
	// https://docs.x.ai/build/features/hooks#events
	"grok": {
		handled:  []string{"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit", "PostToolUseFailure"},
		advisory: []string{"PermissionDenied", "Stop", "StopFailure", "Notification", "SubagentStart", "SubagentStop", "PreCompact", "PostCompact"},
	},
	// https://opencode.ai/docs/plugins/#events and #compaction-hooks;
	// chat.message is used by the installed adapter, without calling the bridge.
	"opencode": {
		handled: []string{"SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "UserPromptSubmit", "PostToolUseFailure"},
		advisory: []string{
			"chat.message", "command.executed", "file.edited", "file.watcher.updated", "installation.updated",
			"lsp.client.diagnostics", "lsp.updated", "message.part.removed", "message.part.updated",
			"message.removed", "message.updated", "permission.asked", "permission.replied", "server.connected",
			"session.created", "session.compacted", "session.deleted", "session.diff", "session.error",
			"session.idle", "session.status", "session.updated", "shell.env", "tool.execute.after", "tool.execute.before",
			"tui.prompt.append", "tui.command.execute", "tui.toast.show", "experimental.session.compacting",
		},
	},
	// https://cursor.com/docs/hooks.md (Reference / Hook events)
	"cursor": {
		handled: []string{"beforeSubmitPrompt", "preToolUse", "postToolUse", "postToolUseFailure", "afterAgentResponse", "stop", "afterFileEdit", "sessionStart", "sessionEnd"},
		advisory: []string{
			"subagentStart", "subagentStop", "beforeShellExecution", "afterShellExecution", "beforeMCPExecution",
			"afterMCPExecution", "beforeReadFile", "beforeTabFileRead", "afterTabFileEdit", "afterAgentThought",
			"preCompact", "workspaceOpen",
		},
	},
}
