package core

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

// Snapshot new Codex installations without changing ownership of legacy hooks.json.
// AgentSentry's command-hook budget is 5 seconds (ENDPOINT-RUNTIME-AgentSentry §4).
// Codex SessionEnd has a documented maximum of 3 seconds:
// https://learn.chatgpt.com/docs/hooks#config-shape.
func prepareCodexHook(i Installation) Installation {
	i.ManagedContent = ""
	groups := map[string]any{}
	for _, event := range hookEvents("codex") {
		group := hookGroup(i, event)
		hook := group["hooks"].([]any)[0].(map[string]any)
		hook["timeout"] = 5
		if event == "SessionEnd" {
			hook["timeout"] = 3
		}
		groups[event] = group
	}
	i.ManagedContent = string(mustJSON(groups))
	return i
}

// CodexHookTOML emits a standalone config.toml or requirements.toml snippet.
// It never reads connection secrets or writes an administrator-owned system path.
// https://learn.chatgpt.com/docs/hooks#config-shape and #managed-hooks-from-requirementstoml.
func CodexHookTOML(binary, connection string, managed bool) (string, error) {
	for _, path := range []string{binary, connection} {
		if !filepath.IsAbs(path) || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
			return "", errors.New("Codex binary and connection paths must be absolute UTF-8 paths without NUL")
		}
	}
	i := prepareCodexHook(Installation{Agent: "codex", ManagedCommand: hookCommand(binary, connection, "codex", runtime.GOOS)})
	var out strings.Builder
	if managed {
		out.WriteString("allow_managed_hooks_only = true\n\n[features]\nhooks = true\n\n[hooks]\n")
		// Configuration Reference §requirements.toml requires an existing managed
		// script directory. Derive it from the endpoint binary; no invented path.
		key := "managed_dir"
		if runtime.GOOS == "windows" {
			key = "windows_managed_dir"
		}
		fmt.Fprintf(&out, "%s = %s\n\n", key, codexTOMLString(filepath.Dir(binary)))
	}
	for _, event := range hookEvents("codex") {
		hook := hookGroup(i, event)["hooks"].([]any)[0].(map[string]any)
		fmt.Fprintf(&out, "[[hooks.%s]]\n\n[[hooks.%s.hooks]]\ntype = \"command\"\n", event, event)
		command := codexTOMLString(hook["command"].(string))
		fmt.Fprintf(&out, "command = %s\n", command)
		if runtime.GOOS == "windows" {
			fmt.Fprintf(&out, "command_windows = %s\n", command)
		}
		fmt.Fprintf(&out, "timeout = %.0f\n\n", hook["timeout"])
	}
	return out.String(), nil
}

func codexTOMLString(value string) string {
	// JSON escaping is TOML-compatible here; DEL must be escaped too.
	// https://toml.io/en/v1.0.0#string
	return strings.ReplaceAll(string(mustJSON(value)), "\x7f", `\u007f`)
}
