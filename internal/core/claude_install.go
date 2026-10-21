package core

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// https://code.claude.com/docs/en/hooks: onFailure requires v2.1.295.
// Unknown/prerelease versions are not evidence of support.
func claudeSupportsFailureBlock(version string) bool {
	fields := strings.Fields(version)
	if len(fields) == 0 {
		return false
	}
	v, _, _ := strings.Cut(fields[0], "+")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	var numbers [3]int
	for n, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return false
		}
		numbers[n] = value
	}
	return numbers[0] > 2 || numbers[0] == 2 && (numbers[1] > 1 || numbers[1] == 1 && numbers[2] >= 295)
}

func prepareClaudeHook(i Installation) (Installation, string) {
	// The snapshot, not the installed CLI version, owns future drift/uninstall checks.
	i.ManagedContent = ""
	group := hookGroup(i, "PreToolUse")
	hook := group["hooks"].([]any)[0].(map[string]any)
	// AgentSentry command-hook precedent: docs/research/ENDPOINT-RUNTIME-AgentSentry.md §4.
	hook["timeout"] = 5
	// Reuse DetectAgents' existing bounded --version probe and 3-second budget.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "claude", "--version")
	// Bound inherited output pipes too; reuse the existing probe budget.
	// https://pkg.go.dev/os/exec#Cmd.WaitDelay
	cmd.WaitDelay = 3 * time.Second
	version, err := cmd.Output()
	warning := "Claude Code >=2.1.295 could not be confirmed; onFailure omitted, host-side hook failures may fail open; upgrade and reinstall"
	if err == nil && claudeSupportsFailureBlock(string(version)) {
		hook["onFailure"] = "block"
		warning = ""
	}
	i.ManagedContent = string(mustJSON(group))
	return i, warning
}
