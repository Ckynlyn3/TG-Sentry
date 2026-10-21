package core

import (
	"strings"
	"testing"
	"time"
)

// Issue #70 reproductions are data only; no command is executed. The 2 MiB
// payload size is the regression workload requested in the issue.
func deeplyNestedShellInputs(t *testing.T, prefix string, check func(*testing.T, string), tokens ...string) {
	t.Helper()
	const inputBytes = 2 << 20
	for _, token := range tokens {
		name := "parentheses"
		if token == "$((" {
			name = "arithmetic"
		}
		t.Run(name, func(t *testing.T) {
			remaining := inputBytes - len(prefix)
			command := prefix + strings.Repeat(token, remaining/len(token)) + strings.Repeat("(", remaining%len(token))
			if len(command) != inputBytes {
				t.Fatalf("input size = %d, want %d", len(command), inputBytes)
			}
			start := time.Now()
			check(t, command)
			t.Logf("%d-byte %s input returned in %s", len(command), name, time.Since(start))
		})
	}
}

func TestBuiltinMatchesDeepShellNesting(t *testing.T) {
	deeplyNestedShellInputs(t, "", func(t *testing.T, command string) {
		in := ReviewInput{ToolName: "Bash", Arguments: map[string]any{"command": command}}
		// A parse error is reported separately, never as a confident built-in hit.
		if hits, parseFailed := builtinMatches(in, ""); len(hits) != 0 || !parseFailed {
			t.Fatalf("parse-error path: hits=%v parseFailed=%t", hits, parseFailed)
		}
	}, "(", "$((")
}

func TestDetailedBuiltinMatchesDeepShellNesting(t *testing.T) {
	// The echo prefix isolates the mvdan parser crash from inspectWindows'
	// suffix scan; naked-parenthesis timing through that fallback is covered by #21 S1.
	deeplyNestedShellInputs(t, "echo ", func(t *testing.T, command string) {
		in := ReviewInput{ToolName: "Bash", Arguments: map[string]any{"command": command}}
		// The detailed matcher likewise reports incomplete parsing without a hit.
		if hits, parseFailed := detailedBuiltinMatches(in, "", policyPath, "linux"); len(hits) != 0 || !parseFailed {
			t.Fatalf("parse-error path: hits=%v parseFailed=%t", hits, parseFailed)
		}
	}, "$((")
}

func TestCaptureScriptsDeepShellNesting(t *testing.T) {
	deeplyNestedShellInputs(t, "", func(t *testing.T, command string) {
		files, status := CaptureScripts("", "Bash", map[string]any{"command": command})
		if status != "incomplete" || len(files) != 1 || files[0].Complete || files[0].ReadError != "无法静态解析当前 Shell 命令" {
			t.Fatalf("parse-error path must mark capture incomplete: status=%q files=%+v", status, files)
		}
	}, "(", "$((")
}
