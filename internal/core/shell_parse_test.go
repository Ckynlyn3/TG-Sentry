package core

import (
	"strings"
	"testing"
)

// Issue #71 follows the existing E_BTPII terminal operational-failure path,
// not a dangerous-command finding. Commands below are parsed, never executed.
func TestShellParseFailurePrecedence(t *testing.T) {
	allow := Rule{ID: "U_ALLOW", Name: "Allow", Enabled: true, Matcher: "contains", Pattern: "echo", Decision: "approve"}
	alert := allow
	alert.ID, alert.Decision = "U_ALERT", "alert"
	deny := allow
	deny.ID, deny.Decision = "U_DENY", "reject"
	for _, tc := range []struct {
		name, command, want string
		rules               []Rule
	}{
		{"malformed", `echo "`, "E_SHELL_PARSE", nil},
		{"recursive-malformed", `bash -c 'echo "'`, "E_SHELL_PARSE", nil},
		{"before-approve", `echo "`, "E_SHELL_PARSE", []Rule{allow}},
		{"before-alert", `echo "`, "E_SHELL_PARSE", []Rule{alert}},
		{"custom-deny-wins", `echo "`, "U_DENY", []Rule{allow, deny}},
		{"builtin-deny-wins", `rm -rf /; bash -c 'echo "'`, "R_SYS_PATH", BuiltinRules()},
		{"well-formed-approve", `echo "fixture"`, "U_ALLOW", []Rule{allow}},
		{"well-formed-fallback", `echo "fixture"`, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluate(ReviewInput{ToolName: "Bash", Arguments: map[string]any{"command": tc.command}}, tc.rules)
			if tc.want == "" {
				if d != nil {
					t.Fatalf("well-formed command no longer reaches fallback: %+v", d)
				}
				return
			}
			wantDecision := "reject"
			if tc.want == "U_ALLOW" {
				wantDecision = "approve"
			}
			if d == nil || d.RuleID != tc.want || d.Decision != wantDecision {
				t.Fatalf("got %+v, want %s/%s", d, wantDecision, tc.want)
			}
			if tc.want == "E_SHELL_PARSE" && strings.Contains(d.Comment, tc.command) {
				t.Fatal("parse diagnostic echoed untrusted command")
			}
		})
	}
}

func TestShellParseMatcherStatus(t *testing.T) {
	for _, tc := range []struct {
		name, command     string
		builtin, detailed bool
	}{
		{"malformed", `echo "`, true, true},
		{"recursive", `bash -c 'echo "'; bash -c 'echo fixture'`, false, true},
		{"well-formed", `echo fixture`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := ReviewInput{ToolName: "Bash", Arguments: map[string]any{"cmd": tc.command}}
			hits, failed := builtinMatches(in, "")
			if len(hits) != 0 || failed != tc.builtin {
				t.Fatalf("builtin: hits=%v parseFailed=%t", hits, failed)
			}
			hits, failed = detailedBuiltinMatches(in, "", policyPath, "linux")
			if len(hits) != 0 || failed != tc.detailed {
				t.Fatalf("detailed: hits=%v parseFailed=%t", hits, failed)
			}
		})
	}
	// A source-writing tool does not parse examples in content as shell commands.
	if d := Evaluate(ReviewInput{ToolName: "Write", Arguments: map[string]any{"content": `echo "`}}, nil); d != nil {
		t.Fatalf("non-shell content treated as a parse failure: %+v", d)
	}
}

func TestShellParseDeepNestingUnavailable(t *testing.T) {
	// Reuse #70's exact 2 MiB workload, beyond the pinned upstream maxNesting.
	deeplyNestedShellInputs(t, "echo ", func(t *testing.T, command string) {
		d := Evaluate(ReviewInput{ToolName: "Bash", Arguments: map[string]any{"command": command}}, BuiltinRules())
		if d == nil || d.Decision != "reject" || d.RuleID != "E_SHELL_PARSE" {
			t.Fatalf("got %+v, want terminal E_SHELL_PARSE reject", d)
		}
	}, "(", "$((")
}

func TestShellParseCaptureDiagnosticUnchanged(t *testing.T) {
	files, status := CaptureScripts("", "Bash", map[string]any{"command": `echo "`})
	// This is the existing CaptureScripts diagnostic, not new UI copy.
	if status != "incomplete" || len(files) != 1 || files[0].Complete || files[0].ReadError != "无法静态解析当前 Shell 命令" {
		t.Fatalf("capture diagnostic changed: status=%q files=%+v", status, files)
	}
}

func TestShellParseReviewRejectsBeforeFallback(t *testing.T) {
	for _, mode := range []string{"human", "model"} {
		t.Run(mode, func(t *testing.T) {
			e := engine(t)
			e.Settings.Mode = mode
			r, err := e.Submit(input("parse-failure", "Bash", map[string]any{"command": `echo "`}))
			if err != nil {
				t.Fatal(err)
			}
			if r.Decision != "reject" || r.RuleID != "E_SHELL_PARSE" || r.ReviewPath != "rule" || r.NeedsHuman || r.Execution != "not_executed" || r.ModelInput != nil {
				t.Fatalf("parse failure reached reviewer fallback: decision=%q rule=%q path=%q human=%t execution=%q modelInput=%t", r.Decision, r.RuleID, r.ReviewPath, r.NeedsHuman, r.Execution, r.ModelInput != nil)
			}
			if r.SensitiveInfo != nil && len(r.SensitiveInfo.Findings) != 0 {
				t.Fatal("parse failure synthesized sensitive findings")
			}
			page, err := e.RiskEvents(0, "", RiskEventFilter{})
			if err != nil || len(page.Items) != 0 {
				t.Fatal("operational failure became a risk finding", page, err)
			}
		})
	}
}
