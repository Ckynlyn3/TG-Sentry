package core

import "testing"

// Hermes Agent (github.com/NousResearch/hermes-agent v0.22.2) sends native tool
// names and argument fields: terminal.command/workdir, read_file.path,
// write_file.path, patch.path (tools/terminal_tool.py:1497-1520,
// tools/file_tools.py:1152-1230).
func TestHermesUsesSharedDecisionEngine(t *testing.T) {
	e, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Register(Instance{ID: "hermes-fixture", Agent: "hermes", SessionID: "oneshot", Cwd: t.TempDir(), HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"terminal", map[string]any{"command": "redis-cli FLUSHALL"}, "reject"},
		{"read_file", map[string]any{"path": "README.md"}, "approve"},
	} {
		r, err := e.Submit(ReviewInput{InstanceID: "hermes-fixture", CallID: tc.tool, ToolName: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Fatal(err)
		}
		if r.Agent != "hermes" || r.Decision != tc.want || r.ReviewPath != "rule" {
			t.Fatalf("shared decision = %s/%s/%s", r.Agent, r.Decision, r.ReviewPath)
		}
	}
}

// Native names must classify like their lowercase Pi equivalents without
// rewriting the wire name.
func TestHermesNativeNameClassification(t *testing.T) {
	for _, tc := range []struct{ tool, key, value, rule string }{
		{"read_file", "path", "README.md", "A7"},
		{"write_file", "path", "/etc/fixture", "R2"},
		{"patch", "path", "/etc/fixture", "R2"},
		{"terminal", "command", "passwd fixture", "R1"},
	} {
		if d := Evaluate(ReviewInput{ToolName: tc.tool, Arguments: map[string]any{tc.key: tc.value}}, BuiltinRules()); d == nil || d.RuleID != tc.rule {
			t.Fatalf("%+v: %+v", tc, d)
		}
	}
	dir := t.TempDir()
	for _, tool := range []string{"read_file", "write_file", "patch"} {
		in := ReviewInput{ToolName: tool, Arguments: map[string]any{"path": dir + "/outside"}}
		if d := checkScope(in, dir, []Scope{{Project: dir, Paths: []string{dir + "/allowed"}}}); d == nil || d.RuleID != "SCOPE_PATH" {
			t.Fatalf("%s scope bypass: %+v", tool, d)
		}
	}
}
