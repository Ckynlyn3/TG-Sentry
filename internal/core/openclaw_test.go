package core

import "testing"

func TestOpenClawUsesSharedDecisionEngine(t *testing.T) {
	e, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Register(Instance{ID: "openclaw-fixture", Agent: "openclaw", SessionID: "gateway", Cwd: t.TempDir(), HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"exec", map[string]any{"command": "redis-cli FLUSHALL"}, "reject"},
		{"read", map[string]any{"path": "README.md"}, "approve"},
	} {
		r, err := e.Submit(ReviewInput{InstanceID: "openclaw-fixture", CallID: tc.tool, ToolName: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Fatal(err)
		}
		if r.Agent != "openclaw" || r.Decision != tc.want || r.ReviewPath != "rule" {
			t.Fatalf("shared decision = %s/%s/%s", r.Agent, r.Decision, r.ReviewPath)
		}
	}
}
