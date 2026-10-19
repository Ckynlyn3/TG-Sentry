package core

import (
	"reflect"
	"testing"
)

func TestBoundRulesAdditiveUnion(t *testing.T) {
	rules := []Rule{{ID: "global"}, {ID: "bound-A", ScopeOnly: true}, {ID: "bound-B", ScopeOnly: true}}
	for _, tc := range []struct {
		name    string
		scopes  []Scope
		want    []Rule
		missing bool
	}{
		{"legacy globals", nil, rules[:1], false},
		{"explicit empty", []Scope{{RuleIDs: []string{}}}, rules[:1], false},
		{"one policy", []Scope{{RuleIDs: []string{"bound-A"}}}, rules[:2], false},
		{"union and duplicates", []Scope{{RuleIDs: []string{"bound-A", "global"}}, {RuleIDs: []string{"bound-B", "bound-A"}}}, rules, false},
		{"deleted bound rule fails closed", []Scope{{RuleIDs: []string{"missing"}}}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := boundRules(rules, tc.scopes)
			if (err != nil) != tc.missing || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%+v err=%v want=%+v", got, err, tc.want)
			}
			if rules[0].ScopeOnly || rules[1].ID != "bound-A" {
				t.Fatal("input mutated")
			}
		})
	}
}

func TestSaveRuleBindingValidation(t *testing.T) {
	e := engine(t)
	code, err := e.CreateEnrollment(testActorContext(), "policy fixture")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{ID: "U_BOUND", Name: "bound read", ScopeOnly: true, Enabled: true, Decision: "reject", Matcher: "contains", Target: "arguments", Pattern: "protected.txt"}
	if err = e.SaveRule(testActorContext(), rule); err != nil {
		t.Fatal(err)
	}
	scope := Scope{ID: "binding", Name: "policy", NodeID: conn.NodeID, Platform: "linux", Project: "/project", RuleIDs: []string{rule.ID}}
	for _, tc := range []struct {
		name   string
		change func(Scope) Scope
		valid  bool
	}{
		{"valid", func(s Scope) Scope { return s }, true},
		{"local", func(s Scope) Scope { s.NodeID = ""; return s }, false},
		{"missing device", func(s Scope) Scope { s.NodeID = "missing"; return s }, false},
		{"wrong platform", func(s Scope) Scope { s.Platform = "darwin"; return s }, false},
		{"missing rule", func(s Scope) Scope { s.RuleIDs = []string{"missing"}; return s }, false},
		{"global reference remains baseline", func(s Scope) Scope { s.RuleIDs = []string{"A7"}; return s }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := e.SaveScope(testActorContext(), tc.change(scope))
			if (err == nil) != tc.valid {
				t.Fatalf("err=%v valid=%v", err, tc.valid)
			}
		})
	}
	if err := e.RevokeClient(testActorContext(), conn.NodeID); err != nil {
		t.Fatal(err)
	}
	if err := e.SaveScope(testActorContext(), scope); err == nil {
		t.Fatal("revoked binding accepted")
	}
}

func TestSubmitBoundPolicySnapshotAndMissingRule(t *testing.T) {
	e := engine(t)
	code, err := e.CreateEnrollment(testActorContext(), "bound")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []Rule{
		{ID: "U_BOUND_ALLOW", Name: "bound allow", ScopeOnly: true, Enabled: true, Decision: "approve", Matcher: "regex", Target: "arguments", Pattern: ".*"},
		{ID: "U_BOUND_DENY", Name: "bound deny", ScopeOnly: true, Enabled: true, Decision: "reject", Matcher: "contains", Target: "arguments", Pattern: "protected.txt"},
	} {
		if err := e.SaveRule(testActorContext(), r); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"U_BOUND_ALLOW", "U_BOUND_DENY"} {
		if err := e.SaveScope(testActorContext(), Scope{ID: id, Name: id, NodeID: conn.NodeID, Platform: "linux", Project: "/project", RuleIDs: []string{id}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Register(Instance{ID: "bound", SessionID: "bound", Agent: "claude", NodeID: conn.NodeID, Platform: "linux", Cwd: "/elsewhere", HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	submit := func(call, tool string, args map[string]any) (Review, error) {
		return e.Submit(ReviewInput{InstanceID: "bound", CallID: call, ToolName: tool, Arguments: args})
	}
	got, err := submit("deny", "Read", map[string]any{"file_path": "protected.txt"})
	if err != nil || got.Decision != "reject" || got.RuleID != "U_BOUND_DENY" {
		t.Fatalf("deny-overrides: %+v %v", got, err)
	}
	got, err = submit("global", "Bash", map[string]any{"command": "redis-cli FLUSHALL"})
	if err != nil || got.Decision != "reject" || got.RuleID == "U_BOUND_ALLOW" {
		t.Fatalf("global protection removed: %+v %v", got, err)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("snapshot missing scopes: %+v", got.Scopes)
	}
	if err := e.DeleteRule(testActorContext(), "U_BOUND_DENY"); err != nil {
		t.Fatal(err)
	}
	if _, err = submit("missing", "Read", map[string]any{"file_path": "README.md"}); err == nil {
		t.Fatal("missing bound rule silently allowed")
	}
}
