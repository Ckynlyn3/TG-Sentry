package core

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func protectionFixture(t *testing.T) (*Engine, string, string) {
	t.Helper()
	e := engine(t)
	code, err := e.CreateEnrollment(testActorContext(), "protection", EnrollmentOptions{Type: "reusable"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err = e.SaveRule(testActorContext(), Rule{ID: "U_TAG", Name: "tag detector", ScopeOnly: true, Decision: "reject", Enabled: true, Matcher: "contains", Pattern: "tag-secret", Categories: []string{"category::sensitive-info"}}); err != nil {
		t.Fatal(err)
	}
	return e, a.NodeID, b.NodeID
}
func publishProtection(t *testing.T, e *Engine, c ProtectionChange) ProtectionState {
	t.Helper()
	s, err := e.Protection()
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.ReviewProtection(c, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	s, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, c.Kind, c.ID, c.Delete)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestProtectionUnionAndBaseline(t *testing.T) {
	e, a, b := protectionFixture(t)
	publishProtection(t, e, ProtectionChange{Kind: "tags", ID: a, Tags: []string{"engineering"}})
	templates := []ProtectionTemplate{}
	for _, action := range []string{"log-only", "alert", "block"} {
		s := publishProtection(t, e, ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: action, Rules: []TemplateRule{{RuleID: "U_TAG", Category: "category::sensitive-info", Action: action}}}})
		templates = append(templates, s.Templates[len(s.Templates)-1])
	}
	scopes := []PolicyScope{{Type: "all"}, {Type: "tags", Tags: []string{"engineering"}}, {Type: "agents", AgentIDs: []string{a}}}
	for i, scope := range scopes {
		publishProtection(t, e, ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: fmt.Sprint(i), TemplateIDs: []string{templates[i].ID}, Scope: scope}})
	}
	for _, tc := range []struct{ node, want string }{{a, "reject"}, {b, "approve"}} {
		if err := e.Register(Instance{ID: tc.node, NodeID: tc.node, Platform: "linux", SessionID: tc.node, Cwd: "/project", HookVersion: Version}); err != nil {
			t.Fatal(err)
		}
		r, err := e.Submit(ReviewInput{InstanceID: tc.node, CallID: ID(), ToolName: "Read", Arguments: map[string]any{"file_path": "tag-secret"}})
		if err != nil || r.Decision != tc.want {
			t.Fatalf("node=%s decision=%s err=%v", tc.node, r.Decision, err)
		}
		r, err = e.Submit(ReviewInput{InstanceID: tc.node, CallID: ID(), ToolName: "Bash", Arguments: map[string]any{"command": "passwd fixture"}})
		if err != nil || r.Decision != "reject" {
			t.Fatalf("baseline lost: %+v %v", r, err)
		}
	}
	// Removing the direct agent binding leaves the tag alert, not the global log-only action.
	s, _ := e.Protection()
	publishProtection(t, e, ProtectionChange{Kind: "policies", ID: s.Policies[2].ID, Delete: true})
	rules, _ := e.Rules()
	got, err := e.protectionRules(rules, nil, a)
	if err != nil {
		t.Fatal(err)
	}
	d := Evaluate(ReviewInput{ToolName: "Read", Arguments: map[string]any{"file_path": "tag-secret"}}, got)
	if d == nil || d.Decision != "alert" {
		t.Fatalf("tag did not override all: %+v", d)
	}
}
func TestProtectionReviewCASDowngradeAndReferences(t *testing.T) {
	e, _, _ := protectionFixture(t)
	s := publishProtection(t, e, ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "fixture", Rules: []TemplateRule{{RuleID: "U_TAG", Category: "category::sensitive-info", Action: "block"}}}})
	id := s.Templates[0].ID
	c := ProtectionChange{Kind: "templates", ID: id, Template: &ProtectionTemplate{Name: "fixture", Rules: []TemplateRule{}}}
	r, err := e.ReviewProtection(c, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Downgrades) == 0 || r.Warning == "" || len(r.Diff) == 0 {
		t.Fatal("missing downgrade/diff")
	}
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, false, "templates", id, false); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("unacknowledged downgrade: %v", err)
	}
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "policies", id, false); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("review substituted: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "templates", id, false)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes, stale := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrProtectionPrecondition) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || stale != 1 {
		t.Fatalf("CAS winners=%d stale=%d", successes, stale)
	}
	s, err = e.Protection()
	if err != nil {
		t.Fatal(err)
	}
	publishProtection(t, e, ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: "bound", TemplateIDs: []string{id}, Scope: PolicyScope{Type: "all"}}})
	s, _ = e.Protection()
	if _, err = e.ReviewProtection(ProtectionChange{Kind: "templates", ID: id, Delete: true}, s.Revision); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("deleted referenced template: %v", err)
	}
	if _, err = e.ReviewProtection(c, s.Revision-1); !errors.Is(err, ErrProtectionPrecondition) {
		t.Fatalf("stale review: %v", err)
	}
}
func TestProtectionValidationAndTenTags(t *testing.T) {
	e, a, _ := protectionFixture(t)
	bad := []ProtectionChange{
		{Kind: "templates", Template: &ProtectionTemplate{Name: "", Rules: []TemplateRule{}}},
		{Kind: "templates", Template: &ProtectionTemplate{Name: "bad", Rules: []TemplateRule{{RuleID: "missing", Category: "category::behavior", Action: "block"}}}},
		{Kind: "templates", Template: &ProtectionTemplate{Name: "bad", Rules: []TemplateRule{{RuleID: "U_TAG", Category: "invalid", Action: "block"}}}},
		{Kind: "templates", Template: &ProtectionTemplate{Name: "bad", Rules: []TemplateRule{{RuleID: "U_TAG", Category: "category::behavior", Action: "allow"}}}},
		{Kind: "policies", Policy: &ProtectionPolicy{Name: "bad", TemplateIDs: []string{"missing"}, Scope: PolicyScope{Type: "all"}}},
		{Kind: "tags", ID: a, Tags: []string{"duplicate", "duplicate"}},
		{Kind: "tags", ID: a, Tags: []string{" "}},
		{Kind: "tags", ID: "missing", Tags: []string{}},
		{Kind: "unknown"},
	}
	for _, c := range bad {
		if _, err := e.ReviewProtection(c, 0); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	tags := []string{}
	for i := range 10 {
		tags = append(tags, fmt.Sprint(i))
	}
	s := publishProtection(t, e, ProtectionChange{Kind: "tags", ID: a, Tags: tags})
	tags = append(tags, "11")
	if _, err := e.ReviewProtection(ProtectionChange{Kind: "tags", ID: a, Tags: tags}, s.Revision); err == nil {
		t.Fatal("accepted eleven tags")
	}
	nodes, err := e.ClientNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if node.ID == a && !reflect.DeepEqual(node.Tags, tags[:10]) {
			t.Fatalf("tags not persisted: %+v", node)
		}
	}
}
