package core

import (
	"errors"
	"slices"
	"testing"
)

func TestProtectionMatcherChangeRequiresAcknowledgement(t *testing.T) {
	source := Rule{ID: "U_TAG", Matcher: "contains", Target: "arguments", Pattern: "tag-secret"}
	for _, tc := range []struct {
		name   string
		change func(Rule) Rule
		want   bool
	}{
		{"matcher", func(r Rule) Rule { r.Matcher = "regex"; return r }, true},
		{"target", func(r Rule) Rule { r.Target = "toolName"; return r }, true},
		{"tool", func(r Rule) Rule { r.Tool = "Bash"; return r }, true},
		{"field", func(r Rule) Rule { r.Field = "nested"; return r }, true},
		{"pattern", func(r Rule) Rule { r.Pattern = "different-secret"; return r }, true},
		{"display name only", func(r Rule) Rule { r.Name = "renamed"; return r }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := ProtectionState{Templates: []ProtectionTemplate{{ID: "template", Rules: []TemplateRule{{RuleID: source.ID, Category: "category::sensitive-info", Action: "block"}}}}, Definitions: map[string][]Rule{"template": {source}}}
			after := before
			after.Definitions = map[string][]Rule{"template": {tc.change(source)}}
			got := configuredDowngrades(before, after, ProtectionReview{Resource: "templates", ResourceID: "template"})
			if slices.Contains(got, source.ID) != tc.want {
				t.Fatalf("matcher change downgrade=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestProtectionDetectorRefreshCannotPublishWithoutAcknowledgement(t *testing.T) {
	e, node, _ := protectionFixture(t)
	s := publishProtection(t, e, ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "fixture", Rules: []TemplateRule{{RuleID: "U_TAG", Category: "category::sensitive-info", Action: "block"}}}})
	id := s.Templates[0].ID
	s = publishProtection(t, e, ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: "all", TemplateIDs: []string{id}, Scope: PolicyScope{Type: "all"}}})
	evaluate := func() *Decision {
		t.Helper()
		rules, err := e.Rules()
		if err != nil {
			t.Fatal(err)
		}
		rules, err = e.protectionRules(rules, nil, node)
		if err != nil {
			t.Fatal(err)
		}
		return Evaluate(ReviewInput{ToolName: "Read", Arguments: map[string]any{"file_path": "tag-secret"}}, rules)
	}
	if d := evaluate(); d == nil || d.Decision != "reject" {
		t.Fatalf("fixture not blocked before refresh: %+v", d)
	}
	var source Rule
	if err := e.get("rules", "U_TAG", &source); err != nil {
		t.Fatal(err)
	}
	source.Pattern = "different-secret"
	if err := e.SaveRule(testActorContext(), source); err != nil {
		t.Fatal(err)
	}
	r, err := e.ReviewProtection(ProtectionChange{Kind: "templates", ID: id, Template: &s.Templates[0]}, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if r.Warning == "" || !slices.Contains(r.Downgrades, "U_TAG") {
		t.Error("detector refresh has no downgrade warning")
	}
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, false, "templates", id, false); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("unacknowledged detector refresh published: %v", err)
	}
	if d := evaluate(); d == nil || d.Decision != "reject" {
		t.Fatalf("rejected publish changed existing protection: %+v", d)
	}
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "templates", id, false); err != nil {
		t.Fatal(err)
	}
	if d := evaluate(); d == nil || d.Decision != "approve" {
		t.Fatalf("acknowledged detector refresh not applied: %+v", d)
	}
}
