package core

import (
	"aegishook/internal/teststore"
	"database/sql"
	"errors"
	"reflect"
	"testing"
)

func TestProtectionSemanticSnapshotsAndLatestTemplate(t *testing.T) {
	e, a, _ := protectionFixture(t)
	rules, err := e.Rules()
	if err != nil {
		t.Fatal(err)
	}
	var source Rule
	for _, r := range rules {
		if r.ID == "R1" {
			source = r
		}
	}
	source.Enabled = false
	if err = e.SaveRule(testActorContext(), source); err != nil {
		t.Fatal(err)
	}
	s := publishProtection(t, e, ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "semantic", Rules: []TemplateRule{{RuleID: "R1", Category: "category::high-risk-ops", Action: "block"}}}})
	id := s.Templates[0].ID
	publishProtection(t, e, ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: "all future agents", TemplateIDs: []string{id}, Scope: PolicyScope{Type: "all"}}})
	evaluate := func() *Decision {
		t.Helper()
		rules, err := e.Rules()
		if err != nil {
			t.Fatal(err)
		}
		rules, err = e.protectionRules(rules, nil, a)
		if err != nil {
			t.Fatal(err)
		}
		return Evaluate(ReviewInput{ToolName: "bash", Arguments: map[string]any{"command": "passwd fixture"}}, rules)
	}
	d := evaluate()
	if d == nil || d.Decision != "reject" || d.RuleID == "R1" {
		t.Fatalf("semantic source alias failed: %+v", d)
	}
	rules, err = e.protectionRules(rules, nil, a)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rules {
		if r.TemplateID == id {
			found = true
			if r.Semantics == nil || r.SourceRuleID != "R1" || r.TemplateRevision != 1 {
				t.Fatalf("lost server provenance: %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("compiled template missing")
	}
	publishProtection(t, e, ProtectionChange{Kind: "templates", ID: id, Template: &ProtectionTemplate{Name: "semantic", Rules: []TemplateRule{{RuleID: "R1", Category: "category::high-risk-ops", Action: "log-only"}}}})
	d = evaluate()
	if d == nil || d.Decision != "approve" {
		t.Fatalf("policy did not follow latest template: %+v", d)
	}
	// Rule CRUD cannot spoof the semantic alias or compiled provenance.
	spoof := Rule{ID: "U_SPOOF", SourceRuleID: "A7", TemplateID: id, TemplateRevision: 99, Name: "spoof", Enabled: true, Decision: "reject", Matcher: "contains", Pattern: "fixture"}
	if err = e.SaveRule(testActorContext(), spoof); err != nil {
		t.Fatal(err)
	}
	spoof = Rule{ID: spoof.ID}
	if err = e.get("rules", spoof.ID, &spoof); err != nil || spoof.SourceRuleID != "" || spoof.TemplateID != "" || spoof.TemplateRevision != 0 {
		t.Fatal("client controls provenance", err)
	}
}
func TestProtectionPolicyValidationAndReviewMethodBinding(t *testing.T) {
	e, a, b := protectionFixture(t)
	s := publishProtection(t, e, ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "fixture", Rules: []TemplateRule{}}})
	id := s.Templates[0].ID
	for _, scope := range []PolicyScope{{Type: "invalid"}, {Type: "all", Tags: []string{"x"}}, {Type: "tags"}, {Type: "tags", Tags: []string{"x", "x"}}, {Type: "tags", Tags: []string{"x"}, AgentIDs: []string{a}}, {Type: "agents"}, {Type: "agents", AgentIDs: []string{a, a}}, {Type: "agents", AgentIDs: []string{a}, Tags: []string{"x"}}, {Type: "agents", AgentIDs: []string{"missing"}}} {
		if _, err := e.ReviewProtection(ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: "invalid", TemplateIDs: []string{id}, Scope: scope}}, s.Revision); err == nil {
			t.Fatalf("invalid scope accepted: %+v", scope)
		}
	}
	c := ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: "both", TemplateIDs: []string{id, id}, Scope: PolicyScope{Type: "all"}}}
	if _, err := e.ReviewProtection(c, s.Revision); err == nil {
		t.Fatal("duplicate template accepted")
	}
	c.Policy.TemplateIDs = []string{id}
	c.Policy.Scope = PolicyScope{Type: "agents", AgentIDs: []string{a}}
	review, err := e.ReviewProtection(c, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.ConfirmProtection(testActorContext(), review.ID, s.Revision, true, "policies", review.ResourceID, false); !errors.Is(err, ErrProtectionConflict) {
		t.Fatal("PUT accepted create review", err)
	}
	if err = e.RevokeClient(testActorContext(), a); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ConfirmProtection(testActorContext(), review.ID, s.Revision, true, "policies", "", false); err == nil {
		t.Fatal("revoked node accepted on publish")
	}
	if _, err = e.ReviewProtection(ProtectionChange{Kind: "tags", ID: a, Tags: []string{"x"}}, s.Revision); err == nil {
		t.Fatal("tagged revoked node")
	}
	c.Policy.Scope = PolicyScope{Type: "agents", AgentIDs: []string{b}}
	s = publishProtection(t, e, c)
	pid := s.Policies[0].ID
	r, err := e.ReviewProtection(ProtectionChange{Kind: "policies", ID: pid, Policy: &ProtectionPolicy{Name: "renamed", TemplateIDs: []string{id}, Scope: PolicyScope{Type: "all"}}}, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, s.Revision, true, "policies", "", false); !errors.Is(err, ErrProtectionConflict) {
		t.Fatal("POST accepted update review", err)
	}
	for _, kind := range []string{"templates", "policies"} {
		if _, err = e.ReviewProtection(ProtectionChange{Kind: kind, ID: "missing", Delete: true}, s.Revision); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
	}
	if _, err = e.ReviewProtection(ProtectionChange{Kind: "templates", Delete: true}, s.Revision); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal(err)
	}
}
func TestProtectionTagImpactDoesNotIncludeUnchangedAgents(t *testing.T) {
	e, a, b := protectionFixture(t)
	s := publishProtection(t, e, ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "fixture", Rules: []TemplateRule{}}})
	publishProtection(t, e, ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: "all", TemplateIDs: []string{s.Templates[0].ID}, Scope: PolicyScope{Type: "all"}}})
	s, _ = e.Protection()
	r, err := e.ReviewProtection(ProtectionChange{Kind: "tags", ID: a, Tags: []string{"x"}}, s.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.AffectedAgentIDs, []string{a}) {
		t.Fatalf("tag on %s affects unchanged %s: %+v", a, b, r)
	}
	if len(r.Bindings) != 1 || len(r.Bindings[0].PolicyIDs) != 1 {
		t.Fatal("missing overlap preview")
	}
}
func TestProtectionAuditRollbackAndDurability(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			e.Close()
		}
	})
	r, err := e.ReviewProtection(ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "durable", Rules: []TemplateRule{}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.ConfirmProtection(testActorContext(), r.ID, 0, true, "templates", "", false); err != nil {
		t.Fatal(err)
	}
	saved, err := e.Protection()
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.Protection()
	if err != nil || !reflect.DeepEqual(saved, got) {
		t.Fatal("published protection lost on reopen", err)
	}
	r, err = reopened.ReviewProtection(ProtectionChange{Kind: "templates", ID: saved.Templates[0].ID, Template: &ProtectionTemplate{Name: "rollback", Rules: []TemplateRule{}}}, saved.Revision)
	if err != nil {
		t.Fatal(err)
	}
	version := reopened.Config().Version
	rejectAudit(t, reopened)
	if _, err = reopened.ConfirmProtection(testActorContext(), r.ID, saved.Revision, true, "templates", saved.Templates[0].ID, false); err == nil {
		t.Fatal("audit failure accepted")
	}
	got, err = reopened.Protection()
	if err != nil || !reflect.DeepEqual(saved, got) || reopened.Config().Version != version {
		t.Fatal("failed publish changed protection or config version", err)
	}
}
func TestProtectionCompilerFailsClosedOnMissingSnapshots(t *testing.T) {
	for _, s := range []ProtectionState{
		{Policies: []ProtectionPolicy{{TemplateIDs: []string{"missing"}, Scope: PolicyScope{Type: "all"}}}},
		{Templates: []ProtectionTemplate{{ID: "missing"}}, Policies: []ProtectionPolicy{{TemplateIDs: []string{"missing"}, Scope: PolicyScope{Type: "all"}}}},
	} {
		if _, err := compileProtection(s, nil, nil, ""); err == nil {
			t.Fatal("missing protection compiled")
		}
	}
}
