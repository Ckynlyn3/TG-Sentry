package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrProtectionPrecondition = errors.New("protection revision changed; keep the draft and review again")
	ErrProtectionConflict     = errors.New("protection change requires confirmation")
	ErrProtectionInvalid      = errors.New("invalid protection change")
)

// AgentSentry's limit: docs/research/FEATURE-INVENTORY.md:50.
const MaxAgentTags = 10

type TemplateRule struct {
	RuleID   string `json:"ruleId"`
	Category string `json:"category"`
	Action   string `json:"action"`
}
type ProtectionTemplate struct {
	ID       string         `json:"id"`
	Revision int            `json:"revision"`
	Name     string         `json:"name"`
	Rules    []TemplateRule `json:"rules"`
}
type PolicyScope struct {
	Type     string   `json:"type"`
	AgentIDs []string `json:"agentIds,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}
type ProtectionPolicy struct {
	ID          string      `json:"id"`
	Revision    int         `json:"revision"`
	Name        string      `json:"name"`
	TemplateIDs []string    `json:"templateIds"`
	Scope       PolicyScope `json:"scope"`
}

// DiscoveryPolicy is disabled when absent, Enabled is false, or IntervalSeconds
// is zero. Consumers check both fields before scanning; no interval is defaulted.
type DiscoveryPolicy struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"intervalSeconds"`
}

// One CAS boundary covers dependencies and impact, not just the edited resource.
// Definitions are server-owned detector snapshots, never accepted from the API.
type ProtectionState struct {
	Revision     int                  `json:"revision"`
	Templates    []ProtectionTemplate `json:"templates"`
	Policies     []ProtectionPolicy   `json:"policies"`
	Tags         map[string][]string  `json:"tags"`
	Definitions  map[string][]Rule    `json:"definitions"`
	ACL          ACLState             `json:"acl"`
	Discovery    *DiscoveryPolicy     `json:"discovery,omitempty"`
	LogWhitelist []LogWhitelistEntry  `json:"logWhitelist,omitempty"`
}
type ProtectionChange struct {
	Kind         string              `json:"kind"`
	ID           string              `json:"id"`
	Delete       bool                `json:"delete"`
	Template     *ProtectionTemplate `json:"template,omitempty"`
	Policy       *ProtectionPolicy   `json:"policy,omitempty"`
	ACL          *ACLRule            `json:"acl,omitempty"`
	Tags         []string            `json:"tags,omitempty"`
	Discovery    *DiscoveryPolicy    `json:"discovery,omitempty"`
	LogWhitelist *LogWhitelistEntry  `json:"logWhitelist,omitempty"`
}
type ProtectionDiff struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}
type ProtectionBinding struct {
	AgentID   string   `json:"agentId"`
	PolicyIDs []string `json:"policyIds"`
}
type ProtectionReview struct {
	ID                string              `json:"id"`
	BaseRevision      int                 `json:"baseRevision"`
	ResourceID        string              `json:"resourceId"`
	Resource          string              `json:"resource"`
	Delete            bool                `json:"delete"`
	Diff              []ProtectionDiff    `json:"diff"`
	Downgrades        []string            `json:"downgrades"`
	Warning           string              `json:"warning"`
	AffectedPolicyIDs []string            `json:"affectedPolicyIds"`
	AffectedAgentIDs  []string            `json:"affectedAgentIds"`
	Bindings          []ProtectionBinding `json:"bindings"`
	Tenant            string              `json:"tenant"`
}
type protectionDraft struct {
	Review ProtectionReview `json:"review"`
	State  ProtectionState  `json:"state"`
}

func (e *Engine) Protection() (ProtectionState, error) {
	s := ProtectionState{Templates: []ProtectionTemplate{}, Policies: []ProtectionPolicy{}, Tags: map[string][]string{}, Definitions: map[string][]Rule{}}
	err := e.get("protection", "current", &s)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil
	}
	return s, err
}

// EffectiveACLRules applies A5's virtual compatibility default without writing
// configuration. Once published, even an empty ACL uses deny-unless-permit.
func (s ProtectionState) EffectiveACLRules() []ACLRule {
	if !s.ACL.Initialized {
		return []ACLRule{{ID: "acl-default-all-pass", Name: "Allow all tools", Enabled: true,
			Subject: ACLSubject{Kind: "all"}, Effect: "allow", Target: ACLTarget{Kind: "all"}}}
	}
	return s.ACL.Rules
}
func templateIndex(s ProtectionState, id string) int {
	return slices.IndexFunc(s.Templates, func(t ProtectionTemplate) bool { return t.ID == id })
}
func policyIndex(s ProtectionState, id string) int {
	return slices.IndexFunc(s.Policies, func(p ProtectionPolicy) bool { return p.ID == id })
}
func validProtectionName(name string) bool {
	// Existing rule-name boundary (policy.go SaveRule).
	return strings.TrimSpace(name) != "" && len(name) <= 200
}
func validTags(tags []string) bool {
	return tags != nil && len(tags) <= MaxAgentTags && validTagNames(tags)
}
func validTagNames(tags []string) bool {
	seen := map[string]bool{}

	for _, tag := range tags {
		// Reuse the existing enrollment-name byte boundary, not an invented limit.
		if strings.TrimSpace(tag) != tag || tag == "" || len(tag) > 120 || seen[tag] {
			return false
		}
		seen[tag] = true
	}
	return true
}
func (e *Engine) reviewTemplate(s *ProtectionState, c ProtectionChange) error {
	idx := templateIndex(*s, c.ID)
	if c.ID != "" && idx < 0 {
		return sql.ErrNoRows
	}
	if c.Delete {
		bound := []string{}
		for _, p := range s.Policies {
			if slices.Contains(p.TemplateIDs, c.ID) {
				bound = append(bound, p.ID)
			}
		}
		if len(bound) > 0 {
			return fmt.Errorf("%w: template used by policies %s", ErrProtectionConflict, strings.Join(bound, ","))
		}
		s.Templates = slices.Delete(s.Templates, idx, idx+1)
		delete(s.Definitions, c.ID)
		return nil
	}
	if c.Template == nil || c.Template.Rules == nil || !validProtectionName(c.Template.Name) {
		return ErrProtectionInvalid
	}
	t := *c.Template
	t.ID = c.ID
	t.Revision = s.Revision + 1
	if t.ID == "" {
		t.ID = ID()
	}
	t.Rules = append([]TemplateRule{}, t.Rules...)
	defs := []Rule{}
	seen := map[string]bool{}
	for _, item := range t.Rules {
		if !validRiskCategory(item.Category) || !hasExact(item.Action, "block", "alert", "log-only", "redact") || (item.Action == "redact" && item.Category != SensitiveInfoCategory) || seen[item.RuleID] {
			return ErrProtectionInvalid
		}
		seen[item.RuleID] = true
		var r Rule
		if err := e.get("rules", item.RuleID, &r); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrProtectionInvalid
			}
			return err
		}
		// Reuse the existing matcher definition. Explicit selection enables it only
		// for applicable policies; it never changes the stored/global rule.
		r.Enabled = true
		r.ScopeOnly = true
		r.Decision = actionDecision(item.Action)
		r.Categories = []string{item.Category}
		defs = append(defs, normalizeRule(r))
	}
	if idx < 0 {
		s.Templates = append(s.Templates, t)
	} else {
		s.Templates[idx] = t
	}
	s.Definitions[t.ID] = defs
	return nil
}
func (e *Engine) reviewPolicy(s *ProtectionState, c ProtectionChange) error {
	idx := policyIndex(*s, c.ID)
	if c.ID != "" && idx < 0 {
		return sql.ErrNoRows
	}
	if c.Delete {
		s.Policies = slices.Delete(s.Policies, idx, idx+1)
		return nil
	}
	if c.Policy == nil || !validProtectionName(c.Policy.Name) || len(c.Policy.TemplateIDs) == 0 {
		return ErrProtectionInvalid
	}
	p := *c.Policy
	p.ID = c.ID
	p.Revision = s.Revision + 1
	if p.ID == "" {
		p.ID = ID()
	}
	seen := map[string]bool{}
	for _, id := range p.TemplateIDs {
		if templateIndex(*s, id) < 0 || seen[id] {
			return ErrProtectionInvalid
		}
		seen[id] = true
	}
	switch p.Scope.Type {
	case "all":
		if len(p.Scope.AgentIDs) > 0 || len(p.Scope.Tags) > 0 {
			return ErrProtectionInvalid
		}
	case "tags":
		if len(p.Scope.AgentIDs) > 0 || len(p.Scope.Tags) == 0 || !validTagNames(p.Scope.Tags) {
			return ErrProtectionInvalid
		}
	case "agents":
		if len(p.Scope.Tags) > 0 || len(p.Scope.AgentIDs) == 0 {
			return ErrProtectionInvalid
		}
		seen = map[string]bool{}
		for _, id := range p.Scope.AgentIDs {
			if seen[id] {
				return ErrProtectionInvalid
			}
			seen[id] = true
			if err := e.protectionNode(id); err != nil {
				return err
			}
		}
	default:
		return ErrProtectionInvalid
	}
	if idx < 0 {
		s.Policies = append(s.Policies, p)
	} else {
		s.Policies[idx] = p
	}
	return nil
}
func aclIndex(s ProtectionState, id string) int {
	return slices.IndexFunc(s.EffectiveACLRules(), func(r ACLRule) bool { return r.ID == id })
}
func (e *Engine) validateACL(r ACLRule) error {
	if !validProtectionName(r.Name) || !hasExact(r.Effect, "allow", "deny") {
		return ErrProtectionInvalid
	}
	switch r.Subject.Kind {
	case "all":
		if len(r.Subject.AgentIDs) > 0 || len(r.Subject.Tags) > 0 {
			return ErrProtectionInvalid
		}
	case "tags":
		if len(r.Subject.AgentIDs) > 0 || len(r.Subject.Tags) == 0 || !validTagNames(r.Subject.Tags) {
			return ErrProtectionInvalid
		}
	case "agents":
		if len(r.Subject.Tags) > 0 || len(r.Subject.AgentIDs) == 0 {
			return ErrProtectionInvalid
		}
		seen := map[string]bool{}
		for _, id := range r.Subject.AgentIDs {
			if seen[id] {
				return ErrProtectionInvalid
			}
			seen[id] = true
			if err := e.protectionNode(id); err != nil {
				return err
			}
		}
	default:
		return ErrProtectionInvalid
	}
	if (r.Target.Kind == "all" && len(r.Target.Tools) == 0) || (r.Target.Kind == "tools" && len(r.Target.Tools) > 0 && validToolNames(r.Target.Tools)) {
		return nil
	}
	return ErrProtectionInvalid
}
func validToolNames(tools []string) bool {
	seen := map[string]bool{}
	for _, tool := range tools {
		// Exact Rule.Tool semantics: do not trim, fold case, or interpret wildcards.
		if strings.TrimSpace(tool) == "" || seen[tool] {
			return false
		}
		seen[tool] = true
	}
	return true
}
func (e *Engine) reviewACL(s *ProtectionState, c ProtectionChange) error {
	idx := aclIndex(*s, c.ID)
	if c.ID != "" && idx < 0 {
		return sql.ErrNoRows
	}
	rules := slices.Clone(s.EffectiveACLRules())
	if c.Delete {
		s.ACL = ACLState{Initialized: true, Rules: slices.Delete(rules, idx, idx+1)}
		return nil
	}
	if c.ACL == nil {
		return ErrProtectionInvalid
	}
	if err := e.validateACL(*c.ACL); err != nil {
		return err
	}
	r := *c.ACL
	r.ID, r.UpdatedAt = c.ID, e.clock()
	if r.ID == "" {
		r.ID = ID()
	}
	r.Subject.AgentIDs = slices.Clone(r.Subject.AgentIDs)
	r.Subject.Tags = slices.Clone(r.Subject.Tags)
	r.Target.Tools = slices.Clone(r.Target.Tools)
	if idx < 0 {
		rules = append(rules, r)
	} else {
		rules[idx] = r
	}
	s.ACL = ACLState{Initialized: true, Rules: rules}
	return nil
}
func (e *Engine) protectionNode(id string) error {
	var n ClientNode
	if err := e.get("client_nodes", id, &n); err != nil {
		return err
	}
	if n.Revoked {
		return ErrProtectionInvalid
	}
	return nil
}
func (e *Engine) applyProtection(s *ProtectionState, c ProtectionChange) error {
	if c.Delete && c.ID == "" {
		return ErrProtectionInvalid
	}
	switch c.Kind {
	case "templates":
		return e.reviewTemplate(s, c)
	case "policies":
		return e.reviewPolicy(s, c)
	case "acl":
		return e.reviewACL(s, c)
	case "log-whitelist":
		return e.reviewLogWhitelist(s, c)
	case "discovery":
		if c.Delete || c.ID != "current" || c.Discovery == nil || c.Discovery.IntervalSeconds < 0 {
			return ErrProtectionInvalid
		}
		discovery := *c.Discovery
		s.Discovery = nil
		if discovery != (DiscoveryPolicy{}) {
			s.Discovery = &discovery
		}
		return nil
	case "tags":
		if c.Delete || !validTags(c.Tags) {
			return ErrProtectionInvalid
		}
		if err := e.protectionNode(c.ID); err != nil {
			return err
		}
		s.Tags[c.ID] = append([]string{}, c.Tags...)
		return nil
	default:
		return ErrProtectionInvalid
	}
}
func (e *Engine) ReviewProtection(c ProtectionChange, base int) (ProtectionReview, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	before, err := e.Protection()
	if err != nil {
		return ProtectionReview{}, err
	}
	if before.Revision != base {
		return ProtectionReview{}, ErrProtectionPrecondition
	}
	// Load again: both states own their maps/slices; draft application cannot mutate before.
	after, err := e.Protection()
	if err != nil {
		return ProtectionReview{}, err
	}
	if err = e.applyProtection(&after, c); err != nil {
		return ProtectionReview{}, err
	}
	r := ProtectionReview{ID: ID(), BaseRevision: base, Resource: c.Kind, ResourceID: c.ID, Delete: c.Delete, Tenant: eventTenant(), Diff: []ProtectionDiff{}, Downgrades: []string{}, AffectedPolicyIDs: []string{}, AffectedAgentIDs: []string{}, Bindings: []ProtectionBinding{}}
	if c.ID == "" {
		if c.Kind == "templates" {
			r.ResourceID = after.Templates[len(after.Templates)-1].ID
		} else if c.Kind == "log-whitelist" {
			r.ResourceID = after.LogWhitelist[len(after.LogWhitelist)-1].ID
		} else if c.Kind == "acl" {
			r.ResourceID = after.ACL.Rules[len(after.ACL.Rules)-1].ID
		} else {
			r.ResourceID = after.Policies[len(after.Policies)-1].ID
		}
	}
	r.Diff = protectionDiff(before, after, c.Kind, r.ResourceID)
	if len(r.Diff) == 0 {
		return ProtectionReview{}, fmt.Errorf("%w: no changes", ErrProtectionInvalid)
	}
	if err = e.protectionImpact(&r, before, after); err != nil {
		return ProtectionReview{}, err
	}
	if len(r.Downgrades) > 0 {
		r.Warning = "Protection is removed or weakened. Other applicable policies and the global baseline remain enforced."
		if c.Kind == "log-whitelist" {
			r.Warning = "Audit and conversation recording is reduced for selected devices. Protection and risk reporting remain enforced."
		}
	}
	after.Revision = base + 1
	if err = e.put("protection_reviews", r.ID, protectionDraft{Review: r, State: after}); err != nil {
		return ProtectionReview{}, err
	}
	return r, nil
}
func (e *Engine) ConfirmProtection(ctx context.Context, reviewID string, base int, ack bool, kind, id string, deleted bool) (ProtectionState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, err := e.Protection()
	if err != nil {
		return s, err
	}
	if s.Revision != base {
		return s, ErrProtectionPrecondition
	}
	var draft protectionDraft
	if err = e.get("protection_reviews", reviewID, &draft); err != nil {
		return s, err
	}
	r := draft.Review
	if r.BaseRevision != base {
		return s, ErrProtectionPrecondition
	}
	exists := kind == "discovery" || kind == "tags" || (kind == "templates" && templateIndex(s, r.ResourceID) >= 0) || (kind == "policies" && policyIndex(s, r.ResourceID) >= 0) || (kind == "acl" && aclIndex(s, r.ResourceID) >= 0) || (kind == "log-whitelist" && logWhitelistIndex(s, r.ResourceID) >= 0)
	if (id == "") == exists || r.Resource != kind || r.Delete != deleted || (id != "" && r.ResourceID != id) || (id == "" && deleted) {
		return s, ErrProtectionConflict
	}
	if len(r.Downgrades) > 0 && !ack {
		return s, ErrProtectionConflict
	}
	// Device revocation can happen outside the aggregate; validate at confirmation.
	if kind == "tags" {
		if err = e.protectionNode(r.ResourceID); err != nil {
			return s, err
		}
	}
	for _, p := range draft.State.Policies {
		if kind != "policies" || p.ID != r.ResourceID {
			continue
		}
		for _, nodeID := range p.Scope.AgentIDs {
			if err = e.protectionNode(nodeID); err != nil {
				return s, err
			}
		}
	}
	if kind == "acl" {
		if idx := aclIndex(draft.State, r.ResourceID); idx >= 0 {
			if err = e.validateACL(draft.State.ACL.Rules[idx]); err != nil {
				return s, err
			}
		}
	}
	if kind == "log-whitelist" {
		if idx := logWhitelistIndex(draft.State, r.ResourceID); idx >= 0 {
			if err = e.validateLogWhitelist(draft.State.LogWhitelist[idx]); err != nil {
				return s, err
			}
		}
	}
	if err = e.change(ctx, "protection", "current", draft.State, "protection."+kind+".publish", fmt.Sprintf("resource=%s review=%s base=%d", r.ResourceID, r.ID, base)); err != nil {
		return s, err
	}
	return draft.State, nil
}
func actionDecision(action string) string {
	switch action {
	case "block":
		return "reject"
	case "alert", "redact":
		return action
	default:
		return "approve"
	}
}
func decisionStrength(decision string) int {
	switch decision {
	case "reject":
		return 3
	case "alert", "redact":
		return 2
	case "approve":
		return 1
	default:
		return 0
	}
}
