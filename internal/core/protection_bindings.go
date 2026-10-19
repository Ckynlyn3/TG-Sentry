package core

import (
	"errors"
	"slices"
)

func policyApplies(p ProtectionPolicy, node string, tags []string) bool {
	switch p.Scope.Type {
	case "all":
		return true
	case "agents":
		return node != "" && slices.Contains(p.Scope.AgentIDs, node)
	case "tags":
		for _, tag := range tags {
			if slices.Contains(p.Scope.Tags, tag) {
				return true
			}
		}
	}
	return false
}

// Compile down to #55's ScopeOnly + Scope.RuleIDs mechanism. The existing
// evaluator sorts block/reject > alert > log-only/approve (DECISIONS #19;
// XACML 3.0 Appendix C deny-overrides). Never replace the baseline rule set.
func compileProtection(s ProtectionState, rules []Rule, scopes []Scope, node string) ([]Rule, error) {
	compiled := append([]Rule{}, rules...)
	bindings := append([]Scope{}, scopes...)
	selected := map[string]bool{}
	for _, p := range s.Policies {
		if !policyApplies(p, node, s.Tags[node]) {
			continue
		}
		binding := Scope{RuleIDs: []string{}}
		for _, id := range p.TemplateIDs {
			if selected[id] {
				continue
			}
			selected[id] = true
			index := templateIndex(s, id)
			if index < 0 {
				return nil, errors.New("policy references missing template")
			}
			defs, ok := s.Definitions[id]
			if !ok {
				return nil, errors.New("template detector snapshot missing")
			}
			for _, source := range defs {
				r := source
				r.SourceRuleID = source.ID
				r.ID = "T_" + id + "_" + source.ID
				r.TemplateID = id
				r.TemplateRevision = s.Templates[index].Revision
				r.ScopeOnly = true
				compiled = append(compiled, r)
				binding.RuleIDs = append(binding.RuleIDs, r.ID)
			}
		}
		bindings = append(bindings, binding)
	}
	return boundRules(compiled, bindings)
}
func (e *Engine) protectionRules(rules []Rule, scopes []Scope, node string) ([]Rule, error) {
	s, err := e.Protection()
	if err != nil {
		return nil, err
	}
	return compileProtection(s, rules, scopes, node)
}
