package core

import "errors"

// Scope.NodeID is the existing admin-owned binding. Project constrains path/target
// scopes, not rule applicability: a client cannot escape bound rules by changing cwd.
// DECISIONS #19: global baseline union bound rules; evaluatePaths denies override.
func boundRules(rules []Rule, scopes []Scope) ([]Rule, error) {
	selected := map[string]bool{}
	for _, scope := range scopes {
		for _, id := range scope.RuleIDs {
			selected[id] = true
		}
	}
	effective := []Rule{}
	for _, rule := range rules {
		if !rule.ScopeOnly || selected[rule.ID] {
			effective = append(effective, rule)
		}
		delete(selected, rule.ID)
	}
	if len(selected) != 0 {
		return nil, errors.New("bound policy references a missing rule")
	}
	return effective, nil
}

// Called under the engine writer lock, like SaveScope's existing validation.
func (e *Engine) validateRuleBinding(s Scope) error {
	if len(s.RuleIDs) == 0 {
		return nil
	}
	var node ClientNode
	if s.NodeID == "" || e.get("client_nodes", s.NodeID, &node) != nil || node.Revoked || node.Platform != s.Platform {
		return errors.New("rule binding requires an enrolled device and its platform")
	}
	for _, id := range s.RuleIDs {
		var rule Rule
		if e.get("rules", id, &rule) != nil {
			return errors.New("bound rule not found")
		}
	}
	return nil
}
