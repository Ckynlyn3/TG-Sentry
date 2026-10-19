package core

import "slices"

// EvaluateACL combines enabled matching rules using XACML 3.0 Appendix C
// deny-overrides, then deny-unless-permit for no match (issue #44 plan §3.2).
// It does not initialize configuration or approve execution: allow only permits
// the caller to continue the existing safety evaluation.
func EvaluateACL(rules []ACLRule, node string, tags []string, tool string) ACLDecision {
	var deny, allow *ACLRule
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || !policyApplies(ProtectionPolicy{Scope: PolicyScope{
			Type: r.Subject.Kind, AgentIDs: r.Subject.AgentIDs, Tags: r.Subject.Tags,
		}}, node, tags) {
			continue
		}
		if r.Target.Kind != "all" && (r.Target.Kind != "tools" || !slices.Contains(r.Target.Tools, tool)) {
			continue
		}
		// As in sortRules, use the lowest ID to make provenance order-independent.
		switch r.Effect {
		case "deny":
			if deny == nil || r.ID < deny.ID {
				deny = r
			}
		case "allow":
			if allow == nil || r.ID < allow.ID {
				allow = r
			}
		}
	}
	if deny != nil {
		return ACLDecision{Effect: "deny", RuleID: deny.ID}
	}
	if allow != nil {
		return ACLDecision{Effect: "allow", RuleID: allow.ID}
	}
	return ACLDecision{Effect: "deny"}
}
