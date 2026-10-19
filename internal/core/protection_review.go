package core

import (
	"reflect"
	"slices"
	"strings"
)

func protectionObject(s ProtectionState, kind, id string) map[string]any {
	out := map[string]any{}
	switch kind {
	case "templates":
		idx := templateIndex(s, id)
		if idx < 0 {
			return out
		}
		t := s.Templates[idx]
		out["name"] = t.Name
		rules := map[string]any{}
		for _, r := range t.Rules {
			rules[r.RuleID] = map[string]any{"category": r.Category, "action": r.Action}
		}
		out["rules"] = rules
		out["detectors"] = s.Definitions[id]
	case "policies":
		idx := policyIndex(s, id)
		if idx < 0 {
			return out
		}
		p := s.Policies[idx]
		out["name"] = p.Name
		out["templateIds"] = p.TemplateIDs
		out["scope"] = map[string]any{"type": p.Scope.Type, "agentIds": append([]string{}, p.Scope.AgentIDs...), "tags": append([]string{}, p.Scope.Tags...)}
	case "tags":
		out["tags"] = s.Tags[id]
	}
	return out
}
func protectionDiff(before, after ProtectionState, kind, id string) []ProtectionDiff {
	out := []ProtectionDiff{}
	var walk func(string, map[string]any, map[string]any)
	walk = func(prefix string, a, b map[string]any) {
		keys := []string{}
		for k := range a {
			keys = append(keys, k)
		}
		for k := range b {
			if _, ok := a[k]; !ok {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, k := range keys {
			if reflect.DeepEqual(a[k], b[k]) {
				continue
			}
			field := prefix + strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
			am, aok := a[k].(map[string]any)
			bm, bok := b[k].(map[string]any)
			if aok && bok {
				walk(field+"/", am, bm)
			} else {
				out = append(out, ProtectionDiff{Field: field, Before: a[k], After: b[k]})
			}
		}
	}
	walk("/", protectionObject(before, kind, id), protectionObject(after, kind, id))
	return out
}
func addUnique(values []string, value string) []string {
	if !slices.Contains(values, value) {
		return append(values, value)
	}
	return values
}

// Matchers are opaque: any refresh can remove coverage. Require acknowledgement
// rather than attempting regex subsumption or guessing whether it is narrower.
func detectorMatchingChanged(before, after []Rule, id string) bool {
	old := slices.IndexFunc(before, func(r Rule) bool { return r.ID == id })
	next := slices.IndexFunc(after, func(r Rule) bool { return r.ID == id })
	if old < 0 || next < 0 {
		return true
	}
	a, b := before[old], after[next]
	return a.Matcher != b.Matcher || a.Target != b.Target || a.Tool != b.Tool || a.Field != b.Field || a.Pattern != b.Pattern
}
func configuredDowngrades(before, after ProtectionState, r ProtectionReview) []string {
	out := []string{}
	if r.Resource == "templates" {
		idx := templateIndex(before, r.ResourceID)
		if idx < 0 {
			return out
		}
		next := map[string]TemplateRule{}
		if i := templateIndex(after, r.ResourceID); i >= 0 {
			for _, rule := range after.Templates[i].Rules {
				next[rule.RuleID] = rule
			}
		}
		for _, old := range before.Templates[idx].Rules {
			n, ok := next[old.RuleID]
			if !ok || n.Category != old.Category || decisionStrength(actionDecision(n.Action)) < decisionStrength(actionDecision(old.Action)) || detectorMatchingChanged(before.Definitions[r.ResourceID], after.Definitions[r.ResourceID], old.RuleID) {
				out = append(out, old.RuleID)
			}
		}
	}
	if r.Resource == "policies" {
		idx := policyIndex(before, r.ResourceID)
		if idx < 0 {
			return out
		}
		old := before.Policies[idx]
		next := policyIndex(after, r.ResourceID)
		if next < 0 {
			return append(out, "policy removed (including future agents)")
		}
		n := after.Policies[next]
		for _, id := range old.TemplateIDs {
			if !slices.Contains(n.TemplateIDs, id) {
				out = addUnique(out, "template binding removed: "+id)
			}
		}
		if !reflect.DeepEqual(old.Scope, n.Scope) {
			out = addUnique(out, "binding scope changed; previously covered agents may lose protection")
		}
	}
	if r.Resource == "tags" {
		for _, tag := range before.Tags[r.ResourceID] {
			if !slices.Contains(after.Tags[r.ResourceID], tag) {
				out = append(out, "tag removed: "+tag)
			}
		}
	}
	return out
}
func (e *Engine) protectionImpact(r *ProtectionReview, before, after ProtectionState) error {
	r.Downgrades = configuredDowngrades(before, after, *r)
	for _, s := range []ProtectionState{before, after} {
		for _, p := range s.Policies {
			if (r.Resource == "policies" && p.ID == r.ResourceID) || (r.Resource == "templates" && slices.Contains(p.TemplateIDs, r.ResourceID)) {
				r.AffectedPolicyIDs = addUnique(r.AffectedPolicyIDs, p.ID)
			}
		}
	}
	nodes, err := list[ClientNode](e, "client_nodes")
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if n.Revoked {
			continue
		}
		binding := ProtectionBinding{AgentID: n.ID, PolicyIDs: []string{}}
		affected := r.Resource == "tags" && r.ResourceID == n.ID
		for _, state := range []ProtectionState{before, after} {
			for _, p := range state.Policies {
				if policyApplies(p, n.ID, state.Tags[n.ID]) && ((r.Resource != "tags" && slices.Contains(r.AffectedPolicyIDs, p.ID)) || (r.Resource == "tags" && r.ResourceID == n.ID)) {
					affected = true
					r.AffectedPolicyIDs = addUnique(r.AffectedPolicyIDs, p.ID)
				}
			}
		}
		for _, p := range after.Policies {
			if policyApplies(p, n.ID, after.Tags[n.ID]) {
				binding.PolicyIDs = append(binding.PolicyIDs, p.ID)
			}
		}
		if affected {
			r.AffectedAgentIDs = append(r.AffectedAgentIDs, n.ID)
			slices.Sort(binding.PolicyIDs)
			r.Bindings = append(r.Bindings, binding)
		}
	}
	slices.Sort(r.AffectedPolicyIDs)
	slices.Sort(r.AffectedAgentIDs)
	return nil
}
