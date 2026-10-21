package core

import (
	"database/sql"
	"reflect"
	"slices"
)

// MatchesNode is exact enrolled-device selection, not an authorization decision.
// Precedent: https://docs.byteplus.com/en/docs/ClawSentry/configure-the-log-whitelist#hFq22VpgC;
// enrolled-node identity and validation follow the existing #44 ACL resource.
func (r LogWhitelistEntry) MatchesNode(node string) bool {
	return r.Enabled && r.Subject.Kind == "agents" && node != "" && slices.Contains(r.Subject.AgentIDs, node)
}

// Admission snapshot follows the existing immutable Review policy snapshots.
// BytePlus Configuration effect: risk events remain, audit/context do not.
// https://docs.byteplus.com/en/docs/ClawSentry/configure-the-log-whitelist#hmPVeCwdd
func logSuppression(s ProtectionState, node string) *LogSuppression {
	ids := []string{}
	for _, entry := range s.LogWhitelist {
		if entry.MatchesNode(node) {
			ids = append(ids, entry.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return &LogSuppression{Revision: s.Revision, EntryIDs: ids}
}

// Explicit allowlist, not a response redactor. Live evaluation/model dispatch
// use the original Review; only this operational projection may be serialized.
func suppressedReview(r Review) Review {
	if r.LogSuppression == nil {
		return r
	}
	out := Review{
		LogSuppression: &LogSuppression{Revision: r.LogSuppression.Revision, EntryIDs: slices.Clone(r.LogSuppression.EntryIDs)},
		Agent:          r.Agent, ID: r.ID, SessionID: r.SessionID, Digest: r.Digest,
		ReviewInput: ReviewInput{InstanceID: r.InstanceID, CallID: r.CallID, ToolName: r.ToolName, ScriptCaptureStatus: r.ScriptCaptureStatus},
		Mode:        r.Mode, Version: r.Version, ReviewPath: r.ReviewPath, ModelName: r.ModelName,
		ModelInputDigest: r.ModelInputDigest, Decision: r.Decision, RuleID: r.RuleID,
		Execution: r.Execution, BlockConfirmed: r.BlockConfirmed, NeedsHuman: r.NeedsHuman,
		CreatedAt: r.CreatedAt, DecidedAt: r.DecidedAt, Deadline: r.Deadline,
		InputState: ContentPolicyOmitted,
	}
	for _, rule := range r.Rules {
		out.Rules = append(out.Rules, Rule{ID: rule.ID, Enabled: rule.Enabled, Decision: rule.Decision,
			Matcher: rule.Matcher, Severity: rule.Severity, Categories: slices.Clone(rule.Categories)})
	}
	if r.ModelVerdict != nil {
		out.ModelVerdict = &Decision{Decision: r.ModelVerdict.Decision, RuleID: r.ModelVerdict.RuleID}
	}
	if r.SensitiveInfo != nil {
		out.SensitiveInfo = &SensitiveResult{Findings: slices.Clone(r.SensitiveInfo.Findings),
			Decision: r.SensitiveInfo.Decision, RuleID: r.SensitiveInfo.RuleID, Unavailable: r.SensitiveInfo.Unavailable}
	}
	if r.PromptAttack != nil {
		out.PromptAttack = &PromptAttackResult{Findings: slices.Clone(r.PromptAttack.Findings), Evidence: slices.Clone(r.PromptAttack.Evidence),
			Decision: r.PromptAttack.Decision, Unavailable: r.PromptAttack.Unavailable}
		out.PromptAttackNSFAMode = r.PromptAttackNSFAMode
	}
	out.OutputState = reviewOutputState(r)
	return out
}

func logWhitelistIndex(s ProtectionState, id string) int {
	return slices.IndexFunc(s.LogWhitelist, func(r LogWhitelistEntry) bool { return r.ID == id })
}

func (e *Engine) validateLogWhitelist(r LogWhitelistEntry) error {
	if !validProtectionName(r.Name) || r.Subject.Kind != "agents" || len(r.Subject.AgentIDs) == 0 {
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
	return nil
}

func (e *Engine) reviewLogWhitelist(s *ProtectionState, c ProtectionChange) error {
	idx := logWhitelistIndex(*s, c.ID)
	if c.ID != "" && idx < 0 {
		return sql.ErrNoRows
	}
	entries := slices.Clone(s.LogWhitelist)
	if c.Delete {
		s.LogWhitelist = slices.Delete(entries, idx, idx+1)
		return nil
	}
	if c.LogWhitelist == nil {
		return ErrProtectionInvalid
	}
	if err := e.validateLogWhitelist(*c.LogWhitelist); err != nil {
		return err
	}
	r := *c.LogWhitelist
	r.ID, r.UpdatedAt = c.ID, e.clock()
	if r.ID == "" {
		r.ID = ID()
	}
	r.Subject.AgentIDs = slices.Clone(r.Subject.AgentIDs)
	if idx < 0 {
		entries = append(entries, r)
	} else {
		entries[idx] = r
	}
	s.LogWhitelist = entries
	return nil
}

// As with aclPermissionExpanded, conservatively acknowledge enabled subject
// changes rather than inventing a scope-subsumption solver. Only recording is
// reduced; protection and risk reporting are not weakened by this resource.
func logWhitelistRecordingReduced(before, after ProtectionState, id string) bool {
	var old, next LogWhitelistEntry
	if idx := logWhitelistIndex(before, id); idx >= 0 {
		old = before.LogWhitelist[idx]
	}
	if idx := logWhitelistIndex(after, id); idx >= 0 {
		next = after.LogWhitelist[idx]
	}
	return next.Enabled && (!old.Enabled || !reflect.DeepEqual(old.Subject, next.Subject))
}
