package core

import "time"

// ContentState is the session audit's local availability vocabulary. It describes
// persisted content, not whether execution is expected or permitted.
type ContentState string

const (
	ContentCaptured             ContentState = "captured"
	ContentPolicyOmitted        ContentState = "policy_omitted"
	ContentNotYetAvailable      ContentState = "not_yet_available"
	ContentPermissionRestricted ContentState = "permission_restricted"
	ContentNeverCaptured        ContentState = "never_captured"
)

func reviewInputState(r Review) ContentState {
	// Match Submit's whole-input omission predicate (reviews.go), not merely
	// the presence of SensitiveInfo: a clean check retains the input.
	if s := r.SensitiveInfo; s != nil && (len(s.Findings) > 0 || s.Unavailable || s.Reason != "") {
		return ContentPolicyOmitted
	}
	if r.Arguments != nil || len(r.Scripts) > 0 || r.UserMessage != "" || r.Context != "" {
		return ContentCaptured
	}
	return ContentNeverCaptured
}

func reviewOutputState(r Review) ContentState {
	// Result stores strings, so succeeded/failed are the persisted evidence of
	// a received result even when its content is empty.
	if r.Result != "" || r.Execution == "succeeded" || r.Execution == "failed" {
		if r.SensitiveInfo != nil {
			return ContentPolicyOmitted
		}
		return ContentCaptured
	}
	if r.Decision == "pending" || r.Execution == "awaiting_execution" {
		return ContentNotYetAvailable
	}
	return ContentNeverCaptured
}

// ReviewMetaView deliberately excludes arguments, user messages, context,
// results, legacy model context and detailed model input from the wire type.
// Script files retain only the metadata provided by ReviewListView.
type ReviewMetaView struct {
	InputState          ContentState     `json:"inputState"`
	OutputState         ContentState     `json:"outputState"`
	SensitiveInfo       *SensitiveResult `json:"sensitiveInfo,omitempty"`
	Agent               string           `json:"agent"`
	ID                  string           `json:"id"`
	InstanceID          string           `json:"instanceId"`
	CallID              string           `json:"callId"`
	ToolName            string           `json:"toolName"`
	ScriptCaptureStatus string           `json:"scriptCaptureStatus,omitempty"`
	Scripts             []ReviewScript   `json:"scriptFiles,omitempty"`
	ModelInputDigest    string           `json:"modelInputDigest,omitempty"`
	ModelName           string           `json:"modelName,omitempty"`
	SessionID           string           `json:"sessionId"`
	Cwd                 string           `json:"cwd"`
	Digest              string           `json:"digest"`
	Mode                string           `json:"mode"`
	ReviewPath          string           `json:"reviewPath"`
	Version             int              `json:"version"`
	Prompt              string           `json:"prompt"`
	Rules               []Rule           `json:"rules"`
	Scopes              []Scope          `json:"scopes"`
	Decision            string           `json:"decision"`
	RuleID              string           `json:"ruleId"`
	Comment             string           `json:"comment"`
	Execution           string           `json:"execution"`
	CreatedAt           time.Time        `json:"createdAt"`
	DecidedAt           *time.Time       `json:"decidedAt"`
	NeedsHuman          bool             `json:"needsHuman"`
	ModelVerdict        *Decision        `json:"modelVerdict,omitempty"`
	Deadline            time.Time        `json:"deadline"`
}

// ProjectReviewContent accepts the server's settled capability, never a caller
// identity. Use it for both legacy arrays and paginated items.
func ProjectReviewContent(reviews []Review, contentAllowed bool) []any {
	out := make([]any, 0, len(reviews))
	for _, review := range reviews {
		r := ReviewListView(review)
		if contentAllowed {
			out = append(out, r)
			continue
		}
		out = append(out, ReviewMetaView{
			InputState: ContentPermissionRestricted, OutputState: ContentPermissionRestricted,
			SensitiveInfo: r.SensitiveInfo, Agent: r.Agent, ID: r.ID,
			InstanceID: r.InstanceID, CallID: r.CallID, ToolName: r.ToolName,
			ScriptCaptureStatus: r.ScriptCaptureStatus, Scripts: r.Scripts,
			ModelInputDigest: r.ModelInputDigest, ModelName: r.ModelName,
			SessionID: r.SessionID, Cwd: r.Cwd, Digest: r.Digest, Mode: r.Mode,
			ReviewPath: r.ReviewPath, Version: r.Version, Prompt: r.Prompt,
			Rules: r.Rules, Scopes: r.Scopes, Decision: r.Decision, RuleID: r.RuleID,
			Comment: r.Comment, Execution: r.Execution, CreatedAt: r.CreatedAt,
			DecidedAt: r.DecidedAt, NeedsHuman: r.NeedsHuman, ModelVerdict: r.ModelVerdict,
			Deadline: r.Deadline,
		})
	}
	return out
}
