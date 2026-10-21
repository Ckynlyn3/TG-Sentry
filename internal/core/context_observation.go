package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"
	"unicode/utf8"
)

type ContextObservationKind string

const (
	ContextObservationInstructions    ContextObservationKind = "instructions"
	ContextObservationToolDefinitions ContextObservationKind = "tool_definitions"
)

type ContextObservationCoverage string

const (
	ContextCoverageObserved  ContextObservationCoverage = "observed"
	ContextCoveragePrepared  ContextObservationCoverage = "prepared"
	ContextCoverageSubmitted ContextObservationCoverage = "submitted"
)

type ContextObservationSource struct {
	Adapter        string `json:"adapter"`
	AdapterVersion string `json:"adapterVersion"`
	Hook           string `json:"hook"`
	SourceRevision string `json:"sourceRevision"`
}

type ContextObservationMeta struct {
	ID              string                     `json:"id"`
	Kind            ContextObservationKind     `json:"kind"`
	Coverage        ContextObservationCoverage `json:"coverage"`
	ContentState    ContentState               `json:"contentState"`
	Source          ContextObservationSource   `json:"source"`
	SessionID       string                     `json:"sessionId"`
	InstanceID      string                     `json:"instanceId"`
	ReviewID        string                     `json:"reviewId,omitempty"`
	NativeAttemptID string                     `json:"nativeAttemptId,omitempty"`
	EpochDigest     string                     `json:"epochDigest,omitempty"`
	ObservedAt      time.Time                  `json:"observedAt"`
	SensitiveInfo   *SensitiveResult           `json:"sensitiveInfo,omitempty"`
}

type ContextInstructions struct {
	Attribute string           `json:"attribute"`
	Parts     []map[string]any `json:"parts"`
}

type ContextToolDefinitions struct {
	Attribute string           `json:"attribute"`
	Items     []map[string]any `json:"items"`
}

type ContextObservation struct {
	ContextObservationMeta
	Instructions    *ContextInstructions    `json:"instructions,omitempty"`
	ToolDefinitions *ContextToolDefinitions `json:"toolDefinitions,omitempty"`
}

func (o ContextObservation) Validate() error {
	if o.Kind != ContextObservationInstructions && o.Kind != ContextObservationToolDefinitions {
		return errors.New("invalid observation kind")
	}
	switch o.Coverage {
	case ContextCoverageObserved, ContextCoveragePrepared, ContextCoverageSubmitted:
	default:
		return errors.New("invalid observation coverage")
	}
	switch o.ContentState {
	case ContentCaptured, ContentPolicyOmitted, ContentNotYetAvailable, ContentPermissionRestricted, ContentNeverCaptured:
	default:
		return errors.New("invalid observation content state")
	}
	if err := o.validateSource(); err != nil {
		return err
	}
	if _, err := json.Marshal(o.ObservedAt); err != nil {
		return errors.New("invalid observation instant")
	}
	if o.EpochDigest != "" {
		digest, err := hex.DecodeString(o.EpochDigest)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != o.EpochDigest {
			return errors.New("invalid observation digest")
		}
	}
	if o.SensitiveInfo != nil && o.SensitiveInfo.Findings == nil {
		return errors.New("sensitive findings require an array")
	}
	if o.ContentState != ContentCaptured {
		if o.Instructions != nil || o.ToolDefinitions != nil {
			return errors.New("non-captured observation carries content")
		}
		return nil
	}
	if o.EpochDigest == "" {
		return errors.New("captured observation requires a digest")
	}
	if o.Kind == ContextObservationInstructions {
		if o.Instructions == nil || o.ToolDefinitions != nil || o.Instructions.Attribute != "gen_ai.system_instructions" || o.Instructions.Parts == nil {
			return errors.New("instructions require exactly their OTel payload")
		}
		return validateContextParts(o.Instructions.Parts, false)
	}
	if o.ToolDefinitions == nil || o.Instructions != nil || o.ToolDefinitions.Attribute != "gen_ai.tool.definitions" || o.ToolDefinitions.Items == nil {
		return errors.New("tool definitions require exactly their OTel payload")
	}
	return validateContextParts(o.ToolDefinitions.Items, true)
}

func (o ContextObservation) validateSource() error {
	s := o.Source
	switch s.Adapter {
	case "openclaw":
		hook := "llm_input.systemPrompt"
		if o.Kind == ContextObservationToolDefinitions {
			hook = "llm_input.tools"
		}
		if s.AdapterVersion != "2026.10.4" || s.SourceRevision != "383c124cc32ffee3f8e56f549b88da94d269a4af" || s.Hook != hook || o.Coverage != ContextCoverageObserved {
			return errors.New("unadmitted OpenClaw observation source")
		}
	case "pi":
		hook := "before_agent_start.systemPrompt"
		if o.Kind == ContextObservationToolDefinitions {
			hook = "getAllTools()∩getActiveTools()"
		}
		if s.AdapterVersion != "1.3.0" || s.SourceRevision != "16f5f0af4d85ca583d045ceb5ed6d646fcaf7761" || s.Hook != hook || o.Coverage != ContextCoveragePrepared {
			return errors.New("unadmitted Pi observation source")
		}
	case "claude", "codex", "cursor", "opencode", "trae":
		if (o.ContentState != ContentNeverCaptured && o.ContentState != ContentPermissionRestricted) || s.Hook != "" {
			return errors.New("unavailable adapter requires no hook and never_captured or capability-restricted metadata")
		}
	default:
		return errors.New("invalid observation adapter")
	}
	return nil
}

func validateContextParts(parts []map[string]any, tools bool) error {
	for _, part := range parts {
		if _, ok := part["type"].(string); !ok {
			return errors.New("OTel payload part requires a string type")
		}
		if tools {
			if _, ok := part["name"].(string); !ok {
				return errors.New("OTel tool definition requires a string name")
			}
		}
	}
	return nil
}

func (o ContextObservation) MarshalJSON() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	type wire ContextObservation
	return json.Marshal(wire(o))
}

// UnmarshalJSON validates the closed wire object itself. encoding/json matches
// object keys case-insensitively, so DisallowUnknownFields alone would let an
// extra "ID" overwrite "id"; every closed object is therefore checked against
// its exact key set first. Reference: https://pkg.go.dev/encoding/json#Unmarshal
func (o *ContextObservation) UnmarshalJSON(data []byte) error {
	if err := requireContextByteLimit(data); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if err := requireContextFields(fields, contextObservationKeys, "id", "kind", "coverage", "contentState", "source", "sessionId", "instanceId", "observedAt"); err != nil {
		return err
	}
	var source map[string]json.RawMessage
	if err := json.Unmarshal(fields["source"], &source); err != nil {
		return err
	}
	if err := requireContextFields(source, contextObservationSourceKeys, "adapter", "adapterVersion", "hook", "sourceRevision"); err != nil {
		return err
	}
	for _, name := range []string{"reviewId", "nativeAttemptId", "epochDigest", "sensitiveInfo", "instructions", "toolDefinitions"} {
		if value, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("null optional observation field")
		}
	}
	if raw, ok := fields["epochDigest"]; ok {
		var digest string
		if err := json.Unmarshal(raw, &digest); err != nil || digest == "" {
			return errors.New("invalid observation digest")
		}
	}
	if raw, ok := fields["sensitiveInfo"]; ok {
		if err := validateContextSensitiveInfo(raw); err != nil {
			return err
		}
	}
	if raw, ok := fields["instructions"]; ok {
		if err := validateContextPayloadObject(raw, "gen_ai.system_instructions", "parts"); err != nil {
			return err
		}
	}
	if raw, ok := fields["toolDefinitions"]; ok {
		if err := validateContextPayloadObject(raw, "gen_ai.tool.definitions", "items"); err != nil {
			return err
		}
	}
	type wire ContextObservation
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if decoded.ContentState != ContentCaptured {
		for _, name := range []string{"instructions", "toolDefinitions"} {
			if _, ok := fields[name]; ok {
				return errors.New("non-captured observation has a payload key")
			}
		}
	}
	out := ContextObservation(decoded)
	if err := out.Validate(); err != nil {
		return err
	}
	*o = out
	return nil
}

func requireContextFields(fields map[string]json.RawMessage, allowed []string, names ...string) error {
	for name := range fields {
		if !slices.Contains(allowed, name) {
			return errors.New("unknown observation field: " + name)
		}
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("missing or null required observation field: " + name)
		}
	}
	return nil
}

func validateContextPayloadObject(raw json.RawMessage, attribute, content string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if err := requireContextFields(fields, []string{"attribute", content}, "attribute", content); err != nil {
		return err
	}
	var got string
	if err := json.Unmarshal(fields["attribute"], &got); err != nil || got != attribute {
		return errors.New("invalid observation payload attribute")
	}
	var items []map[string]any
	if err := json.Unmarshal(fields[content], &items); err != nil || items == nil {
		return errors.New("observation payload requires an array of objects")
	}
	return nil
}

func rejectContextNull(fields map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		if value, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("null optional observation field: " + name)
		}
	}
	return nil
}

func validateContextSensitiveInfo(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if err := requireContextFields(fields, contextSensitiveResultKeys, "findings", "decision", "unavailable"); err != nil {
		return err
	}
	var findings []json.RawMessage
	if err := json.Unmarshal(fields["findings"], &findings); err != nil || findings == nil {
		return errors.New("sensitive findings require an array")
	}
	if err := rejectContextNull(fields, "reason", "ruleId"); err != nil {
		return err
	}
	for _, finding := range findings {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(finding, &item); err != nil {
			return err
		}
		if err := requireContextFields(item, contextSensitiveFindingKeys, "category", "tag", "entityType", "score"); err != nil {
			return err
		}
		if err := rejectContextNull(item, "ruleId"); err != nil {
			return err
		}
		if span, ok := item["span"]; ok {
			var spanFields map[string]json.RawMessage
			if err := json.Unmarshal(span, &spanFields); err != nil {
				return err
			}
			if err := requireContextFields(spanFields, contextSensitiveSpanKeys, "startUTF16", "endUTF16"); err != nil {
				return err
			}
		}
	}
	return nil
}

// ContextObservationByteLimit is the aggregate ceiling for one observation,
// reused from the existing JSON request-body limit (internal/server/server.go:67,
// http.MaxBytesReader with 2<<20). It bounds allocation before decoding or
// scanning; no new number is introduced. Reference: OWASP Denial of Service,
// input validation.
const ContextObservationByteLimit = 2 << 20

var (
	contextObservationKeys       = []string{"id", "kind", "coverage", "contentState", "source", "sessionId", "instanceId", "reviewId", "nativeAttemptId", "epochDigest", "observedAt", "sensitiveInfo", "instructions", "toolDefinitions"}
	contextObservationSourceKeys = []string{"adapter", "adapterVersion", "hook", "sourceRevision"}
	contextSensitiveResultKeys   = []string{"findings", "decision", "unavailable", "reason", "ruleId"}
	contextSensitiveFindingKeys  = []string{"category", "tag", "entityType", "span", "score", "ruleId"}
	contextSensitiveSpanKeys     = []string{"startUTF16", "endUTF16"}
)

func requireContextByteLimit(data []byte) error {
	if len(data) > ContextObservationByteLimit {
		return errors.New("observation exceeds the byte limit")
	}
	return nil
}

func ContextObservationDigest(payload []byte) (string, error) {
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "", errors.New("invalid observation JSON")
	}
	return contextObservationDigest(decoded)
}

func contextObservationDigest(decoded any) (string, error) {
	data, err := json.Marshal(decoded)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func CaptureContextObservation(meta ContextObservationMeta, payload []byte) (ContextObservation, error) {
	out := ContextObservation{ContextObservationMeta: meta}
	out.ContentState, out.EpochDigest, out.SensitiveInfo = ContentNeverCaptured, "", nil
	if err := requireContextByteLimit(payload); err != nil {
		return ContextObservation{}, err
	}
	if len(payload) == 0 {
		return out, out.Validate()
	}
	out.ContentState = ContentCaptured
	if err := out.validateSource(); err != nil {
		return ContextObservation{}, err
	}
	if !utf8.Valid(payload) {
		out.ContentState = ContentPolicyOmitted
		out.SensitiveInfo = &SensitiveResult{Findings: []SensitiveFinding{}, Decision: "reject", Unavailable: true, Reason: "Credential pattern scan unavailable.", RuleID: "E_SECRET_SCAN"}
		return out, out.Validate()
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return ContextObservation{}, errors.New("invalid observation JSON")
	}
	if contextPayloadRedacted(decoded) {
		out.ContentState = ContentPolicyOmitted
		out.SensitiveInfo = &SensitiveResult{Findings: []SensitiveFinding{}, Decision: "reject", Reason: "Observation payload omitted by RedactText."}
		return out, out.Validate()
	}
	array, ok := decoded.([]any)
	if !ok {
		return ContextObservation{}, errors.New("observation payload must be an array")
	}
	parts := make([]map[string]any, len(array))
	for i, value := range array {
		part, ok := value.(map[string]any)
		if !ok {
			return ContextObservation{}, errors.New("observation payload part must be an object")
		}
		parts[i] = part
	}
	if out.Kind == ContextObservationInstructions {
		out.Instructions = &ContextInstructions{Attribute: "gen_ai.system_instructions", Parts: parts}
	} else {
		out.ToolDefinitions = &ContextToolDefinitions{Attribute: "gen_ai.tool.definitions", Items: parts}
	}
	var err error
	out.EpochDigest, err = contextObservationDigest(decoded)
	if err != nil {
		return ContextObservation{}, err
	}
	return out, out.Validate()
}

func contextPayloadRedacted(value any) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if RedactText(key) != key || contextPayloadRedacted(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if contextPayloadRedacted(child) {
				return true
			}
		}
	case string:
		return RedactText(value) != value
	}
	return false
}

func ProjectContextObservationContent(observation ContextObservation, contentAllowed bool) ContextObservation {
	if !contentAllowed {
		observation.ContentState = ContentPermissionRestricted
		observation.Instructions, observation.ToolDefinitions = nil, nil
	}
	return observation
}

func ContextObservationStartsEpoch(previousTenant string, previous *ContextObservation, tenant string, current ContextObservation) bool {
	return previous == nil || previousTenant != tenant || previous.InstanceID != current.InstanceID || previous.Source != current.Source || previous.SessionID != current.SessionID || previous.Kind != current.Kind || previous.Coverage != current.Coverage || previous.EpochDigest != current.EpochDigest
}
