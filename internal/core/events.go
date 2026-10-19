package core

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Event is the metadata-only CloudEvents projection of a committed review.
// OCSF 1.9.0 is pinned under testdata/event-schema; see docs/EVENT-SCHEMA.md.
// Raw review content stays in the existing review record, never this DTO.
type Event struct {
	SpecVersion     string    `json:"specversion"`
	ID              string    `json:"id"`
	Source          string    `json:"source"`
	Type            string    `json:"type"`
	Time            time.Time `json:"time"`
	DataContentType string    `json:"datacontenttype"`
	Data            EventData `json:"data"`
}
type EventData struct {
	CategoryUID  int           `json:"category_uid"`
	ClassUID     int           `json:"class_uid"`
	ActivityID   int           `json:"activity_id"`
	ActivityName string        `json:"activity_name,omitempty"`
	TypeUID      int           `json:"type_uid"`
	SeverityID   int           `json:"severity_id"`
	Time         int64         `json:"time"`
	Metadata     EventMetadata `json:"metadata"`
	Actor        EventActor    `json:"actor"`
	FindingInfo  *EventFinding `json:"finding_info,omitempty"`
	*EventControl
	SrcEndpoint *EventEndpoint `json:"src_endpoint,omitempty"`
	API         *EventAPI      `json:"api,omitempty"`
	StatusID    *int           `json:"status_id,omitempty"`
	Unmapped    EventUnmapped  `json:"unmapped"`
}
type EventControl struct {
	ActionID      int `json:"action_id"`
	DispositionID int `json:"disposition_id"`
}
type EventMetadata struct {
	UID            string       `json:"uid"`
	Version        string       `json:"version"`
	Product        EventProduct `json:"product"`
	Profiles       []string     `json:"profiles,omitempty"`
	TenantUID      string       `json:"tenant_uid"`
	CorrelationUID string       `json:"correlation_uid"`
	Labels         []string     `json:"labels,omitempty"`
}
type EventProduct struct {
	Name    string        `json:"name"`
	Feature *EventFeature `json:"feature,omitempty"`
}
type EventFeature struct {
	Name string `json:"name"`
}
type EventActor struct {
	AppUID string `json:"app_uid,omitempty"`
}
type EventFinding struct {
	UID      string         `json:"uid"`
	Types    []string       `json:"types,omitempty"`
	Analytic *EventAnalytic `json:"analytic,omitempty"`
}
type EventAnalytic struct {
	UID    string `json:"uid,omitempty"`
	TypeID int    `json:"type_id"`
}
type EventEndpoint struct {
	UID string `json:"uid,omitempty"`
}
type EventAPI struct {
	Operation string        `json:"operation"`
	Request   *EventRequest `json:"request,omitempty"`
}
type EventRequest struct {
	UID string `json:"uid"`
}
type EventUnmapped struct {
	TGSentry EventExtension `json:"tg_sentry"`
}
type EventExtension struct {
	ContentState  string `json:"content_state,omitempty"`
	IdentityState string `json:"identity_state,omitempty"`
	ToolCallID    string `json:"tool_call_id,omitempty"`
}

// eventTenant is the single server-owned tenant source for SQL, RLS and events.
// Provisioning and authenticated tenant selection remain out of scope (#12).
func eventTenant() string { return "default" }

func (e *Engine) reviewEvents(tx *sql.Tx, r Review, action string) ([]Event, error) {
	node, err := reviewEventNode(tx, r.InstanceID)
	if err != nil {
		return nil, err
	}
	events := []Event{}
	if action == "review.submit" || action == "review.result" {
		events = append(events, e.auditReviewEvent(r, node, action))
	}
	if event, ok := riskReviewEvent(r, node, action); ok && (r.PromptAttack == nil || !hasPromptAttackFinding(*r.PromptAttack, r.RuleID)) {
		events = append(events, event)
	}
	// Custom observations are independent of the winning (possibly denying)
	// verdict. Project their configured log/alert action, never a blocking claim.
	if r.SensitiveInfo != nil {
		for _, finding := range r.SensitiveInfo.Findings {
			if finding.Tag != "custom" || finding.RuleID == r.RuleID {
				continue
			}
			observed := r
			observed.RuleID, observed.ReviewPath, observed.Decision = finding.RuleID, "rule", "approve"
			for _, rule := range r.Rules {
				if rule.ID == finding.RuleID && rule.Decision == "reject" {
					observed.Decision = "reject"
				}
			}
			if event, ok := riskReviewEvent(observed, node, action); ok {
				events = append(events, event)
			}
		}
	}
	events = append(events, promptAttackEvents(r, node, action)...)
	return events, nil
}
func reviewEventNode(tx *sql.Tx, instanceID string) (string, error) {
	var i Instance
	var payload []byte
	if err := tx.QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind='instances' AND id=$2", eventTenant(), instanceID).Scan(&payload); err != nil {
		return "", err
	}
	if err := json.Unmarshal(payload, &i); err != nil {
		return "", err
	}
	if i.NodeID == "" {
		return "", nil
	}
	// #6 device identity: resolve the persisted enrollment in this event transaction.
	err := tx.QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind='client_nodes' AND id=$2", eventTenant(), i.NodeID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var enrolled ClientNode
	if err = json.Unmarshal(payload, &enrolled); err != nil {
		return "", err
	}
	if enrolled.Revoked || enrolled.ID != i.NodeID {
		return "", nil
	}
	return enrolled.ID, nil
}
func (e *Engine) auditReviewEvent(r Review, node, action string) Event {
	event := newReviewEvent(r, node, r.CreatedAt)
	event.Type = "tg.sentry.audit.v1"
	event.Data.CategoryUID = 6
	event.Data.ClassUID = 6003
	event.Data.ActivityID = 99
	event.Data.TypeUID = 600399
	event.Data.SeverityID = 1
	event.Data.ActivityName = "Tool Call Request"
	status := 0
	if action == "review.result" {
		event.Time = e.clock().UTC()
		event.Data.Time = event.Time.UnixMilli()
		event.Data.ActivityName = "Tool Call Result"
		switch r.Execution {
		case "succeeded":
			status = 1
		case "failed":
			status = 2
		}
	}
	event.Data.SrcEndpoint = &EventEndpoint{UID: node}
	event.Data.API = &EventAPI{Operation: screenedIdentifier(r.ToolName)}
	if r.CallID != "" {
		event.Data.API.Request = &EventRequest{UID: screenedIdentifier(r.CallID)}
	}
	event.Data.StatusID = &status
	event.Data.Unmapped.TGSentry.ContentState = "omitted"
	return event
}
func riskReviewEvent(r Review, node, action string) (Event, bool) {
	// Operational errors/timeouts are not detected attacks (EVENT-SCHEMA §3).
	if r.DecidedAt == nil || strings.HasPrefix(r.RuleID, "E_") {
		return Event{}, false
	}
	var rule *Rule
	if r.ReviewPath == "rule" {
		for j := range r.Rules {
			if r.Rules[j].ID == r.RuleID && r.Rules[j].Enabled {
				rule = &r.Rules[j]
				break
			}
		}
	}
	alert := rule != nil && hasExact(rule.Decision, "alert", "redact") && r.Decision == "approve"
	loggedSensitive := rule != nil && hasExact(SensitiveInfoCategory, rule.Categories...) && r.Decision == "approve"
	if r.Decision != "reject" && !alert && !loggedSensitive {
		return Event{}, false
	}
	// Output-only secret findings are new observations, not a claim that the
	// already executed tool was prevented. Input decisions are not re-emitted.
	resultSecret := false
	if action == "review.result" && r.SensitiveInfo != nil {
		for _, finding := range r.SensitiveInfo.Findings {
			resultSecret = resultSecret || finding.Tag == "secret"
		}
	}
	if !hasExact(action, "review.submit", "review.human", "review.model") && !resultSecret {
		return Event{}, false
	}
	event := newReviewEvent(r, node, *r.DecidedAt)
	event.Type = "tg.sentry.risk.v1"
	event.Data.EventControl = &EventControl{}
	event.Data.CategoryUID = 2
	event.Data.ClassUID = 2004
	event.Data.ActivityID = 1
	event.Data.TypeUID = 200401
	event.Data.Metadata.Profiles = []string{"security_control", "host"}
	event.Data.FindingInfo = &EventFinding{UID: eventIdentifier(r.ID)}
	if rule != nil {
		event.Data.SeverityID = severityID(rule.Severity)
		event.Data.FindingInfo.Types = append([]string(nil), rule.Categories...)
		event.Data.FindingInfo.Analytic = &EventAnalytic{UID: eventIdentifier(rule.ID), TypeID: 1}
	}
	if r.ReviewPath == "model" && r.ModelVerdict != nil {
		// OCSF 1.9.0 analytic type 4 is Learning (ML/DL), never a rule hit.
		analytic := &EventAnalytic{TypeID: 4}
		if r.ModelName != "" {
			analytic.UID = eventIdentifier(r.ModelName)
		}
		event.Data.FindingInfo.Analytic = analytic
		// Decision has no severity/category fields: preserve Unknown, not a guess.
	}
	if loggedSensitive || resultSecret {
		event.Data.ActionID = 3
		event.Data.DispositionID = 17 // OCSF monitor = Observed/Logged (EVENT-SCHEMA §3).
	} // Observed only; no replacement/prevention claim.
	if alert {
		event.Data.ActionID = 3
		event.Data.DispositionID = 19
	}
	// reject authorizes denial, but is not adapter evidence of enforced blocking.
	event.Data.Unmapped.TGSentry.ToolCallID = screenedIdentifier(r.CallID)
	return event, true
}
func newReviewEvent(r Review, node string, at time.Time) Event {
	id := ID()
	event := Event{SpecVersion: "1.0", ID: id, Source: "/control-plane", Time: at.UTC(), DataContentType: "application/json"}
	event.Data.Time = at.UnixMilli()
	event.Data.Metadata = EventMetadata{UID: id, Version: "1.9.0", Product: EventProduct{Name: "TG-Sentry"}, TenantUID: eventTenant(), CorrelationUID: screenedIdentifier(r.SessionID)}
	if node != "" {
		event.Source = "/endpoints/" + node
		event.Data.Actor.AppUID = node + "/" + eventIdentifier(r.Agent)
	} else {
		event.Data.Unmapped.TGSentry.IdentityState = "unenrolled"
	}
	return event
}
func severityID(value string) int {
	return map[string]int{"unknown": 0, "low": 2, "medium": 3, "high": 4, "critical": 5}[value]
}

// No caller may accidentally consume an allow alongside a failed audit commit.
func (e *Engine) commitReviewOutcome(ctx context.Context, r Review, action string) (Review, error) {
	if err := e.commitReview(ctx, r, action); err != nil {
		r.Decision = "reject"
		r.Execution = "not_executed"
		r.NeedsHuman = false
		return r, err
	}
	return r, nil
}

// eventIdentifier restricts opaque metadata to RFC 3986 unreserved characters.
// The 64-byte source ceiling reuses the custom rule-ID suffix limit (policy.go).
// Named local exception: digests preserve correlation, not anonymity (§5).
// Only plain identifiers pass through; the sha256: namespace is reserved for
// generated digests so a caller-supplied digest cannot alias another value.
var eventIdentifierPattern = regexp.MustCompile(`^(?:[A-Za-z0-9._~-]{1,64}|sha256:[a-f0-9]{64})$`)
var plainEventIdentifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

// Alphanumeric tokens preserve opaque hex IDs: letters are not delimiters.
var privateIdentifierRuns = regexp.MustCompile(`[A-Za-z0-9]+`)
var generatedIdentifier = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func privateIdentifier(value string) bool {
	for _, run := range privateIdentifierRuns.FindAllString(value, -1) {
		digits := strings.TrimSuffix(strings.TrimSuffix(run, "x"), "X")
		if len(digits) >= 13 && len(digits) <= 19 && ValidLuhn(digits) || ValidCNID(run) {
			return true
		}
	}
	return false
}

// Lifecycle APIs accept either the raw identifier or the already screened store
// key. Register reserves the digest namespace, so callers cannot alias a key.
func screenedIdentifier(value string) string {
	if generatedIdentifier.MatchString(value) {
		return value
	}
	return eventIdentifier(value)
}

func eventIdentifier(value string) string {
	if value == "" {
		return ""
	}
	redacted := RedactText(value)
	// ISO/IEC 7812 PAN lengths (13–19 digits) and GB 11643 identifiers
	// are private even when used as metadata and BTPII is not enabled.
	private := privateIdentifier(value)
	if redacted == value && !private && plainEventIdentifier.MatchString(redacted) {
		return redacted
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Each source/rule/head has its own occurrence, including observations beside a
// stronger denial. Sources and tags are allowlisted; no input or reply is copied.
func promptAttackEvents(r Review, node, action string) []Event {
	if r.PromptAttack == nil || !hasExact(action, "review.submit", "review.model", "review.result") {
		return nil
	}
	// Human-only authorization waits do not defer completed synchronous findings.
	// Async detection still emits once from review.model, never review.human.
	if action == "review.submit" && r.Decision == "pending" && (r.ReviewPath != "human" || !r.NeedsHuman) {
		return nil
	}
	events := []Event{}
	findings := append([]PromptAttackFinding(nil), r.PromptAttack.Findings...)
	// An evidence-only NSFA head still has an occurrence, attributed to an enabled
	// effective binding without manufacturing a fourteen-tag classifier label.
	for _, evidence := range r.PromptAttack.Evidence {
		if evidence.Head == "Dangerous_Operations_Tool_Abuse" {
			for _, rule := range r.Rules {
				if rule.Enabled && rule.Matcher == "prompt-attack" {
					findings = append(findings, PromptAttackFinding{RuleID: rule.ID, Type: "nsfa:" + evidence.Head})
					break
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, f := range findings {
		source := f.Type
		head := ""
		if strings.HasPrefix(source, "nsfa:") {
			head = strings.TrimPrefix(source, "nsfa:")
			source = "nsfa"
		}
		if !hasExact(source, "pattern", "classifier", "nsfa") {
			continue
		}
		var matched *Rule
		for j := range r.Rules {
			if r.Rules[j].ID == f.RuleID {
				matched = &r.Rules[j]
				break
			}
		}
		if matched == nil {
			continue
		}
		uid := r.ID + "/pa/" + eventIdentifier(f.RuleID) + "/" + source
		if head != "" {
			uid += "/" + eventIdentifier(head)
		}
		if seen[uid] {
			continue
		}
		seen[uid] = true
		observed := r
		observed.Decision = "reject"
		observed.ReviewPath = "rule"
		observed.RuleID = f.RuleID
		now := r.CreatedAt
		if r.DecidedAt != nil {
			now = *r.DecidedAt
		}
		observed.DecidedAt = &now
		event, ok := riskReviewEvent(observed, node, "review.model")
		if !ok {
			continue
		}
		event.Data.FindingInfo.UID = uid
		if f.Tag != "" {
			event.Data.Metadata.Labels = []string{f.Tag}
		}
		feature := source
		if feature == "pattern" {
			feature = "patterns"
		}
		event.Data.Metadata.Product.Feature = &EventFeature{Name: "prompt-attack/" + feature}
		if source == "classifier" {
			event.Data.FindingInfo.Analytic.TypeID = 4
		}
		if action == "review.result" {
			event.Data.ActionID = 3
			event.Data.DispositionID = 15
		} else if source == "nsfa" && r.PromptAttackNSFAMode != "enforce" || matched.Decision == "approve" {
			event.Data.ActionID = 3
			event.Data.DispositionID = 17
		} else if matched.Decision == "alert" {
			event.Data.ActionID = 3
			event.Data.DispositionID = 19
		}
		events = append(events, event)
	}
	return events
}
