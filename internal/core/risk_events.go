package core

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

var ErrRiskEventQuery = errors.New("invalid risk event query or page token")

type RiskEventFilter struct {
	Severity, Category, Agent string
	From                      *int64 `json:"From,omitempty"`
	To                        *int64 `json:"To,omitempty"`
}
type RiskEventPage struct {
	Items         []Event `json:"items"`
	NextPageToken string  `json:"next_page_token"`
}

func validRiskCategory(value string) bool {
	return hasExact(value, "category::sensitive-info", "category::high-risk-ops", "category::prompt-attack", "category::behavior", "category::supply-chain")
}
func validRiskFilter(filter RiskEventFilter) bool {
	return (filter.Severity == "" || hasExact(filter.Severity, "unknown", "low", "medium", "high", "critical")) && (filter.Category == "" || validRiskCategory(filter.Category)) && (filter.From == nil || filter.To == nil || *filter.From <= *filter.To)
}
func riskEventMatches(event Event, filter RiskEventFilter) bool {
	if (filter.From != nil && event.Data.Time < *filter.From) || (filter.To != nil && event.Data.Time >= *filter.To) {
		return false
	}
	if filter.Severity != "" && event.Data.SeverityID != severityID(filter.Severity) {
		return false
	}
	if filter.Category != "" && (event.Data.FindingInfo == nil || !hasExact(filter.Category, event.Data.FindingInfo.Types...)) {
		return false
	}
	return filter.Agent == "" || event.Data.Actor.AppUID == filter.Agent
}

type riskEventOccurrence struct {
	Event
	AuditID    string
	EventIndex int
}

func riskPageToken(event riskEventOccurrence, filter RiskEventFilter) string {
	// SHA-256 hides the cursor representation; tokens carry no authorization.
	// Bind the stored occurrence, not just its shared CloudEvents identity.
	// Filter binding detects changed arguments; page_size may change (AIP-158).
	payload, _ := json.Marshal(struct {
		ID, Source, AuditID string
		EventIndex          int
		Filter              RiskEventFilter
	}{event.ID, event.Source, event.AuditID, event.EventIndex, filter})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
func (e *Engine) riskEvents() ([]Event, error) {
	occurrences, err := e.riskEventOccurrences()
	if err != nil {
		return nil, err
	}
	events := make([]Event, 0, len(occurrences))
	for _, occurrence := range occurrences {
		events = append(events, occurrence.Event)
	}
	return events, nil
}
func (e *Engine) riskEventOccurrences() ([]riskEventOccurrence, error) {
	audits, err := e.Audits()
	if err != nil {
		return nil, err
	}
	events := []riskEventOccurrence{}
	for _, audit := range audits {
		for index, event := range audit.Events {
			if event.Type == "tg.sentry.risk.v1" {
				events = append(events, riskEventOccurrence{event, audit.ID, index})
			}
		}
	}
	// Preserve audit-row/array order when occurrence time and event ID tie.
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Time.Equal(events[j].Time) {
			return events[i].ID > events[j].ID
		}
		return events[i].Time.After(events[j].Time)
	})
	return events, nil
}
func (e *Engine) RiskEvents(pageSize int, pageToken string, filter RiskEventFilter) (RiskEventPage, error) {
	if pageSize < 0 || !validRiskFilter(filter) {
		return RiskEventPage{}, ErrRiskEventQuery
	}
	// Reuse the existing calls-page default and ceiling (store.go ReviewsPage).
	if pageSize == 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	// ponytail: M1 scans existing audit rows, as AIP-158 permits for small sets.
	// M2 (#11) should index the typed event projection; no parallel event store.
	events, err := e.riskEventOccurrences()
	if err != nil {
		return RiskEventPage{}, err
	}
	page := RiskEventPage{Items: []Event{}}
	found := pageToken == ""
	lastToken := ""
	for _, occurrence := range events {
		event := occurrence.Event
		if !riskEventMatches(event, filter) {
			continue
		}
		if !found {
			if riskPageToken(occurrence, filter) == pageToken {
				found = true
			}
			continue
		}
		if len(page.Items) == pageSize {
			page.NextPageToken = lastToken
			break
		}
		page.Items = append(page.Items, event)
		lastToken = riskPageToken(occurrence, filter)
	}
	if !found {
		return RiskEventPage{}, ErrRiskEventQuery
	}
	return page, nil
}
func (e *Engine) RiskEvent(id string) (Event, error) {
	events, err := e.riskEvents()
	if err != nil {
		return Event{}, err
	}
	for _, event := range events {
		if event.ID == id {
			return event, nil
		}
	}
	return Event{}, sql.ErrNoRows
}
