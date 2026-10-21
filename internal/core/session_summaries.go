package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrSessionSummaryQuery = errors.New("invalid session summary query")

// Plan §3.2 / LD2 and LD5: metadata only; user association is deferred to #72.
type SessionDevice struct {
	NodeID string `json:"nodeId"`
	Name   string `json:"name,omitempty"`
}
type SessionSummary struct {
	SessionID   string          `json:"sessionId"`
	Agents      []string        `json:"agents"`
	Devices     []SessionDevice `json:"devices"`
	User        *string         `json:"user"`
	UserState   string          `json:"userState"`
	SessionTime time.Time       `json:"sessionTime"`
	LastCallAt  *time.Time      `json:"lastCallAt"`
	CallCount   int             `json:"callCount"`
}
type SessionSummaryFilter struct{ Agent, NodeID, SessionKey, From, To string }
type SessionSummaryPage struct {
	Items    []SessionSummary `json:"items"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"pageSize"`
}

// Nine fixed fractional digits retain RFC3339Nano precision and make UTC
// instants sortable (§3.2, A3); time.RFC3339Nano itself trims trailing zeros.
const sessionInstantLayout = "2006-01-02T15:04:05.000000000Z"

func sessionBound(value string, upper bool) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	stamp, err := time.Parse("2006-01-02", value)
	if err == nil {
		if upper {
			stamp = stamp.AddDate(0, 0, 1)
		}
		return stamp, nil
	}
	stamp, err = time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, ErrSessionSummaryQuery
	}
	return stamp.UTC(), nil
}

func sessionSummaryWhere(filter SessionSummaryFilter) (string, []any, error) {
	from, err := sessionBound(filter.From, false)
	if err != nil {
		return "", nil, err
	}
	to, err := sessionBound(filter.To, true)
	if err != nil {
		return "", nil, err
	}
	if filter.From != "" && filter.To != "" && from.After(to) {
		return "", nil, ErrSessionSummaryQuery
	}
	where := []string{}
	args := []any{eventTenant()}
	add := func(expr string, value any) {
		args = append(args, value)
		where = append(where, strings.ReplaceAll(expr, "?", fmt.Sprintf("$%d", len(args))))
	}
	if filter.Agent != "" {
		add("EXISTS (SELECT 1 FROM activity a WHERE a.session_id=s.session_id AND a.agent=?)", AgentID(filter.Agent))
	}
	if filter.NodeID != "" {
		add("EXISTS (SELECT 1 FROM activity a WHERE a.session_id=s.session_id AND a.node=?)", filter.NodeID)
	}
	if filter.SessionKey != "" {
		add("s.session_id=?", filter.SessionKey)
	}
	if filter.From != "" {
		add("s.session_time>=?", from.Format(sessionInstantLayout))
	}
	if filter.To != "" {
		add("s.session_time<?", to.Format(sessionInstantLayout))
	}
	if len(where) == 0 {
		return "", args, nil
	}
	return "WHERE " + strings.Join(where, " AND "), args, nil
}

func (e *Engine) SessionSummaries(page, pageSize int, filter SessionSummaryFilter) (SessionSummaryPage, error) {
	// Existing /calls bounds, per plan LD9. HTTP rejects invalid values.
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	where, args, err := sessionSummaryWhere(filter)
	if err != nil {
		return SessionSummaryPage{}, err
	}
	// Guard offset overflow for non-HTTP callers as well.
	if page-1 > int(^uint(0)>>1)/pageSize {
		return SessionSummaryPage{}, ErrSessionSummaryQuery
	}
	query := e.sessionSummariesSQL(where, len(args)+1, len(args)+2)
	args = append(args, pageSize, (page-1)*pageSize)
	tx, err := e.beginTenant()
	if err != nil {
		return SessionSummaryPage{}, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(query, args...)
	if err != nil {
		return SessionSummaryPage{}, err
	}
	defer rows.Close()
	out := SessionSummaryPage{Items: []SessionSummary{}, Page: page, PageSize: pageSize}
	for rows.Next() {
		item, total, err := scanSessionSummary(rows)
		if err != nil {
			return SessionSummaryPage{}, err
		}
		out.Total = total
		if item != nil {
			out.Items = append(out.Items, *item)
		}
	}
	return out, rows.Err()
}

func scanSessionSummary(rows *sql.Rows) (*SessionSummary, int, error) {
	var total int
	var id, stamp, last, agents, devices sql.NullString
	var count sql.NullInt64
	if err := rows.Scan(&total, &id, &stamp, &last, &count, &agents, &devices); err != nil {
		return nil, 0, err
	}
	if !id.Valid {
		return nil, total, nil
	}
	item := SessionSummary{SessionID: id.String, Agents: []string{}, Devices: []SessionDevice{}, UserState: "unassociated", CallCount: int(count.Int64)}
	var err error
	item.SessionTime, err = time.Parse(sessionInstantLayout, stamp.String)
	if err != nil {
		return nil, 0, err
	}
	if last.Valid {
		value, err := time.Parse(sessionInstantLayout, last.String)
		if err != nil {
			return nil, 0, err
		}
		item.LastCallAt = &value
	}
	if agents.Valid && agents.String != "null" {
		if err := json.Unmarshal([]byte(agents.String), &item.Agents); err != nil {
			return nil, 0, err
		}
	}
	if devices.Valid && devices.String != "null" {
		if err := json.Unmarshal([]byte(devices.String), &item.Devices); err != nil {
			return nil, 0, err
		}
	}
	return &item, total, nil
}
