package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Product defaults, not statutory retention periods:
// Defender XDR, "Data retention": https://learn.microsoft.com/en-us/defender-xdr/data-privacy#data-retention
// Purview Audit Standard: https://learn.microsoft.com/en-us/purview/audit-solutions-overview#audit-standard
const defaultRetentionDays = 180

// time.Duration's int64 nanoseconds bound, not a product policy maximum.
const maxRetentionDays = int64((1<<63 - 1) / (24 * time.Hour))

type RetentionPolicy struct {
	EventsDays int64 `json:"eventsDays"`
	AuditDays  int64 `json:"auditDays"`
}

// LoadRetentionPolicy reads operator environment only; Open never adopts a
// policy or starts purging. The serve-owned worker must adopt before its first run.
func LoadRetentionPolicy() (RetentionPolicy, error) {
	p := RetentionPolicy{EventsDays: defaultRetentionDays, AuditDays: defaultRetentionDays}
	for name, dst := range map[string]*int64{
		"TG_SENTRY_EVENTS_RETENTION_DAYS": &p.EventsDays,
		"TG_SENTRY_AUDIT_RETENTION_DAYS":  &p.AuditDays,
	} {
		value, set := os.LookupEnv(name)
		if !set {
			continue
		}
		if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return RetentionPolicy{}, fmt.Errorf("%s must be positive integer days", name)
		}
		days, err := strconv.ParseInt(value, 10, 64)
		if err != nil || days <= 0 || days > maxRetentionDays {
			return RetentionPolicy{}, fmt.Errorf("%s is outside the representable positive day range", name)
		}
		*dst = days
	}
	return p, nil
}

func (p RetentionPolicy) validate() error {
	if p.EventsDays <= 0 || p.AuditDays <= 0 || p.EventsDays > maxRetentionDays || p.AuditDays > maxRetentionDays {
		return errors.New("retention policy requires representable positive integer days")
	}
	return nil
}

// AdoptRetentionPolicy commits a changed effective policy and its audit together.
// Deployment operators own the environment; a caller context cannot fabricate
// a human attribution for this system configuration change.
func (e *Engine) AdoptRetentionPolicy(ctx context.Context, p RetentionPolicy) error {
	if err := p.validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tx, err := e.beginTenantTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin retention adoption: %w", err)
	}
	defer tx.Rollback()
	current, err := retentionPolicyTx(ctx, tx)
	if err == nil && current == p {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load retention policy: %w", err)
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, upsertRecord, eventTenant(), "retention", "current", string(payload)); err != nil {
		return fmt.Errorf("persist retention policy: %w", err)
	}
	a := Audit{ID: ID(), Actor: SystemActor("retention-config"), Action: "retention.config", Subject: "retention", Detail: string(payload), CreatedAt: e.clock()}
	if err := insertRetentionAudit(ctx, tx, a); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit retention adoption: %w", err)
	}
	if e.Notify != nil {
		e.Notify()
	}
	return nil
}

func retentionPolicyTx(ctx context.Context, tx *sql.Tx) (RetentionPolicy, error) {
	var payload string
	if err := tx.QueryRowContext(ctx, "SELECT payload FROM records WHERE tenant_id=$1 AND kind='retention' AND id='current'", eventTenant()).Scan(&payload); err != nil {
		return RetentionPolicy{}, err
	}
	var p RetentionPolicy
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return RetentionPolicy{}, err
	}
	return p, p.validate()
}

func insertRetentionAudit(ctx context.Context, tx *sql.Tx, a Audit) error {
	payload, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, insertRecord, eventTenant(), "audit", a.ID, string(payload)); err != nil {
		return fmt.Errorf("insert retention audit: %w", err)
	}
	return nil
}

// PurgeResult is also the metadata-only transactional receipt: no deleted IDs
// or content. Counts describe committed deletions, never a rolled-back attempt.
type PurgeResult struct {
	Policy              RetentionPolicy `json:"policy"`
	EventsCutoff        time.Time       `json:"eventsCutoff"`
	AuditCutoff         time.Time       `json:"auditCutoff"`
	Reviews             int64           `json:"reviews"`
	EventEnvelopes      int64           `json:"eventEnvelopes"`
	AuditEnvelopes      int64           `json:"auditEnvelopes"`
	MalformedTimestamps int64           `json:"malformedTimestamps"`
}

// PurgeExpired removes whole rows in one tenant transaction under the existing
// writer lock. Named local exception "retention-envelope-categories": nonempty
// audit.events uses event retention; reviews and other audits use audit retention.
// Only reviews/audit are allowlisted; outbox and all other kinds survive.
// ponytail: set-based deletes without batching; measure expiry-wave contention
// before adding batches (MongoDB TTL, "Change the expireAfterSeconds value").
// https://www.mongodb.com/docs/manual/core/index-ttl/#change-the-expireafterseconds-value-for-a-ttl-index
func (e *Engine) PurgeExpired(ctx context.Context, now time.Time) (PurgeResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	tx, err := e.beginTenantTx(ctx, nil)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("begin retention purge: %w", err)
	}
	defer tx.Rollback()
	p, err := retentionPolicyTx(ctx, tx)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("load retention policy: %w", err)
	}
	now = now.UTC()
	result, err := retentionCutoffs(p, now)
	if err != nil {
		return PurgeResult{}, err
	}
	keys, malformed, err := e.expiredRetentionKeys(ctx, tx, result)
	if err != nil {
		return PurgeResult{}, err
	}
	result.MalformedTimestamps = malformed
	if malformed != 0 {
		// MongoDB TTL "Expiration of Data": missing/non-date fields do not
		// expire. Report counts only, never payloads or identifiers.
		// https://www.mongodb.com/docs/manual/core/index-ttl/#expiration-of-data
		slog.WarnContext(ctx, "retention skipped malformed timestamps", "count", malformed)
	}
	result, err = e.purgeRetentionKeys(ctx, tx, keys, result)
	if err != nil {
		return PurgeResult{}, err
	}
	if result.Reviews+result.EventEnvelopes+result.AuditEnvelopes == 0 {
		return result, nil
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return PurgeResult{}, err
	}
	a := Audit{ID: ID(), Actor: SystemActor("retention"), Action: "retention.purge", Subject: "retention", Detail: string(payload), CreatedAt: now}
	if err := insertRetentionAudit(ctx, tx, a); err != nil {
		return PurgeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return PurgeResult{}, fmt.Errorf("commit retention purge: %w", err)
	}
	if e.Notify != nil {
		e.Notify()
	}
	return result, nil
}

func retentionCutoffs(p RetentionPolicy, now time.Time) (PurgeResult, error) {
	if now.IsZero() {
		return PurgeResult{}, errors.New("retention clock is unset")
	}
	result := PurgeResult{Policy: p, EventsCutoff: now.Add(-time.Duration(p.EventsDays) * 24 * time.Hour), AuditCutoff: now.Add(-time.Duration(p.AuditDays) * 24 * time.Hour)}
	// Use time.Time.MarshalJSON's actual RFC 3339 representation limits, not
	// an invented year ceiling. See https://pkg.go.dev/time#Time.MarshalJSON.
	for _, stamp := range []time.Time{now, result.EventsCutoff, result.AuditCutoff} {
		if _, err := stamp.MarshalJSON(); err != nil {
			return PurgeResult{}, errors.New("retention clock or cutoff outside RFC 3339 date range")
		}
	}
	return result, nil
}

func (e *Engine) purgeRetentionKeys(ctx context.Context, tx *sql.Tx, keys [3][]string, result PurgeResult) (PurgeResult, error) {
	counts := []*int64{&result.Reviews, &result.EventEnvelopes, &result.AuditEnvelopes}
	for i, ids := range keys {
		if len(ids) == 0 {
			continue
		}
		kind := "audit"
		if i == 0 {
			kind = "reviews"
		}
		count, err := e.deleteRetentionKeys(ctx, tx, kind, ids)
		if err != nil {
			return PurgeResult{}, err
		}
		*counts[i] = count
	}
	return result, nil
}

func (e *Engine) expiredRetentionKeys(ctx context.Context, tx *sql.Tx, result PurgeResult) ([3][]string, int64, error) {
	var keys [3][]string
	var malformed int64
	events := "COALESCE(json_array_length(payload,'$.events'),0)"
	if e.postgres {
		events = "CASE WHEN json_typeof(payload::json->'events')='array' THEN json_array_length(payload::json->'events') ELSE 0 END"
	}
	rows, err := tx.QueryContext(ctx, "SELECT kind,id,"+e.jsonField("", "createdAt")+","+e.jsonField("", "decision")+","+events+" FROM records WHERE tenant_id=$1 AND kind IN ('reviews','audit')", eventTenant())
	if err != nil {
		return keys, 0, fmt.Errorf("select retention metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, id string
		var stamp, decision sql.NullString
		var eventCount int64
		if err := rows.Scan(&kind, &id, &stamp, &decision, &eventCount); err != nil {
			return keys, malformed, fmt.Errorf("read retention metadata: %w", err)
		}
		// Lead disposition: Go RFC3339Nano parsing is the single expiry rule.
		// It preserves offsets and nanoseconds without database conversion loss.
		created, err := time.Parse(time.RFC3339Nano, stamp.String)
		if !stamp.Valid || err != nil || created.IsZero() {
			malformed++
			continue
		}
		category, cutoff := 2, result.AuditCutoff
		if kind == "reviews" {
			category = 0
		} else if eventCount > 0 {
			category, cutoff = 1, result.EventsCutoff
		}
		if !created.Before(cutoff) {
			continue
		}
		if kind == "reviews" && decision.String == "pending" {
			return keys, malformed, errors.New("retention blocked by expired pending reviews; run decision expiry first")
		}
		keys[category] = append(keys[category], id)
	}
	return keys, malformed, rows.Err()
}

func (e *Engine) deleteRetentionKeys(ctx context.Context, tx *sql.Tx, kind string, ids []string) (int64, error) {
	// Native JSON table expansion avoids parameter-count limits without batches.
	// PostgreSQL 16 §9.16 and SQLite JSON1 §4.23; same functions as risk_stats.go.
	// https://www.postgresql.org/docs/16/functions-json.html
	// https://www.sqlite.org/json1.html#the_json_each_and_json_tree_table_valued_functions
	payload, err := json.Marshal(ids)
	if err != nil {
		return 0, err
	}
	set := "SELECT value FROM json_each($3)"
	if e.postgres {
		set = "SELECT json_array_elements_text($3::json)"
	}
	deleted, err := tx.ExecContext(ctx, "DELETE FROM records WHERE tenant_id=$1 AND kind=$2 AND id IN ("+set+")", eventTenant(), kind, string(payload))
	if err != nil {
		return 0, fmt.Errorf("delete expired retention rows: %w", err)
	}
	count, err := deleted.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count retention deletions: %w", err)
	}
	return count, nil
}
