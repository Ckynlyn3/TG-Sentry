package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// EventExportFilter uses the risk-list predicates and inclusive event times.
type EventExportFilter struct {
	RiskEventFilter
	Start, End time.Time
}

// eventExportBatchSize reuses the existing ReviewsPage/RiskEvents page ceiling.
const eventExportBatchSize = 100

type eventExportRow struct {
	id      string
	payload []byte
}

// eventExportBatch owns export SQL so the tenant transaction can evolve in one
// place. Release the single store connection before writing to a slow client.
func (e *Engine) eventExportBatch(ctx context.Context, after, upper string) ([]eventExportRow, string, error) {
	tx, err := e.beginTenantTx(ctx, &sql.TxOptions{ReadOnly: true}) // RLS tenant context (#11).
	if err != nil {
		return nil, upper, fmt.Errorf("begin event export: %w", err)
	}
	defer tx.Rollback()
	if upper == "" {
		if err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),'') FROM records WHERE tenant_id='default' AND kind='audit'").Scan(&upper); err != nil {
			return nil, upper, fmt.Errorf("bound event export: %w", err)
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,payload FROM records WHERE tenant_id='default' AND kind='audit' AND id>$1 AND id<=$2 ORDER BY id LIMIT $3", after, upper, eventExportBatchSize)
	if err != nil {
		return nil, upper, fmt.Errorf("query event export: %w", err)
	}
	defer rows.Close()
	batch := make([]eventExportRow, 0, eventExportBatchSize)
	for rows.Next() {
		var row eventExportRow
		if err = rows.Scan(&row.id, &row.payload); err != nil {
			return nil, upper, fmt.Errorf("scan event export: %w", err)
		}
		batch = append(batch, row)
	}
	if err = rows.Err(); err != nil {
		return nil, upper, fmt.Errorf("read event export: %w", err)
	}
	if err = rows.Close(); err != nil {
		return nil, upper, fmt.Errorf("close event export: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, upper, fmt.Errorf("commit event export: %w", err)
	}
	return batch, upper, nil
}

// StreamEvents reads bounded keyset batches of existing audit rows. Raw event
// objects preserve unknown OCSF/CloudEvents fields and exact JSON numbers.
// ponytail: filters scan M1 audit JSON; #11's typed projection can index them.
// An upper ID bounds traversal, not a point-in-time snapshot of concurrent writes.
func (e *Engine) StreamEvents(ctx context.Context, eventType string, filter EventExportFilter, visit func(json.RawMessage) error) error {
	if !validRiskFilter(filter.RiskEventFilter) || (!filter.Start.IsZero() && !filter.End.IsZero() && filter.Start.After(filter.End)) || !hasExact(eventType, "tg.sentry.risk.v1", "tg.sentry.audit.v1") {
		return ErrRiskEventQuery
	}
	after, upper := "", ""
	for {
		batch, bound, err := e.eventExportBatch(ctx, after, upper)
		if err != nil {
			return err
		}
		upper = bound
		for _, row := range batch {
			var audit struct {
				Events []json.RawMessage `json:"events"`
			}
			if err = json.Unmarshal(row.payload, &audit); err != nil {
				return fmt.Errorf("decode event export row: %w", err)
			}
			for _, raw := range audit.Events {
				if err = ctx.Err(); err != nil {
					return err
				}
				var event Event
				if err = json.Unmarshal(raw, &event); err != nil {
					return fmt.Errorf("decode event export: %w", err)
				}
				if event.Type != eventType || !riskEventMatches(event, filter.RiskEventFilter) || (!filter.Start.IsZero() && event.Time.Before(filter.Start)) || (!filter.End.IsZero() && event.Time.After(filter.End)) {
					continue
				}
				if err = visit(raw); err != nil {
					return fmt.Errorf("write event export: %w", err)
				}
			}
			after = row.id
		}
		if len(batch) < eventExportBatchSize {
			return nil
		}
	}
}
