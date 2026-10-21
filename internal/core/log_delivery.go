package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/sethvargo/go-retry"
)

const logDeliveryKind = "log_delivery"

type pendingLogDelivery struct {
	ID          string          `json:"id"`
	Destination string          `json:"destination"`
	Address     string          `json:"address"`
	Transport   string          `json:"transport"`
	Facility    int             `json:"facility"`
	Topic       string          `json:"topic,omitempty"`
	CreatedAt   time.Time       `json:"createdAt"`
	Event       json.RawMessage `json:"event"`
}

// Transactional outbox, https://microservices.io/patterns/data/transactional-outbox.html.
// No credentials or review bodies: reuse the exact event bytes embedded in audit.
func (e *Engine) queueLogDeliveries(tx *sql.Tx, audit []byte) error {
	if e.syslog == nil && e.kafka == nil {
		return nil
	}
	var stored struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(audit, &stored); err != nil {
		return err
	}
	for _, raw := range stored.Events {
		if e.syslog != nil {
			row := pendingLogDelivery{ID: ID(), Destination: e.syslog.destination(), Address: e.syslog.address, Transport: e.syslog.transport, Facility: e.syslog.facility, CreatedAt: e.clock().UTC(), Event: raw}
			if err := e.insertLogDelivery(tx, row); err != nil {
				return err
			}
		}
		if e.kafka != nil {
			topic, err := e.kafka.topic(raw)
			if err != nil {
				return err
			}
			row := pendingLogDelivery{ID: ID(), Destination: e.kafka.destination(), Address: e.kafka.address(), Transport: "kafka-tls", Topic: topic, CreatedAt: e.clock().UTC(), Event: raw}
			if err := e.insertLogDelivery(tx, row); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Engine) insertLogDelivery(tx *sql.Tx, row pendingLogDelivery) error {
	b, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(insertRecord, eventTenant(), logDeliveryKind, row.ID, string(b)); err != nil {
		return errors.New("cannot queue log delivery")
	}
	return nil
}

// beginLogDeliveryTx retains cancellation during acquisition and SQL. Conn.Close
// waits for the Tx's automatic rollback before the worker can join and DB.Close.
// https://pkg.go.dev/database/sql#Conn.BeginTx and #Conn.Close.
func (e *Engine) beginLogDeliveryTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, *sql.Conn, error) {
	conn, err := e.DB.Conn(ctx)
	if err != nil {
		return nil, nil, err
	}
	tx, err := conn.BeginTx(ctx, opts)
	if err != nil {
		return nil, nil, errors.Join(err, conn.Close())
	}
	// Same transaction-local RLS binding as beginTenantTx; never payload-derived.
	if e.postgres {
		if _, err = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", eventTenant()); err != nil {
			return nil, nil, errors.Join(err, tx.Rollback(), conn.Close())
		}
	}
	return tx, conn, nil
}

// No tail cursor: every batch scans current pending keys, including low-sorting
// new IDs. Release the single tenant connection before dialing or writing.
func (e *Engine) pendingLogDeliveries(ctx context.Context, destination string) ([]pendingLogDelivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, conn, err := e.beginLogDeliveryTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errors.New("cannot begin log delivery read")
	}
	defer conn.Close() // Barrier follows rollback (including automatic rollback).
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id,payload FROM records WHERE tenant_id=$1 AND kind=$2 AND "+e.jsonField("", "destination")+"=$3 ORDER BY id LIMIT $4", eventTenant(), logDeliveryKind, destination, eventExportBatchSize)
	if err != nil {
		return nil, errors.New("cannot query log delivery")
	}
	defer rows.Close()
	batch := make([]pendingLogDelivery, 0, eventExportBatchSize)
	for rows.Next() {
		var id string
		var b []byte
		var row pendingLogDelivery
		if rows.Scan(&id, &b) != nil || json.Unmarshal(b, &row) != nil || row.ID != id || row.Destination != destination {
			return nil, errors.New("invalid pending log delivery")
		}
		batch = append(batch, row)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, errors.New("cannot read log delivery rows")
	}
	if err = tx.Commit(); err != nil {
		return nil, errors.New("cannot release log delivery read")
	}
	return batch, nil
}

func (e *Engine) ackLogDelivery(ctx context.Context, id, destination string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, conn, err := e.beginLogDeliveryTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin log delivery acknowledgement")
	}
	defer conn.Close()
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM records WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND "+e.jsonField("", "destination")+"=$4", eventTenant(), logDeliveryKind, id, destination); err != nil {
		return errors.New("cannot acknowledge log delivery")
	}
	if err = tx.Commit(); err != nil {
		return errors.New("cannot commit log delivery acknowledgement")
	}
	return nil
}

// LogDeliveryStatus describes local durable work only, never remote receipt.
// Pending includes held routes and disabled-sink backlog; no disk cap/TTL is claimed.
type LogDeliveryStatus struct {
	Pending int64
	Held    int64
	Oldest  time.Time
}

func (e *Engine) LogDeliveryStatus(ctx context.Context) (LogDeliveryStatus, error) {
	if err := ctx.Err(); err != nil {
		return LogDeliveryStatus{}, err
	}
	tx, conn, err := e.beginLogDeliveryTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return LogDeliveryStatus{}, errors.New("cannot read log delivery status")
	}
	defer conn.Close()
	defer tx.Rollback()
	destination := ""
	if e.syslog != nil {
		destination = e.syslog.destination()
	}
	kafkaDestination := ""
	if e.kafka != nil {
		kafkaDestination = e.kafka.destination()
	}
	var status LogDeliveryStatus
	var oldest sql.NullString
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN "+e.jsonField("", "destination")+" IN ($3,$4) THEN 0 ELSE 1 END),0),MIN("+e.jsonField("", "createdAt")+") FROM records WHERE tenant_id=$1 AND kind=$2", eventTenant(), logDeliveryKind, destination, kafkaDestination).Scan(&status.Pending, &status.Held, &oldest)
	if err != nil {
		return status, errors.New("cannot query log delivery status")
	}
	if oldest.Valid {
		status.Oldest, err = time.Parse(time.RFC3339Nano, oldest.String)
		if err != nil {
			return status, errors.New("invalid log delivery age")
		}
	}
	if err = tx.Commit(); err != nil {
		return status, errors.New("cannot release log delivery status read")
	}
	return status, nil
}

func logDeliveryBackoff() retry.Backoff {
	// Reuse go-retry, with franz-go v1.22.2 RetryBackoffFn's 250 ms,
	// +/-20% jitter and 5 s cap (plan §4); no retry cutoff or event TTL.
	return retry.WithCappedDuration(5*time.Second, retry.WithJitterPercent(20, retry.NewExponential(250*time.Millisecond)))
}

func (e *Engine) logDeliveryLoop(ctx context.Context) {
	defer e.workers.Done()
	sender := syslogSender{config: *e.syslog}
	defer sender.close()
	for ctx.Err() == nil {
		err := retry.Do(ctx, logDeliveryBackoff(), func(ctx context.Context) error {
			err := e.drainLogDeliveries(ctx, &sender)
			if err != nil && ctx.Err() == nil {
				status, statusErr := e.LogDeliveryStatus(ctx)
				log.Printf("syslog delivery blocked: %v; pending=%d held=%d oldest=%s status_error=%v", err, status.Pending, status.Held, status.Oldest.Format(time.RFC3339Nano), statusErr)
				return retry.RetryableError(err)
			}
			return err
		})
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-e.deliveryWake:
		}
	}
}

func (e *Engine) drainLogDeliveries(ctx context.Context, sender *syslogSender) error {
	for {
		batch, err := e.pendingLogDeliveries(ctx, sender.config.destination())
		if err != nil {
			return err
		}
		for _, row := range batch {
			if row.Address != sender.config.address || row.Transport != sender.config.transport || row.Facility != sender.config.facility {
				return errors.New("pending log route mismatch")
			}
			if err = sender.send(ctx, row.Event); err != nil {
				return err
			}
			if err = e.ackLogDelivery(ctx, row.ID, row.Destination); err != nil {
				return err
			}
		}
		if len(batch) < eventExportBatchSize {
			return nil
		}
	}
}
