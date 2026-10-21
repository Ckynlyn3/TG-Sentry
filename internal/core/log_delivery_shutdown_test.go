package core

import (
	"aegishook/internal/teststore"
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

func TestLogDeliveryBlockedDatabaseShutdownReplay(t *testing.T) {
	for _, operation := range []string{"acquire-read", "acquire-ack", "acquire-status", "locked-ack"} {
		t.Run(operation, func(t *testing.T) {
			dir := teststore.Dir(t, t.TempDir())
			e, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			// Isolate delivery shutdown from the unrelated periodic sweep.
			close(e.stop)
			e.workers.Wait()
			e.stop = make(chan struct{})
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			e.syslog = &syslogConfig{address: listener.Addr().String(), transport: "tcp", facility: 16}
			if err := e.Register(Instance{ID: "instance", SessionID: "session", Cwd: t.TempDir(), HookVersion: Version}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err != nil {
				t.Fatal(err)
			}
			batch, err := e.pendingLogDeliveries(context.Background(), e.syslog.destination())
			if err != nil || len(batch) == 0 {
				t.Fatal("missing durable event", err)
			}
			row := batch[0]
			for _, other := range batch[1:] {
				if err := e.ackLogDelivery(context.Background(), other.ID, other.Destination); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			e.deliveryCancel = cancel
			defer cancel()
			var release func()
			if operation == "locked-ack" {
				release = blockLogDeliveryAck(t, e, row.ID)
			} else {
				conn, err := e.DB.Conn(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				release = func() {
					if err := conn.Close(); err != nil {
						t.Error(err)
					}
				}
			}
			defer func() {
				if release != nil {
					release()
				}
			}()
			before := e.DB.Stats().WaitCount
			result := make(chan error, 1)
			e.workers.Add(1)
			go func() {
				defer e.workers.Done()
				var err error
				switch operation {
				case "acquire-read":
					_, err = e.pendingLogDeliveries(ctx, row.Destination)
				case "acquire-status":
					_, err = e.LogDeliveryStatus(ctx)
				default:
					err = e.ackLogDelivery(ctx, row.ID, row.Destination)
				}
				result <- err
			}()
			waitCtx, stop := context.WithTimeout(context.Background(), logDeliveryIOBudget)
			defer stop()
			for {
				blocked := e.DB.Stats().WaitCount > before
				if operation == "locked-ack" {
					if e.postgres {
						// Owner observer: this exact test schema's DELETE is waiting on
						// our row lock, not an inferred timing-based sleep.
						err = teststore.Admin(t, e.DB).QueryRowContext(waitCtx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='tg_sentry_app' AND wait_event_type='Lock' AND query LIKE 'DELETE FROM records%' AND pid IN (SELECT pid FROM pg_locks WHERE relation='records'::regclass))`).Scan(&blocked)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						blocked = sqliteLogDeliveryAckBlocked(t)
					}
				}
				if blocked {
					t.Logf("%s blocking fixture observed postgres=%t", operation, e.postgres)
					break
				}
				select {
				case err := <-result:
					t.Fatalf("database operation did not block: %v", err)
				case <-waitCtx.Done():
					t.Fatal("blocking fixture not exercised")
				default:
				}
			}
			closed := make(chan error, 1)
			started := time.Now()
			go func() { closed <- e.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Error(err)
				}
			case <-waitCtx.Done():
				// Release only our fixture, so the RED failure cannot strand a
				// goroutine/container or lock. This is not a passing shutdown.
				t.Error("Close did not cancel blocked database operation")
				release()
				release = nil
				if err := <-closed; err != nil {
					t.Error(err)
				}
				return
			}
			t.Logf("%s shutdown=%s postgres=%t", operation, time.Since(started), e.postgres)
			if err := <-result; err == nil {
				t.Fatal("cancelled database work succeeded")
			}
			if operation == "locked-ack" && e.DB.Stats().InUse != 0 {
				t.Fatal("worker cleanup outlived database close")
			}
			release()
			release = nil
			// The cancelled acknowledgement must roll back, and the next process
			// must be able to reopen immediately and replay the original event.
			t.Setenv("TG_SENTRY_SYSLOG_ADDRESS", e.syslog.address)
			t.Setenv("TG_SENTRY_SYSLOG_TRANSPORT", "tcp")
			t.Setenv("TG_SENTRY_SYSLOG_FACILITY", "16")
			received := make(chan []byte, 1)
			errs := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					errs <- err
					return
				}
				defer conn.Close()
				msg, err := readSyslogFrame(bufio.NewReader(conn))
				if err != nil {
					errs <- err
					return
				}
				received <- msg
			}()
			next, err := Open(dir)
			if err != nil {
				t.Fatal("reopen after cancelled transaction", err)
			}
			defer next.Close()
			replayCtx, done := context.WithTimeout(context.Background(), logDeliveryIOBudget)
			defer done()
			select {
			case msg := <-received:
				if !bytes.HasSuffix(msg, row.Event) {
					t.Fatal("restart changed pending occurrence")
				}
			case err := <-errs:
				t.Fatal(err)
			case <-replayCtx.Done():
				t.Fatal("cancelled work was lost, not replayed")
			}
			waitLogStatus(t, next, func(s LogDeliveryStatus) bool { return s.Pending == 0 })
		})
	}
}

// Observe the real pinned SQLite driver's busy handler on the acknowledgement
// stack, not merely a borrowed connection or an elapsed sleep. Debug=2 is the
// documented goroutine-stack form: https://pkg.go.dev/runtime/pprof#Profile.WriteTo.
func sqliteLogDeliveryAckBlocked(t *testing.T) bool {
	t.Helper()
	var stacks bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&stacks, 2); err != nil {
		t.Fatal(err)
	}
	for _, stack := range strings.Split(stacks.String(), "\n\n") {
		if strings.Contains(stack, "(*Engine).ackLogDelivery") && strings.Contains(stack, "_sqliteDefaultBusyCallback") {
			return true
		}
	}
	return false
}

func blockLogDeliveryAck(t *testing.T, e *Engine, id string) func() {
	t.Helper()
	if e.postgres {
		owner := teststore.Admin(t, e.DB)
		tx, err := owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec("SELECT id FROM records WHERE tenant_id=$1 AND kind=$2 AND id=$3 FOR UPDATE", eventTenant(), logDeliveryKind, id); err != nil {
			t.Fatal(err)
		}
		return func() {
			if err := tx.Rollback(); err != nil {
				t.Error(err)
			}
		}
	}
	// SQLite's existing WAL allows reads, but a second writer blocks DELETE.
	// Keep its lock until Close returns; rollback only our external fixture.
	db, err := sql.Open("sqlite", filepath.Join(e.Dir, "aegishook.db"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := tx.Exec("UPDATE records SET payload=payload WHERE tenant_id=$1 AND kind=$2 AND id=$3", eventTenant(), logDeliveryKind, id); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatal(err)
	}
	return func() {
		if err := tx.Rollback(); err != nil {
			t.Error(err)
		}
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}
}
