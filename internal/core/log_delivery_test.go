package core

import (
	"aegishook/internal/teststore"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLogDeliveryDisabledAndIndependentAcks(t *testing.T) {
	e := engine(t)
	if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err != nil {
		t.Fatal(err)
	}
	status, err := e.LogDeliveryStatus(context.Background())
	if err != nil || status.Pending != 0 {
		t.Fatalf("disabled queued work: %+v %v", status, err)
	}
	// Decision-complete store fixture: no network worker; insert two routing identities.
	e.syslog = &syslogConfig{address: "localhost:6514", transport: "tls", facility: 16}
	r, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"}))
	if err != nil {
		t.Fatal(err)
	}
	batch, err := e.pendingLogDeliveries(context.Background(), e.syslog.destination())
	if err != nil || len(batch) == 0 {
		t.Fatalf("missing pending deliveries: %v", err)
	}
	for _, row := range batch {
		var event Event
		if json.Unmarshal(row.Event, &event) != nil || event.Data.Metadata.TenantUID != eventTenant() {
			t.Fatal("tenant not server-bound")
		}
		if strings.Contains(string(row.Event), "passwd alice") {
			t.Fatal("raw content queued")
		}
	}
	other := batch[0]
	other.ID, other.Destination = "000-low-sorting", "other-destination"
	if err := e.put(logDeliveryKind, other.ID, other); err != nil {
		t.Fatal(err)
	}
	if err := e.ackLogDelivery(context.Background(), other.ID, e.syslog.destination()); err != nil {
		t.Fatal(err)
	}
	if err := e.get(logDeliveryKind, other.ID, &other); err != nil {
		t.Fatal("wrong destination ack deleted work")
	}
	if err := e.ackLogDelivery(context.Background(), batch[0].ID, e.syslog.destination()); err != nil {
		t.Fatal(err)
	}
	if err := e.get(logDeliveryKind, batch[0].ID, &other); err == nil {
		t.Fatal("ack did not remove successful destination")
	}
	if _, err := e.Reviews(); err != nil || r.ID == "" {
		t.Fatal("delivery interfered with review")
	}
}

func TestLogDeliveryRollbackTogether(t *testing.T) {
	e := engine(t)
	e.syslog = &syslogConfig{address: "localhost:6514", transport: "tls", facility: 16}
	admin := teststore.Admin(t, e.DB)
	var fail, clear string
	if e.postgres {
		fail = `CREATE FUNCTION fail_delivery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='log_delivery' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_delivery BEFORE INSERT ON records FOR EACH ROW EXECUTE FUNCTION fail_delivery()`
		clear = `DROP TRIGGER fail_delivery ON records; DROP FUNCTION fail_delivery()`
	} else {
		fail = `CREATE TRIGGER fail_delivery BEFORE INSERT ON records WHEN NEW.kind='log_delivery' BEGIN SELECT RAISE(ABORT,'injected'); END`
		clear = `DROP TRIGGER fail_delivery`
	}
	if _, err := admin.Exec(fail); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(clear); err != nil {
			t.Error(err)
		}
	})
	before, _ := e.Audits()
	if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err == nil {
		t.Fatal("outbox failure did not fail business transaction")
	}
	reviews, err := e.Reviews()
	if err != nil || len(reviews) != 0 {
		t.Fatal("review escaped rollback")
	}
	after, err := e.Audits()
	if err != nil || len(before) != len(after) {
		t.Fatal("audit escaped rollback")
	}
	status, err := e.LogDeliveryStatus(context.Background())
	if err != nil || status.Pending != 0 {
		t.Fatal("pending delivery escaped rollback")
	}
}

func TestLogDeliveryRestartReplayAndChangedRoute(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close() // Queue while receiver is down.
	t.Setenv("TG_SENTRY_SYSLOG_ADDRESS", address)
	t.Setenv("TG_SENTRY_SYSLOG_TRANSPORT", "tcp")
	t.Setenv("TG_SENTRY_SYSLOG_FACILITY", "16")
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Register(Instance{ID: "instance", SessionID: "session", Cwd: t.TempDir(), HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err != nil {
		t.Fatal(err)
	}
	batch, err := e.pendingLogDeliveries(context.Background(), e.syslog.destination())
	if err != nil || len(batch) == 0 {
		t.Fatal("outage lost pending work")
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	// A changed route holds, never redirects, existing backlog.
	t.Setenv("TG_SENTRY_SYSLOG_FACILITY", "17")
	e, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	status, err := e.LogDeliveryStatus(context.Background())
	if err != nil || status.Held != int64(len(batch)) {
		t.Fatalf("changed route: %+v %v", status, err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TG_SENTRY_SYSLOG_FACILITY", "16")
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, len(batch))
	errs := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for range batch {
			msg, err := readSyslogFrame(reader)
			if err != nil {
				errs <- err
				return
			}
			received <- msg
		}
	}()
	e, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
	defer cancel()
	schemas := pinnedEventSchemas(t)
	for _, row := range batch {
		select {
		case msg := <-received:
			start := bytes.Index(msg, []byte("\xef\xbb\xbf"))
			if start < 0 || !bytes.Equal(msg[start+3:], row.Event) {
				t.Fatal("restart changed occurrence payload")
			}
			var wire map[string]any
			if err := json.Unmarshal(msg[start+3:], &wire); err != nil {
				t.Fatal(err)
			}
			if err := validateEventWire(schemas, wire); err != nil {
				t.Fatal(err)
			}
		case err := <-errs:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// Worker may be just after its socket write; wait on status, not sleeps.
	waitLogStatus(t, e, func(s LogDeliveryStatus) bool { return s.Pending == 0 })
}

func waitLogStatus(t *testing.T, e *Engine, match func(LogDeliveryStatus) bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
	defer cancel()
	// Existing sweep cadence; notifications are latency hints, never durability.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		status, err := e.LogDeliveryStatus(ctx)
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if err == nil && match(status) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("delivery status timed out: %+v", status)
		case <-ticker.C:
		}
	}
}
