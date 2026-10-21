package core

import (
	"aegishook/internal/teststore"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func logDeliveryTrigger(t *testing.T, e *Engine, operation, kind string) func() {
	t.Helper()
	admin := teststore.Admin(t, e.DB)
	name := "fail_log_" + strings.ToLower(operation)
	var create, drop string
	if e.postgres {
		create = "CREATE FUNCTION " + name + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.kind='" + kind + "' THEN RAISE EXCEPTION 'injected'; END IF; RETURN OLD; END $$; CREATE TRIGGER " + name + " BEFORE " + operation + " ON records FOR EACH ROW EXECUTE FUNCTION " + name + "()"
		drop = "DROP TRIGGER " + name + " ON records; DROP FUNCTION " + name + "()"
	} else {
		create = "CREATE TRIGGER " + name + " BEFORE " + operation + " ON records WHEN OLD.kind='" + kind + "' BEGIN SELECT RAISE(ABORT,'injected'); END"
		drop = "DROP TRIGGER " + name
	}
	if _, err := admin.Exec(create); err != nil {
		t.Fatal(err)
	}
	return func() {
		if _, err := admin.Exec(drop); err != nil {
			t.Error(err)
		}
	}
}

func TestLogDeliveryAckFailureReplaysSameOccurrenceAndPreservesNotify(t *testing.T) {
	e := engine(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	e.syslog = &syslogConfig{address: listener.Addr().String(), transport: "tcp", facility: 16}
	notifications := 0
	e.Notify = func() { notifications++ }
	if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err != nil {
		t.Fatal(err)
	}
	if notifications != 1 {
		t.Fatal("existing Notify callback was not preserved")
	}
	batch, err := e.pendingLogDeliveries(context.Background(), e.syslog.destination())
	if err != nil || len(batch) == 0 {
		t.Fatal(err)
	}
	// Limit this deterministic failure fixture to one occurrence.
	for _, row := range batch[1:] {
		if err := e.ackLogDelivery(context.Background(), row.ID, row.Destination); err != nil {
			t.Fatal(err)
		}
	}
	received := make(chan []byte, 2)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for range 2 {
			msg, err := readSyslogFrame(r)
			if err != nil {
				return
			}
			received <- msg
		}
	}()
	clear := logDeliveryTrigger(t, e, "DELETE", logDeliveryKind)
	sender := syslogSender{config: *e.syslog}
	defer sender.close()
	ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
	defer cancel()
	if err := e.drainLogDeliveries(ctx, &sender); err == nil {
		t.Fatal("ack failure silently accepted")
	}
	left, err := e.pendingLogDeliveries(ctx, e.syslog.destination())
	if err != nil || len(left) != 1 || !bytes.Equal(left[0].Event, batch[0].Event) {
		t.Fatal("ack failure lost retryability")
	}
	clear()
	if err := e.drainLogDeliveries(ctx, &sender); err != nil {
		t.Fatal(err)
	}
	var first []byte
	for range 2 {
		select {
		case msg := <-received:
			if first == nil {
				first = msg
			} else if !bytes.Equal(msg, first) {
				t.Fatal("uncertain ack changed replayed occurrence")
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	status, err := e.LogDeliveryStatus(ctx)
	if err != nil || status.Pending != 0 {
		t.Fatal("successful retry not acknowledged")
	}
}

func TestLogDeliveryTenantAndLowSortingIDs(t *testing.T) {
	e := engine(t)
	cfg := syslogConfig{address: "localhost:6514", transport: "tcp", facility: 16}
	raw := json.RawMessage(`{"type":"ok","time":"2026-10-20T00:00:00Z","data":{"metadata":{"tenant_uid":"attacker"}}}`)
	row := pendingLogDelivery{ID: "zz-first", Destination: cfg.destination(), Address: cfg.address, Transport: cfg.transport, CreatedAt: time.Now().UTC(), Event: raw}
	if err := e.put(logDeliveryKind, row.ID, row); err != nil {
		t.Fatal(err)
	}
	batch, err := e.pendingLogDeliveries(context.Background(), cfg.destination())
	if err != nil || len(batch) != 1 {
		t.Fatal(err)
	}
	row.ID = "00-late-low"
	if err := e.put(logDeliveryKind, row.ID, row); err != nil {
		t.Fatal(err)
	}
	foreign := row
	foreign.ID = "foreign"
	b, _ := json.Marshal(foreign)
	if _, err := teststore.Admin(t, e.DB).Exec(insertRecord, "other", logDeliveryKind, foreign.ID, string(b)); err != nil {
		t.Fatal(err)
	}
	batch, err = e.pendingLogDeliveries(context.Background(), cfg.destination())
	if err != nil || len(batch) != 2 || batch[0].ID != "00-late-low" {
		t.Fatal("tenant claim or low-sorting ID altered traversal")
	}
	if err := e.ackLogDelivery(context.Background(), foreign.ID, cfg.destination()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := teststore.Admin(t, e.DB).QueryRow("SELECT COUNT(*) FROM records WHERE tenant_id='other' AND kind=$1", logDeliveryKind).Scan(&count); err != nil || count != 1 {
		t.Fatal("ack crossed tenant")
	}
}

func TestLogDeliveryDisabledPreservesBacklogAndNoCredentialBytes(t *testing.T) {
	pki := newSyslogTestPKI(t)
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadSyslogConfig(syslogEnv(map[string]string{"ADDRESS": "localhost", "FACILITY": "16", "CA_FILE": pki.caFile, "CERT_FILE": pki.certFile, "KEY_FILE": pki.keyFile}))
	if err != nil {
		t.Fatal(err)
	}
	e.syslog = cfg // Store-only fixture; no network worker.
	instance := Instance{ID: "instance", SessionID: "session", Cwd: t.TempDir(), HookVersion: Version}
	if err := e.Register(instance); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(pki.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := e.beginTenant()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query("SELECT payload FROM records WHERE tenant_id=$1", eventTenant())
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(payload, key) || bytes.Contains(payload, []byte("PRIVATE KEY")) || bytes.Contains(payload, []byte(pki.keyFile)) || bytes.Contains(payload, []byte(pki.certFile)) {
			t.Fatal("credential bytes or secret file paths persisted")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	tx.Rollback()
	status, err := e.LogDeliveryStatus(context.Background())
	if err != nil || status.Pending == 0 {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	after, err := e.LogDeliveryStatus(context.Background())
	if err != nil || after.Pending != status.Pending || after.Held != after.Pending {
		t.Fatal("disabled sink erased backlog")
	}
	if err := e.Register(instance); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err != nil {
		t.Fatal(err)
	}
	after, err = e.LogDeliveryStatus(context.Background())
	if err != nil || after.Pending != status.Pending {
		t.Fatal("disabled sink queued new work")
	}
}

func TestLogDeliveryWorkerReleasesDatabaseAndJoinsOnClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("TG_SENTRY_SYSLOG_ADDRESS", listener.Addr().String())
	t.Setenv("TG_SENTRY_SYSLOG_TRANSPORT", "tls")
	t.Setenv("TG_SENTRY_SYSLOG_FACILITY", "16")
	e := engine(t)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			accepted <- c
		}
	}() // Accept TCP but stall TLS handshake.
	if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
	defer cancel()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd bob"})); err != nil {
		t.Fatal("network held single database connection", err)
	}
	status, err := e.LogDeliveryStatus(ctx)
	if err != nil || status.Pending == 0 {
		t.Fatal("stalled TLS lost work")
	}
	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("workers failed to join before database close")
	}
}

func TestLogDeliveryCorruptRecordsAndStoreFailuresStayBlocked(t *testing.T) {
	e := engine(t)
	cfg := syslogConfig{address: "localhost:6514", transport: "tcp", facility: 16}
	row := pendingLogDelivery{ID: "broken", Destination: cfg.destination(), Address: "wrong", CreatedAt: time.Now(), Event: []byte(`{"type":"ok","time":"2026-10-20T00:00:00Z"}`)}
	if err := e.put(logDeliveryKind, row.ID, row); err != nil {
		t.Fatal(err)
	}
	sender := syslogSender{config: cfg}
	if err := e.drainLogDeliveries(context.Background(), &sender); err == nil {
		t.Fatal("route mismatch sent")
	}
	if err := e.get(logDeliveryKind, row.ID, &row); err != nil {
		t.Fatal("blocked data lost")
	}
	if _, err := e.LogDeliveryStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := []byte(`{"destination":"` + cfg.destination() + `","id":"wrong"}`)
	if _, err := teststore.Admin(t, e.DB).Exec(upsertRecord, eventTenant(), logDeliveryKind, row.ID, string(b)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pendingLogDeliveries(context.Background(), cfg.destination()); err == nil {
		t.Fatal("corrupt identity accepted")
	}
	e.Close()
	if _, err := e.pendingLogDeliveries(context.Background(), cfg.destination()); err == nil {
		t.Fatal("closed store accepted read")
	}
	if err := e.ackLogDelivery(context.Background(), row.ID, cfg.destination()); err == nil {
		t.Fatal("closed store accepted ack")
	}
	if _, err := e.LogDeliveryStatus(context.Background()); err == nil {
		t.Fatal("closed store accepted status")
	}
}
