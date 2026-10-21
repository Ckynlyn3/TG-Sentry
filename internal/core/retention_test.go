package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"aegishook/internal/teststore"
)

func TestRetentionPolicyEnvironment(t *testing.T) {
	for _, name := range []string{"TG_SENTRY_EVENTS_RETENTION_DAYS", "TG_SENTRY_AUDIT_RETENTION_DAYS"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	p, err := LoadRetentionPolicy()
	if err != nil || p != (RetentionPolicy{EventsDays: 180, AuditDays: 180}) {
		t.Fatal(p, err)
	}
	for _, name := range []string{"TG_SENTRY_EVENTS_RETENTION_DAYS", "TG_SENTRY_AUDIT_RETENTION_DAYS"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "30")
			p, err := LoadRetentionPolicy()
			want := RetentionPolicy{EventsDays: 180, AuditDays: 180}
			if name == "TG_SENTRY_EVENTS_RETENTION_DAYS" {
				want.EventsDays = 30
			} else {
				want.AuditDays = 30
			}
			if err != nil || p != want {
				t.Fatal(p, err)
			}
			for _, value := range []string{"", "0", "-1", "+1", "1.5", " 30", "30 ", "bad", "9223372036854775808", strconv.FormatInt(int64(time.Duration(1<<63-1)/(24*time.Hour))+1, 10)} {
				t.Setenv(name, value)
				if _, err := LoadRetentionPolicy(); err == nil {
					t.Fatalf("accepted %s=%q", name, value)
				}
			}
		})
	}
}

func retentionEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case <-e.stop: // Restart tests already closed this engine.
		default:
			e.Close()
		}
	})
	return e, dir
}

func retentionAudits(t *testing.T, e *Engine, action string) []Audit {
	t.Helper()
	all, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	var result []Audit
	for _, a := range all {
		if a.Action == action {
			result = append(result, a)
		}
	}
	return result
}

func TestRetentionAdoptionAtomicAndRestartNoop(t *testing.T) {
	e, dir := retentionEngine(t)
	ctx := WithActor(context.Background(), Actor{Kind: "human", Subject: "not-the-operator"})
	policy := RetentionPolicy{EventsDays: 30, AuditDays: 180}
	if err := e.AdoptRetentionPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	var stored RetentionPolicy
	if err := e.get("retention", "current", &stored); err != nil || stored != policy {
		t.Fatal(stored, err)
	}
	audits := retentionAudits(t, e, "retention.config")
	if len(audits) != 1 || audits[0].Actor != SystemActor("retention-config") {
		t.Fatal(audits)
	}
	if !strings.Contains(audits[0].Detail, `"eventsDays":30`) {
		t.Fatal(audits[0].Detail)
	}
	if err := e.AdoptRetentionPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if len(retentionAudits(t, e, "retention.config")) != 1 {
		t.Fatal("unchanged adoption audited")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.AdoptRetentionPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if len(retentionAudits(t, reopened, "retention.config")) != 1 {
		t.Fatal("unchanged restart audited")
	}
	rejectAudit(t, reopened)
	if err := reopened.AdoptRetentionPolicy(ctx, RetentionPolicy{EventsDays: 1, AuditDays: 1}); err == nil {
		t.Fatal("audit failure ignored")
	}
	if err := reopened.get("retention", "current", &stored); err != nil || stored != policy {
		t.Fatal("failed adoption changed policy", stored, err)
	}
	if err := reopened.AdoptRetentionPolicy(ctx, RetentionPolicy{}); err == nil {
		t.Fatal("invalid direct policy accepted")
	}
}

func TestRetentionInitialAdoptionRollback(t *testing.T) {
	e, _ := retentionEngine(t)
	rejectAudit(t, e)
	if err := e.AdoptRetentionPolicy(context.Background(), RetentionPolicy{EventsDays: 180, AuditDays: 180}); err == nil {
		t.Fatal("audit failure ignored")
	}
	var p RetentionPolicy
	if err := e.get("retention", "current", &p); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("failed initial policy persisted", err)
	}
}

func TestRetentionPurgeCategoriesBoundaryIsolationAndDurability(t *testing.T) {
	e, dir := retentionEngine(t)
	ctx := context.Background()
	policy := RetentionPolicy{EventsDays: 30, AuditDays: 180}
	if err := e.AdoptRetentionPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 123456789, time.UTC)
	eventCutoff, auditCutoff := now.Add(-30*24*time.Hour), now.Add(-180*24*time.Hour)
	type fixture struct {
		kind, id, stamp, events string
		deleted                 bool
	}
	fixtures := []fixture{
		{"reviews", "review-old", auditCutoff.Add(-time.Nanosecond).Format(time.RFC3339Nano), "", true},
		{"reviews", "review-boundary", auditCutoff.Format(time.RFC3339Nano), "", false},
		{"reviews", "review-new", auditCutoff.Add(time.Nanosecond).Format(time.RFC3339Nano), "", false},
		{"audit", "standalone-old", auditCutoff.Add(-time.Second).Format(time.RFC3339Nano), "", true},
		{"audit", "empty-events-old", auditCutoff.Add(-time.Second).Format(time.RFC3339Nano), `,"events":[]`, true},
		{"audit", "null-events-old", auditCutoff.Add(-time.Second).Format(time.RFC3339Nano), `,"events":null`, true},
		{"audit", "standalone-younger", eventCutoff.Add(-time.Second).Format(time.RFC3339Nano), "", false},
		{"audit", "mixed-events-old", eventCutoff.Add(-time.Nanosecond).Format(time.RFC3339Nano), `,"events":[{"type":"tg.sentry.risk.v1"},{"type":"tg.sentry.audit.v1"}]`, true},
		{"audit", "event-boundary", eventCutoff.Format(time.RFC3339Nano), `,"events":[{}]`, false},
		{"audit", "event-offset-boundary", eventCutoff.In(time.FixedZone("offset", 8*60*60)).Format(time.RFC3339Nano), `,"events":[{}]`, false},
		{"audit", "event-offset-old", eventCutoff.Add(-time.Nanosecond).In(time.FixedZone("offset", -7*60*60)).Format(time.RFC3339Nano), `,"events":[{}]`, true},
		{"audit", "event-new", eventCutoff.Add(time.Nanosecond).Format(time.RFC3339Nano), `,"events":[{"future_field":"preserve-exactly"}]`, false},
		{"audit", "event-future", now.Add(time.Hour).Format(time.RFC3339Nano), `,"events":[{}]`, false},
		{"audit", "integer-second", eventCutoff.Truncate(time.Second).Format(time.RFC3339Nano), `,"events":[{}]`, true},
		{"audit", "millisecond-new", eventCutoff.Truncate(time.Second).Add(124 * time.Millisecond).Format(time.RFC3339Nano), `,"events":[{}]`, false},
	}
	payloads := map[string]string{}
	for _, f := range fixtures {
		payload := `{"id":"` + f.id + `","createdAt":"` + f.stamp + `","decision":"approve","unknown_field":"exact bytes"` + f.events + `}`
		payloads[f.id] = payload
		if _, err := teststore.Admin(t, e.DB).Exec(insertRecord, eventTenant(), f.kind, f.id, payload); err != nil {
			t.Fatal(err)
		}
	}
	old := auditCutoff.Add(-time.Hour).Format(time.RFC3339Nano)
	for _, kind := range []string{"reviews", "audit", "outbox", "usage", "instances", "protection", "settings", "retention"} {
		tenant := eventTenant()
		if kind == "reviews" || kind == "audit" {
			tenant = "other"
		}
		if _, err := teststore.Admin(t, e.DB).Exec(insertRecord, tenant, kind, "unrelated", `{"createdAt":"`+old+`"}`); err != nil {
			t.Fatal(err)
		}
	}
	notifications := 0
	e.Notify = func() { notifications++ }
	result, err := e.PurgeExpired(ctx, now)
	if err != nil || result.Reviews != 1 || result.EventEnvelopes != 3 || result.AuditEnvelopes != 3 || result.MalformedTimestamps != 0 {
		t.Fatal(result, err)
	}
	if !result.EventsCutoff.Equal(eventCutoff) || !result.AuditCutoff.Equal(auditCutoff) || result.Policy != policy {
		t.Fatal(result)
	}
	if notifications != 1 {
		t.Fatal("missing committed notification", notifications)
	}
	for _, f := range fixtures {
		var payload string
		err := teststore.Admin(t, e.DB).QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind=$2 AND id=$3", eventTenant(), f.kind, f.id).Scan(&payload)
		if f.deleted {
			if !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("expired row survives", f.id, err)
			}
		} else if err != nil || payload != payloads[f.id] {
			t.Fatal("survivor changed", f.id, err)
		}
	}
	var unrelated int
	if err := teststore.Admin(t, e.DB).QueryRow("SELECT count(*) FROM records WHERE id='unrelated'").Scan(&unrelated); err != nil || unrelated != 8 {
		t.Fatal("foreign/unrelated rows changed", unrelated, err)
	}
	audits := retentionAudits(t, e, "retention.purge")
	if len(audits) != 1 || audits[0].Actor != SystemActor("retention") {
		t.Fatal(audits)
	}
	var receipt PurgeResult
	if err := json.Unmarshal([]byte(audits[0].Detail), &receipt); err != nil || !reflect.DeepEqual(receipt, result) {
		t.Fatal(receipt, err)
	}
	for id := range payloads {
		if strings.Contains(audits[0].Detail, id) {
			t.Fatal("purge receipt disclosed id")
		}
	}
	second, err := e.PurgeExpired(ctx, now)
	if err != nil || second.Reviews+second.EventEnvelopes+second.AuditEnvelopes != 0 || len(retentionAudits(t, e, "retention.purge")) != 1 || notifications != 1 {
		t.Fatal("no-op audited/notified", second, err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var review Review
	if err := reopened.get("reviews", "review-old", &review); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("delete not durable", err)
	}
	if len(retentionAudits(t, reopened, "retention.purge")) != 1 {
		t.Fatal("receipt not durable")
	}
}

func TestRetentionPurgeMalformedSurvivesWhileValidExpires(t *testing.T) {
	e, _ := retentionEngine(t)
	ctx := context.Background()
	if err := e.AdoptRetentionPolicy(ctx, RetentionPolicy{EventsDays: 1, AuditDays: 1}); err != nil {
		t.Fatal(err)
	}
	for id, value := range map[string]any{"missing": nil, "bad": "invalid", "invalid-date": "2026-02-30T00:00:00Z", "not-string": 123, "empty": "", "zero": "0001-01-01T00:00:00Z"} {
		payload := map[string]any{"id": id, "decision": "approve"}
		if value != nil {
			payload["createdAt"] = value
		}
		if err := e.put("reviews", id, payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.put("reviews", "valid-old", Review{ID: "valid-old", Decision: "approve", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	result, err := e.PurgeExpired(ctx, now)
	if err != nil || result.Reviews != 1 || result.MalformedTimestamps != 6 {
		t.Fatal(result, err)
	}
	for _, id := range []string{"missing", "bad", "invalid-date", "not-string", "empty", "zero"} {
		var payload map[string]any
		if err := e.get("reviews", id, &payload); err != nil {
			t.Fatal("malformed row removed", id, err)
		}
	}
	result, err = e.PurgeExpired(ctx, now)
	if err != nil || result.Reviews != 0 || result.MalformedTimestamps != 6 || len(retentionAudits(t, e, "retention.purge")) != 1 {
		t.Fatal("malformed no-op added receipt", result, err)
	}
}

func TestRetentionPurgeAuditAndDeleteFailureRollback(t *testing.T) {
	for _, failure := range []string{"audit", "delete"} {
		t.Run(failure, func(t *testing.T) {
			e, _ := retentionEngine(t)
			ctx := context.Background()
			if err := e.AdoptRetentionPolicy(ctx, RetentionPolicy{EventsDays: 1, AuditDays: 1}); err != nil {
				t.Fatal(err)
			}
			old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			if err := e.put("reviews", "old-review", Review{ID: "old-review", Decision: "approve", CreatedAt: old}); err != nil {
				t.Fatal(err)
			}
			if err := e.put("audit", "old-audit", Audit{ID: "old-audit", CreatedAt: old}); err != nil {
				t.Fatal(err)
			}
			if failure == "audit" {
				rejectAudit(t, e)
			} else {
				query := `CREATE TRIGGER reject_delete BEFORE DELETE ON records WHEN OLD.kind='audit' BEGIN SELECT RAISE(ABORT,'delete unavailable'); END;`
				if e.postgres {
					query = `CREATE FUNCTION reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'delete unavailable'; END $$; CREATE TRIGGER reject_delete BEFORE DELETE ON records FOR EACH ROW WHEN (OLD.kind='audit') EXECUTE FUNCTION reject_delete();`
				}
				if _, err := teststore.Admin(t, e.DB).Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			notifications := 0
			e.Notify = func() { notifications++ }
			if result, err := e.PurgeExpired(ctx, old.Add(180*24*time.Hour)); err == nil || result.Reviews+result.AuditEnvelopes+result.EventEnvelopes != 0 {
				t.Fatal("failure not atomic", result, err)
			}
			for _, kind := range []string{"reviews", "audit"} {
				id := "old-review"
				if kind == "audit" {
					id = "old-audit"
				}
				var value map[string]any
				if err := e.get(kind, id, &value); err != nil {
					t.Fatal("rollback lost row", kind, err)
				}
			}
			if notifications != 0 || len(retentionAudits(t, e, "retention.purge")) != 0 {
				t.Fatal("failed purge notified/audited")
			}
		})
	}
}

func TestRetentionPurgeRequiresPolicyAndValidClock(t *testing.T) {
	e, _ := retentionEngine(t)
	ctx := context.Background()
	if _, err := e.PurgeExpired(ctx, time.Now()); err == nil {
		t.Fatal("purged without adoption")
	}
	if err := e.AdoptRetentionPolicy(ctx, RetentionPolicy{EventsDays: 180, AuditDays: 180}); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{{}, time.Date(0, 1, 2, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := e.PurgeExpired(ctx, now); err == nil {
			t.Fatal("invalid/unrepresentable cutoff accepted", now)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := e.PurgeExpired(cancelled, time.Now()); err == nil {
		t.Fatal("ignored cancelled context")
	}
}

func TestRetentionPurgePendingReviewFailsWithoutDeleting(t *testing.T) {
	e, _ := retentionEngine(t)
	ctx := context.Background()
	if err := e.AdoptRetentionPolicy(ctx, RetentionPolicy{EventsDays: 1, AuditDays: 1}); err != nil {
		t.Fatal(err)
	}
	// Stop the existing sweep via its channel (no wall-time wait); Close still
	// closes that channel and resources normally. Exercise retention in isolation.
	e.stop <- struct{}{}
	old := time.Now().Add(-180 * 24 * time.Hour)
	if err := e.put("reviews", "pending", Review{ID: "pending", Decision: "pending", CreatedAt: old, Deadline: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.PurgeExpired(ctx, time.Now()); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatal("expired pending review silently deleted", err)
	}
}

func TestRetentionConfirmedBlockOriginalExpiredUpdateRetained(t *testing.T) {
	e := engine(t)
	ctx := context.Background()
	if err := e.AdoptRetentionPolicy(ctx, RetentionPolicy{EventsDays: 30, AuditDays: 180}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	originalTime := now.Add(-31 * 24 * time.Hour)
	e.clock = func() time.Time { return originalTime }
	r, err := e.Submit(input("retention-confirmed", "Bash", map[string]any{"command": "redis-cli FLUSHALL"}))
	if err != nil || r.Decision != "reject" {
		t.Fatal(r, err)
	}
	before, err := e.RiskEvents(0, "", RiskEventFilter{})
	if err != nil || len(before.Items) != 1 {
		t.Fatal(before, err)
	}
	e.clock = func() time.Time { return now }
	if err := e.Result(r.ID, "instance", "not_executed", ""); err != nil {
		t.Fatal(err)
	}
	updates := retentionAudits(t, e, "review.result")
	if len(updates) != 1 {
		t.Fatal(updates)
	}
	var bytes string
	if err := teststore.Admin(t, e.DB).QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind='audit' AND id=$2", eventTenant(), updates[0].ID).Scan(&bytes); err != nil {
		t.Fatal(err)
	}
	if result, err := e.PurgeExpired(ctx, now); err != nil || result.EventEnvelopes != 1 || result.Reviews != 0 {
		t.Fatal(result, err)
	}
	after, err := e.RiskEvents(0, "", RiskEventFilter{})
	if err != nil || len(after.Items) != 1 || after.Items[0].Data.ActivityID != 2 || after.Items[0].Data.FindingInfo.UID != before.Items[0].Data.FindingInfo.UID {
		t.Fatal("follow-up lost or original synthesized", after, err)
	}
	var retained string
	if err := teststore.Admin(t, e.DB).QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind='audit' AND id=$2", eventTenant(), updates[0].ID).Scan(&retained); err != nil || retained != bytes {
		t.Fatal("update payload changed", err)
	}
}

func TestRetentionPostgres(t *testing.T) {
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") == "" {
		t.Skip("requires disposable PostgreSQL; SKIPPED, not exercised")
	}
	TestRetentionPurgeCategoriesBoundaryIsolationAndDurability(t)
}
