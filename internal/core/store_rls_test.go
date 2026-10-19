package core

import (
	"aegishook/internal/teststore"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
)

func postgresEngine(t *testing.T) *Engine {
	t.Helper()
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") == "" {
		t.Skip("requires disposable Postgres")
	}
	e, err := Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestPostgresRuntimeRole(t *testing.T) {
	e := postgresEngine(t)
	var name string
	var unsafe, owner, enabled, forced bool
	err := e.DB.QueryRow(`SELECT current_user, r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb,
 c.relowner=r.oid, c.relrowsecurity, c.relforcerowsecurity
 FROM pg_roles r CROSS JOIN pg_class c WHERE r.rolname=current_user AND c.oid='records'::regclass`).Scan(&name, &unsafe, &owner, &enabled, &forced)
	if err != nil || name != "tg_sentry_app" || unsafe || owner || !enabled || !forced {
		t.Fatalf("unsafe runtime role/policies: role=%s unsafe=%v owner=%v enabled=%v forced=%v err=%v", name, unsafe, owner, enabled, forced, err)
	}
}

func TestPostgresRLSFailClosed(t *testing.T) {
	e := postgresEngine(t)
	admin := teststore.Admin(t, e.DB)
	if _, err := admin.Exec(`INSERT INTO records VALUES ('default','fixture','mine','{}'),('other','fixture','foreign','{}')`); err != nil {
		t.Fatal(err)
	}
	// An extra permissive policy must not OR away the tenant restriction.
	if _, err := admin.Exec(`CREATE POLICY additional_allow ON records USING (true) WITH CHECK (true)`); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "default", "other", "unknown"} {
		t.Run("tenant="+tenant, func(t *testing.T) {
			tx, err := e.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if tenant != "" {
				if _, err := tx.Exec("SELECT set_config('app.tenant_id', $1, true)", tenant); err != nil {
					t.Fatal(err)
				}
			}
			want := 0
			if tenant == "default" || tenant == "other" {
				want = 1
			}
			var count int
			if err := tx.QueryRow("SELECT COUNT(*) FROM records WHERE kind='fixture'").Scan(&count); err != nil || count != want {
				t.Fatalf("unfiltered read: %d want %d: %v", count, want, err)
			}
			if tenant != "default" {
				return
			}
			if err := tx.QueryRow("SELECT payload FROM records WHERE tenant_id='other' AND id='foreign'").Scan(new(string)); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("cross-tenant read: %v", err)
			}
			for _, query := range []string{"UPDATE records SET payload='{}' WHERE tenant_id='other'", "DELETE FROM records WHERE tenant_id='other'"} {
				result, err := tx.Exec(query)
				if err != nil {
					t.Fatal(err)
				}
				n, err := result.RowsAffected()
				if err != nil || n != 0 {
					t.Fatalf("cross-tenant mutation: %d %v", n, err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, query := range []string{
		`INSERT INTO records VALUES ('other','fixture','forged','{}')`,
		`INSERT INTO records VALUES ('other','fixture','foreign','{}') ON CONFLICT(tenant_id,kind,id) DO UPDATE SET payload=excluded.payload`,
		`UPDATE records SET tenant_id='other' WHERE kind='fixture' AND id='mine'`,
	} {
		tx, err := e.beginTenant()
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(query)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("WITH CHECK accepted forbidden write: %v", err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.DB.Exec(`INSERT INTO records VALUES ('default','fixture','unset','{}')`); err == nil {
		t.Fatal("missing context permitted insert")
	}
	// COPY TO is a real export path, not a SELECT standing in for export.
	config, err := pgx.ParseConfig(os.Getenv("TG_SENTRY_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(context.Background(), "SELECT set_config('app.tenant_id', $1, true)", eventTenant()); err != nil {
		t.Fatal(err)
	}
	var exported captureExport
	if _, err := conn.PgConn().CopyTo(context.Background(), &exported, "COPY (SELECT * FROM records WHERE tenant_id='other') TO STDOUT"); err != nil || len(exported) != 0 {
		t.Fatalf("cross-tenant export: %q %v", exported, err)
	}
}

type captureExport []byte

func (b *captureExport) Write(p []byte) (int, error) { *b = append(*b, p...); return len(p), nil }

func TestPostgresTenantTransactionPoolReset(t *testing.T) {
	e := postgresEngine(t)
	var session int
	if err := e.DB.QueryRow("SELECT pg_backend_pid()").Scan(&session); err != nil {
		t.Fatal(err)
	}
	for _, commit := range []bool{true, false} {
		tx, err := e.beginTenant()
		if err != nil {
			t.Fatal(err)
		}
		var tenant string
		if err := tx.QueryRow("SELECT current_setting('app.tenant_id', true)").Scan(&tenant); err != nil || tenant != eventTenant() {
			t.Fatalf("missing transaction context: %q %v", tenant, err)
		}
		if commit {
			err = tx.Commit()
		} else {
			err = tx.Rollback()
		}
		if err != nil {
			t.Fatal(err)
		}
		var pid, count int
		var unset bool
		if err := e.DB.QueryRow("SELECT pg_backend_pid(), NULLIF(current_setting('app.tenant_id', true),'') IS NULL, (SELECT COUNT(*) FROM records)").Scan(&pid, &unset, &count); err != nil || pid != session || !unset || count != 0 {
			t.Fatalf("pooled context leaked: pid=%d initial=%d unset=%v rows=%d %v", pid, session, unset, count, err)
		}
	}
}

func TestPostgresRLSMigrationRetainsData(t *testing.T) {
	e := postgresEngine(t)
	admin := teststore.Admin(t, e.DB)
	files, err := fs.Sub(storeMigrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, admin, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`INSERT INTO records VALUES ('other','fixture','retained','{"value":"unchanged"}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := admin.QueryRow("SELECT payload FROM records WHERE tenant_id='other' AND id='retained'").Scan(&payload); err != nil || payload != `{"value":"unchanged"}` {
		t.Fatalf("down lost bytes: %q %v", payload, err)
	}
	if err := migratePostgres(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := e.DB.QueryRow("SELECT COUNT(*) FROM records").Scan(&count); err != nil || count != 0 {
		t.Fatalf("reapply did not restore deny-unset: %d %v", count, err)
	}
}

func TestPostgresRejectsOwnerRuntime(t *testing.T) {
	postgresEngine(t)
	t.Setenv("TG_SENTRY_DATABASE_URL", os.Getenv("TG_SENTRY_MIGRATION_DATABASE_URL"))
	if db, _, err := openDatabase(t.TempDir()); err == nil {
		db.Close()
		t.Fatal("owner accepted as runtime role")
	}
}

func TestPostgresForgedTenantIdentityRejected(t *testing.T) {
	e := postgresEngine(t)
	admin := teststore.Admin(t, e.DB)
	token, nodeID, instanceID := ID()+ID(), ID(), ID()
	node, err := json.Marshal(storedClientNode{ClientNode: ClientNode{ID: nodeID}, Hash: credentialHash(token)})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := json.Marshal(Instance{ID: instanceID, NodeID: nodeID, SessionID: "foreign", State: "idle", Heartbeat: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for kind, payload := range map[string][]byte{"client_nodes": node, "instances": instance} {
		id := nodeID
		if kind == "instances" {
			id = instanceID
		}
		if _, err := admin.Exec("INSERT INTO records VALUES('other',$1,$2,$3)", kind, id, string(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := e.AuthenticateClient(token); ok {
		t.Fatal("foreign device credential authenticated")
	}
	if e.ClientOwnsInstance(nodeID, instanceID) {
		t.Fatal("foreign agent ownership accepted")
	}
	if _, err := e.Submit(ReviewInput{InstanceID: instanceID, CallID: ID(), ToolName: "Bash", Arguments: map[string]any{"command": "echo fixture"}}); err == nil {
		t.Fatal("forged foreign agent submitted a review")
	}
	if err := e.RevokeClient(testActorContext(), nodeID); err == nil {
		t.Fatal("foreign device revoked")
	}
	events, err := e.RiskEvents(20, "", RiskEventFilter{})
	if err != nil || len(events.Items) != 0 {
		t.Fatal("foreign risk export visible", err)
	}
}

func TestPostgresForceAppliesToNonSuperOwner(t *testing.T) {
	e := postgresEngine(t)
	admin := teststore.Admin(t, e.DB)
	var owner string
	if err := admin.QueryRow("SELECT current_user").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec("ALTER TABLE records OWNER TO tg_sentry_app"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec("ALTER TABLE records OWNER TO " + pgx.Identifier{owner}.Sanitize()); err != nil {
			t.Error(err)
		}
	}()
	var count int
	if err := e.DB.QueryRow("SELECT COUNT(*) FROM records").Scan(&count); err != nil || count != 0 {
		t.Fatalf("FORCE failed for owner: %d %v", count, err)
	}
	tx, err := e.beginTenant()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := tx.QueryRow("SELECT COUNT(*) FROM records").Scan(&count); err != nil || count == 0 {
		t.Fatalf("owner positive control: %d %v", count, err)
	}
}

func TestPostgresMigrationConfigurationFailClosed(t *testing.T) {
	postgresEngine(t)
	for _, dsn := range []string{"", "postgres://fixture:must-not-leak@%zz/db"} {
		t.Setenv("TG_SENTRY_MIGRATION_DATABASE_URL", dsn)
		if db, _, err := openDatabase(t.TempDir()); err == nil {
			db.Close()
			t.Fatal("invalid migration configuration accepted")
		} else if strings.Contains(err.Error(), "must-not-leak") {
			t.Fatal("migration credential exposed")
		}
	}
}

func TestPostgresPreappliedMigrationAndClosedPool(t *testing.T) {
	e := postgresEngine(t)
	// The service need not receive owner credentials after an offline migration.
	t.Setenv("TG_SENTRY_MIGRATION_DATABASE_URL", "")
	if err := os.Unsetenv("TG_SENTRY_MIGRATION_DATABASE_URL"); err != nil {
		t.Fatal(err)
	}
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	db, postgres, err := openDatabase(t.TempDir())
	if err != nil || !postgres {
		t.Fatalf("preapplied migrations unavailable: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if tx, err := e.beginTenant(); err == nil {
		tx.Rollback()
		t.Fatal("closed tenant pool accepted transaction")
	}
}
