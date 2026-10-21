package core

import (
	"aegishook/internal/teststore"
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresRejectsWritableSearchPath(t *testing.T) {
	e := postgresEngine(t)
	admin := teststore.Admin(t, e.DB)
	var schema string
	if err := admin.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	writable := pgx.Identifier{schema + "_writable"}.Sanitize()
	if _, err := admin.Exec("CREATE SCHEMA " + writable + "; GRANT USAGE, CREATE ON SCHEMA " + writable + " TO tg_sentry_app"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP SCHEMA " + writable + " CASCADE"); err != nil {
			t.Error(err)
		}
	})
	// Release the existing writer lock so success cannot be a lock rejection.
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(os.Getenv("TG_SENTRY_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	attacker := stdlib.OpenDB(*config)
	defer attacker.Close()
	if _, err := attacker.Exec("CREATE TABLE " + writable + ".records (decoy boolean)"); err != nil {
		t.Fatal(err)
	}
	// A later decoy cannot shadow an existing earlier table. Put it first for
	// the shadowing control, and keep the later-schema privilege regression too.
	for _, path := range []string{writable + "," + schema, schema + "," + writable, schema + "," + writable + ",pg_catalog"} {
		t.Run(path, func(t *testing.T) {
			config := config.Copy()
			config.RuntimeParams["search_path"] = path
			probe := stdlib.OpenDB(*config)
			defer probe.Close()
			var writablePrivilege, appOwned, shadows bool
			if err := probe.QueryRow(`SELECT pg_catalog.has_schema_privilege($1,'CREATE'),
			  c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user),
			  'records'::regclass=c.oid FROM pg_catalog.pg_class c WHERE c.oid=$2::regclass`,
				schema+"_writable", writable+".records").Scan(&writablePrivilege, &appOwned, &shadows); err != nil || !writablePrivilege || !appOwned || shadows != strings.HasPrefix(path, writable) {
				t.Fatalf("invalid decoy control: writable=%v appOwned=%v shadows=%v err=%v", writablePrivilege, appOwned, shadows, err)
			}
			t.Logf("app-owned decoy is writable; shadows records=%v", shadows)
			dsn := os.Getenv("TG_SENTRY_DATABASE_URL")
			if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
				u, err := url.Parse(dsn)
				if err != nil {
					t.Fatal(err)
				}
				query := u.Query()
				query.Set("search_path", path)
				u.RawQuery = query.Encode()
				dsn = u.String()
			} else {
				dsn += " search_path='" + path + "'"
			}
			t.Setenv("TG_SENTRY_DATABASE_URL", dsn)
			if db, _, err := openDatabase(t.TempDir()); err == nil {
				db.Close()
				t.Fatal("writable later search_path schema accepted")
			} else if !strings.Contains(err.Error(), "search_path") {
				t.Fatalf("missing actionable search_path error: %v", err)
			}
		})
	}
}

func TestPostgresTempRecordsCannotShadowStore(t *testing.T) {
	e := postgresEngine(t)
	// Replace the opening session: no temp schema exists when bootstrap runs.
	e.DB.SetMaxIdleConns(0)
	conn, err := e.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var real, resolved, decoy uint32
	if err := conn.QueryRowContext(context.Background(), "SELECT 'records'::regclass::oid").Scan(&real); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "CREATE TEMP TABLE records (decoy boolean)"); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(context.Background(), "SELECT 'records'::regclass::oid, 'pg_temp.records'::regclass::oid").Scan(&resolved, &decoy); err != nil {
		t.Fatal(err)
	}
	if decoy == real || resolved != real {
		t.Fatalf("temp table shadowed store: real=%d resolved=%d decoy=%d", real, resolved, decoy)
	}
}

func TestPostgresRejectsAppWritableMigrationSearchPath(t *testing.T) {
	e := postgresEngine(t)
	admin := teststore.Admin(t, e.DB)
	var schema string
	if err := admin.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec("GRANT CREATE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO tg_sentry_app"); err != nil {
		t.Fatal(err)
	}
	if err := migrateConfiguredPostgres(); err == nil {
		t.Fatal("goose accepted app-writable search_path")
	}
}

func TestPostgresRechecksSearchPathOnReplacementConnection(t *testing.T) {
	e := postgresEngine(t)
	admin := teststore.Admin(t, e.DB)
	var schema string
	if err := admin.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec("GRANT CREATE ON SCHEMA " + quoted + " TO tg_sentry_app"); err != nil {
		t.Fatal(err)
	}
	// Close the idle session; Ping must pass through AfterConnect again.
	e.DB.SetMaxIdleConns(0)
	if err := e.DB.PingContext(context.Background()); err == nil {
		t.Fatal("replacement connection accepted newly writable search_path")
	}
}
