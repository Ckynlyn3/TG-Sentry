package core

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var storeMigrations embed.FS

// ponytail: M1 keeps the existing kind/id JSON KV contract and one writer;
// tenant isolation is enforced by PostgreSQL RLS, not payload claims.
const upsertRecord = "INSERT INTO records(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,kind,id) DO UPDATE SET payload=excluded.payload"
const insertRecord = "INSERT INTO records(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4)"
const insertSnapshot = "INSERT INTO records(tenant_id,kind,id,payload) VALUES($1,'settings_versions',$2,$3) ON CONFLICT(tenant_id,kind,id) DO NOTHING"
const storeLock = "hashtextextended(current_database() || '.' || current_schema() || '.tg-sentry.default', 0)"

// PostgreSQL Schemas, "Usage Patterns": the app must not be able to CREATE in
// any searched schema, not just current_schema(). Check before resolving either
// records or goose_db_version, without hardcoding the deployment/test schema.
// https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATTERNS
// pg_catalog is implicitly searched first unless explicitly listed otherwise;
// qualify the bootstrap functions so even that ordering cannot bypass this check.
func checkPostgresSearchPath(ctx context.Context, conn *pgx.Conn) error {
	var safe bool
	err := conn.QueryRow(ctx, `SELECT NOT EXISTS (
	  SELECT FROM pg_catalog.unnest(pg_catalog.current_schemas(true)) AS s(name)
	  WHERE pg_catalog.has_schema_privilege('tg_sentry_app', s.name, 'CREATE'))`).Scan(&safe)
	if err != nil || !safe {
		return errors.Join(errors.New("unsafe Postgres search_path: app role must not have CREATE on searched schemas"), conn.Close(ctx))
	}
	// Explicit pg_temp last prevents a future temp table from shadowing records.
	// Preserve operator ordering if pg_temp was already explicit (duplicates are harmless).
	// https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY
	if _, err := conn.Exec(ctx, `SELECT pg_catalog.set_config('search_path',
	  pg_catalog.current_setting('search_path') OPERATOR(pg_catalog.||) ', pg_temp', false)`); err != nil {
		return errors.Join(errors.New("cannot secure Postgres search_path"), conn.Close(ctx))
	}
	return nil
}

func migratePostgres(ctx context.Context, db *sql.DB) error {
	files, err := fs.Sub(storeMigrations, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files)
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}

func openDatabase(dir string) (*sql.DB, bool, error) {
	dsn, postgres := os.LookupEnv("TG_SENTRY_DATABASE_URL")
	if !postgres {
		db, err := openSQLite(dir)
		return db, false, err
	}
	// Empty-but-configured must fail closed, not select a local SQLite store.
	if dsn == "" {
		return nil, true, errors.New("TG_SENTRY_DATABASE_URL is empty")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, true, errors.New("invalid Postgres configuration")
	}
	if err := migrateConfiguredPostgres(); err != nil {
		return nil, true, errors.New("cannot migrate Postgres store; check owner configuration and non-writable app search_path")
	}
	db := stdlib.OpenDB(*config, stdlib.OptionAfterConnect(func(ctx context.Context, conn *pgx.Conn) error {
		if err := checkPostgresSearchPath(ctx, conn); err != nil {
			return err
		}
		// Never retain owner/superuser credentials in the runtime query pool.
		var safe bool
		err := conn.QueryRow(ctx, `SELECT r.rolname='tg_sentry_app' AND session_user=current_user
          AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
          AND c.relowner<>r.oid AND c.relrowsecurity AND c.relforcerowsecurity
          AND NOT has_table_privilege(c.oid,'TRUNCATE')
          AND NOT EXISTS (SELECT FROM pg_auth_members WHERE member=r.oid)
          FROM pg_roles r CROSS JOIN pg_class c
          WHERE r.rolname=current_user AND c.oid='records'::regclass`).Scan(&safe)
		if err != nil || !safe {
			return errors.Join(errors.New("unsafe Postgres runtime role or missing RLS"), conn.Close(ctx))
		}
		// Lock the actual query session, including every replacement connection.
		// Local file locks alone cannot serialize different dirs on the same DSN.
		var acquired bool
		// stdlib's connector does not close a connection rejected by AfterConnect.
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock("+storeLock+")").Scan(&acquired); err != nil {
			return errors.Join(err, conn.Close(ctx))
		}
		if !acquired {
			return errors.Join(errors.New("Postgres store already open"), conn.Close(ctx))
		}
		return nil
	}))
	// Keep the existing single-writer model; session locks release on DB.Close.
	db.SetMaxOpenConns(1)
	if err = db.PingContext(context.Background()); err != nil {
		db.Close()
		// Driver errors may contain a DSN or server-provided sensitive details.
		return nil, true, errors.New("cannot open Postgres store; check configuration, non-writable search_path, migrations and single-writer ownership")
	}
	return db, true, nil
}

func openSQLite(dir string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", filepath.Join(dir, "aegishook.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS records(tenant_id TEXT NOT NULL,kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(tenant_id,kind,id));`); err == nil {
		err = upgradeSQLiteTenant(db)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	if err = os.Chmod(filepath.Join(dir, "aegishook.db"), 0600); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func upgradeSQLiteTenant(db *sql.DB) error {
	var columns int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('records') WHERE name='tenant_id'").Scan(&columns); err != nil {
		return err
	}
	if columns == 0 {
		// Transactional rebuild preserves all legacy payload bytes and key pairs.
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.Exec(`ALTER TABLE records RENAME TO records_legacy;
CREATE TABLE records(tenant_id TEXT NOT NULL,kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(tenant_id,kind,id));
INSERT INTO records SELECT 'default',kind,id,payload FROM records_legacy;
DROP TABLE records_legacy;`); err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_records_reviews_created ON records(tenant_id,kind,json_extract(payload,'$.createdAt'));
CREATE INDEX IF NOT EXISTS idx_records_client_credential_hash ON records(tenant_id,json_extract(payload,'$.tokenHash')) WHERE kind='client_nodes';`)
	return err
}

// Only fixed, developer-authored field/alias names reach these SQL expressions.
func (e *Engine) jsonField(alias, field string) string {
	if e.postgres {
		return "(" + alias + "payload::json->>'" + field + "') COLLATE \"C\""
	}
	return "json_extract(" + alias + "payload,'$." + field + "')"
}

// PostgreSQL 16 §9.27.1: true limits this setting to the current transaction.
// https://www.postgresql.org/docs/16/functions-admin.html#FUNCTIONS-ADMIN-SET
func (e *Engine) beginTenant() (*sql.Tx, error) {
	return e.beginTenantTx(context.Background(), nil)
}

// beginTenantTx is beginTenant with caller context and options (read-only export).
func (e *Engine) beginTenantTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	tx, err := e.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if e.postgres {
		if _, err = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", eventTenant()); err != nil {
			return nil, errors.Join(err, tx.Rollback())
		}
	}
	return tx, nil
}

// Owner DSN is optional when migrations have already been applied out-of-process.
// It is never used by the runtime pool and never falls back to the app DSN.
func migrateConfiguredPostgres() error {
	dsn, configured := os.LookupEnv("TG_SENTRY_MIGRATION_DATABASE_URL")
	if !configured {
		return nil
	}
	if dsn == "" {
		return errors.New("empty migration database URL")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return errors.New("invalid migration database configuration")
	}
	owner := stdlib.OpenDB(*config, stdlib.OptionAfterConnect(checkPostgresSearchPath))
	defer owner.Close()
	return migratePostgres(context.Background(), owner)
}
