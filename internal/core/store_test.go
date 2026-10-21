package core

import (
	"aegishook/internal/teststore"
	"context"
	"io/fs"

	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func rejectAudit(t *testing.T, e *Engine) {
	t.Helper()
	query := `CREATE TRIGGER reject_audit BEFORE INSERT ON records WHEN NEW.kind='audit' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;`
	if e.postgres {
		query = `CREATE FUNCTION reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$;
CREATE TRIGGER reject_audit BEFORE INSERT ON records FOR EACH ROW WHEN (NEW.kind='audit') EXECUTE FUNCTION reject_audit();`
	}
	if _, err := teststore.Admin(t, e.DB).Exec(query); err != nil {
		t.Fatal(err)
	}
}

func TestStoreTenantIsolation(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	// A different tenant can use the same logical key, but no default-tenant
	// read, list, update, deletion, token lookup or count may observe its data.
	foreign := `{"id":"foreign","createdAt":"2099-01-01T00:00:00Z","decision":"pending","needsHuman":true,"tokenHash":"` + credentialHash(strings.Repeat("a", 64)) + `"}`
	for _, kind := range []string{"reviews", "client_nodes", "rules", "scopes", "settings_versions", "audit"} {
		if _, err := teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('other',$1,'foreign',$2)", kind, foreign); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Review("foreign"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign review visible: %v", err)
	}
	if _, ok := e.AuthenticateClient(strings.Repeat("a", 64)); ok {
		t.Fatal("foreign client authenticated")
	}
	page, err := e.ReviewsPage(1, 20, ReviewFilter{})
	if err != nil || page.Total != 0 || page.PendingTotal != 0 || len(page.Items) != 0 {
		t.Fatalf("foreign review counted: %+v %v", page, err)
	}
	for _, kind := range []string{"rules", "scopes", "settings_versions", "audit"} {
		items, err := list[map[string]any](e, kind)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			if item["id"] == "foreign" {
				t.Fatalf("foreign %s listed", kind)
			}
		}
	}
	if err := e.put("reviews", "foreign", Review{ID: "local", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := e.change(testActorContext(), "reviews", "foreign", nil, "test.delete", ""); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := teststore.Admin(t, e.DB).QueryRow("SELECT payload FROM records WHERE tenant_id='other' AND kind='reviews' AND id='foreign'").Scan(&payload); err != nil || payload != foreign {
		t.Fatalf("foreign row modified: %v", err)
	}
}

func TestStoreLiteralSearchAndOrdering(t *testing.T) {
	e, err := Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, id := range []string{"a", "b", "wild_%\\quote'"} {
		if err := e.put("reviews", id, Review{ID: id, CreatedAt: time.Unix(0, 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.put("reviews", "no-time", map[string]string{"id": "no-time"}); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"%", "_", "\\", "quote'", "WILD_"} {
		page, err := e.ReviewsPage(1, 20, ReviewFilter{Query: query})
		if err != nil || page.Total != 1 || page.Items[0].ID != "wild_%\\quote'" {
			t.Fatalf("literal query %q: %+v %v", query, page, err)
		}
	}
	items, err := e.Reviews()
	if err != nil || len(items) != 4 || items[0].ID != "a" || items[1].ID != "b" || items[3].ID != "no-time" {
		t.Fatalf("stable null-last ordering: %+v %v", items, err)
	}
}

func TestConfiguredDatabaseFailsClosed(t *testing.T) {
	for _, dsn := range []string{"", "postgres://user:fixture-password@%zz/db"} {
		t.Run(dsn, func(t *testing.T) {
			t.Setenv("TG_SENTRY_DATABASE_URL", dsn)
			dir := t.TempDir()
			e, err := Open(dir)
			if err == nil {
				e.Close()
				t.Fatal("invalid configured Postgres silently fell back to SQLite")
			}
			if strings.Contains(err.Error(), "fixture-password") {
				t.Fatal("database URL leaked in error")
			}
			if _, err := os.Stat(filepath.Join(dir, "aegishook.db")); !os.IsNotExist(err) {
				t.Fatal("configured Postgres created SQLite")
			}
		})
	}
}

func TestPostgresStoreSingleWriter(t *testing.T) {
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") == "" {
		t.Skip("requires disposable Postgres")
	}
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "aegishook.db")); !os.IsNotExist(err) {
		t.Fatal("Postgres mode created SQLite")
	}
	secondDir := t.TempDir()
	if other, err := Open(secondDir); err == nil {
		other.Close()
		e.Close()
		t.Fatal("two engines admitted for the same Postgres store")
	}
	if err := e.put("fixture", "restart", map[string]string{"value": "persisted"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(secondDir)
	if err != nil {
		t.Fatal("failed open leaked process/database lock", err)
	}
	defer e.Close()
	var value map[string]string
	if err := e.get("fixture", "restart", &value); err != nil || value["value"] != "persisted" {
		t.Fatal("Postgres data did not survive engine reopen", err)
	}
}

func TestPostgresMigrationUpDown(t *testing.T) {
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") == "" {
		t.Skip("requires disposable Postgres")
	}
	teststore.Dir(t, t.TempDir())
	config, err := pgx.ParseConfig(os.Getenv("TG_SENTRY_MIGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal("invalid disposable test URL")
	}
	db := stdlib.OpenDB(*config)
	defer db.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := migratePostgres(ctx, db); err != nil {
			t.Fatal("migration must be repeatable", err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='records' AND column_name='tenant_id' AND is_nullable='NO'").Scan(&count); err != nil || count != 1 {
		t.Fatal("tenant column missing", err)
	}
	if _, err := db.Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES(NULL,'fixture','bad','{}')"); err == nil {
		t.Fatal("null tenant accepted")
	}
	if _, err := db.Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('default','fixture','bad','not-json')"); err == nil {
		t.Fatal("invalid payload accepted")
	}
	files, err := fs.Sub(storeMigrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('default','client_enrollments','migration-fixture','{}')"); err != nil {
		t.Fatal(err)
	}
	var index sql.NullString
	if err := db.QueryRow("SELECT to_regclass('idx_records_client_credential_hash')::text").Scan(&index); err != nil || !index.Valid {
		t.Fatal("credential index missing", err)
	}
	if _, err := provider.DownTo(ctx, 1); err != nil {
		t.Fatal("credential index rollback", err)
	}
	if err := db.QueryRow("SELECT to_regclass('idx_records_client_credential_hash')::text").Scan(&index); err != nil || index.Valid {
		t.Fatal("credential index retained after rollback", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM records WHERE tenant_id='default' AND kind='client_enrollments' AND id='migration-fixture'").Scan(&count); err != nil || count != 1 {
		t.Fatal("index rollback changed enrollment data", err)
	}
	if err := migratePostgres(ctx, db); err != nil {
		t.Fatal("credential index reapply", err)
	}
	if _, err := provider.DownTo(ctx, 0); err != nil {
		t.Fatal("rollback", err)
	}
	var table sql.NullString
	if err := db.QueryRow("SELECT to_regclass('records')::text").Scan(&table); err != nil || table.Valid {
		t.Fatal("down migration retained records table", err)
	}
	if err := migratePostgres(ctx, db); err != nil {
		t.Fatal("reapply after rollback", err)
	}
}

func TestSQLiteLegacyTenantUpgrade(t *testing.T) {
	// This fixture specifically exercises an existing on-disk SQLite database,
	// not a fallback from Postgres or an imported customer database.
	t.Setenv("TG_SENTRY_DATABASE_URL", "")
	if err := os.Unsetenv("TG_SENTRY_DATABASE_URL"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "aegishook.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE records(kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(kind,id));
CREATE INDEX idx_records_reviews_created ON records(kind,json_extract(payload,'$.createdAt'));
INSERT INTO records VALUES('fixture','saved','{"value":"retained"}');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		e, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]string
		err = e.get("fixture", "saved", &value)
		if closeErr := e.Close(); err != nil || closeErr != nil || value["value"] != "retained" {
			t.Fatal("legacy data changed across tenant upgrade/reopen", err, closeErr)
		}
	}
}

func TestPostgresFailedStartupReleasesLock(t *testing.T) {
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") == "" {
		t.Skip("requires disposable Postgres")
	}
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.put("settings", "current", "not-a-settings-object"); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(dir); err == nil {
		other.Close()
		t.Fatal("bad settings accepted")
	}
	config, err := pgx.ParseConfig(os.Getenv("TG_SENTRY_MIGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal("invalid disposable test URL")
	}
	db := stdlib.OpenDB(*config)
	_, err = db.Exec("DELETE FROM records WHERE tenant_id='default' AND kind='settings' AND id='current'")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir)
	if err != nil {
		t.Fatal("failed startup retained a lock", err)
	}
	e.Close()
}

func TestSQLiteInvalidDatabaseFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aegishook.db")
	original := []byte("fixture: not a SQLite database")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if db, err := openSQLite(dir); err == nil || db != nil {
		if db != nil {
			db.Close()
		}
		t.Fatal("invalid local store accepted")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != string(original) {
		t.Fatal("failed open altered the existing local file", err)
	}
}

func TestSQLiteTenantUpgradeRollsBackInvalidLegacyRows(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A damaged/imported legacy table must not be left half-renamed if copying
	// into the new NOT NULL schema fails after DDL has already run.
	if _, err := db.Exec(`CREATE TABLE records(kind TEXT,id TEXT,payload TEXT);
INSERT INTO records VALUES('fixture','retained',NULL)`); err != nil {
		t.Fatal(err)
	}
	if err := upgradeSQLiteTenant(db); err == nil {
		t.Fatal("invalid legacy payload accepted")
	}
	var tenantColumns, legacyTables, rows int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('records') WHERE name='tenant_id'").Scan(&tenantColumns); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='records_legacy'").Scan(&legacyTables); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM records WHERE kind='fixture' AND id='retained' AND payload IS NULL").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if tenantColumns != 0 || legacyTables != 0 || rows != 1 {
		t.Fatalf("partial migration retained: tenant columns=%d legacy tables=%d rows=%d", tenantColumns, legacyTables, rows)
	}
}

func TestSQLiteCredentialIndexPopulatedUpgradeAndReopen(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "aegishook.db"))
	if err != nil {
		t.Fatal(err)
	}
	// Existing tenant-aware SQLite store, populated before #6's index exists.
	payload := `{"id":"device","tokenHash":"fixture-hash","revoked":false}`
	_, err = db.Exec(`CREATE TABLE records(tenant_id TEXT NOT NULL,kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(tenant_id,kind,id));
INSERT INTO records VALUES('default','client_nodes','device',$1)`, payload)
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		t.Fatal("create populated fixture", err, closeErr)
	}
	for i := 0; i < 2; i++ {
		db, err := openSQLite(dir)
		if err != nil {
			t.Fatal(err)
		}
		var indexes int
		if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_records_client_credential_hash'").Scan(&indexes); err != nil || indexes != 1 {
			db.Close()
			t.Fatal("credential index missing after upgrade/reopen", err)
		}
		var saved string
		if err := db.QueryRow("SELECT payload FROM records WHERE tenant_id='default' AND kind='client_nodes' AND json_extract(payload,'$.tokenHash')=$1", "fixture-hash").Scan(&saved); err != nil || saved != payload {
			db.Close()
			t.Fatal("upgrade changed credential payload", err)
		}
		var planID, parentID, unused int
		var detail string
		if err := db.QueryRow("EXPLAIN QUERY PLAN SELECT payload FROM records WHERE tenant_id='default' AND kind='client_nodes' AND json_extract(payload,'$.tokenHash')=$1", "fixture-hash").Scan(&planID, &parentID, &unused, &detail); err != nil || !strings.Contains(detail, "idx_records_client_credential_hash") {
			db.Close()
			t.Fatal("credential lookup does not use tenant hash index", err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAtomicFileDirectorySync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic")
	sentinel := errors.New("injected directory fsync failure")
	called := false
	err := atomicFile(path, []byte("new"), 0600, func(parent string) error {
		called = true
		if parent != dir {
			t.Fatal("wrong directory synced")
		}
		b, err := os.ReadFile(path)
		if err != nil || string(b) != "new" {
			t.Fatal("directory synced before rename", err)
		}
		return sentinel
	})
	if !called || !errors.Is(err, sentinel) {
		t.Fatal("directory sync failure swallowed", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("atomic temp file leaked", err)
	}
	if err := AtomicFile(path, []byte("durable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syncDirectory(filepath.Join(dir, "absent")); runtime.GOOS != "windows" && err == nil {
		t.Fatal("missing sync directory accepted")
	}
}
