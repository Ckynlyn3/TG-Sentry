// Package teststore gives each existing directory-based fixture its own Postgres
// schema when the disposable TG_SENTRY_TEST_DATABASE_URL is explicitly set.
package teststore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed postgres-dev-init.sql
var postgresDevInit string

func Dir(t testing.TB, dir string) string {
	t.Helper()
	dsn := os.Getenv("TG_SENTRY_TEST_DATABASE_URL")
	// Never let tests select a developer's configured application database.
	t.Setenv("TG_SENTRY_DATABASE_URL", "")
	t.Setenv("TG_SENTRY_MIGRATION_DATABASE_URL", "")
	if dsn == "" {
		if err := os.Unsetenv("TG_SENTRY_DATABASE_URL"); err != nil {
			t.Fatal(err)
		}
		if err := os.Unsetenv("TG_SENTRY_MIGRATION_DATABASE_URL"); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid disposable test database URL")
	}
	db := stdlib.OpenDB(*config)
	defer db.Close()
	if _, err := db.Exec(postgresDevInit); err != nil {
		t.Fatal("provision disposable app role", err)
	}
	digest := sha256.Sum256([]byte(dir))
	// Same 16-byte identity width as core.ID; safely below Postgres's 63-byte name limit.
	schema := "test_" + hex.EncodeToString(digest[:16])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = db.ExecContext(context.Background(), "CREATE SCHEMA IF NOT EXISTS "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db := stdlib.OpenDB(*config)
		defer db.Close()
		if _, err := db.ExecContext(context.Background(), "DROP SCHEMA IF EXISTS "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid disposable test database URL")
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + schema
	}
	t.Setenv("TG_SENTRY_MIGRATION_DATABASE_URL", dsn)
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid disposable test database URL")
		}
		u.User = url.UserPassword("tg_sentry_app", "dev-only")
		dsn = u.String()
	} else {
		dsn += " user=tg_sentry_app password=dev-only"
	}
	t.Setenv("TG_SENTRY_DATABASE_URL", dsn)
	return dir
}

// adminPools keeps one owner pool per test so looped fixture inserts stay
// within the server's max_connections.
var adminPools sync.Map

// Admin is only for disposable fixture setup and inspection, never runtime queries.
func Admin(t testing.TB, fallback *sql.DB) *sql.DB {
	t.Helper()
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") == "" {
		return fallback
	}
	if db, ok := adminPools.Load(t); ok {
		return db.(*sql.DB)
	}
	dsn := os.Getenv("TG_SENTRY_MIGRATION_DATABASE_URL")
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid disposable owner URL")
	}
	db := stdlib.OpenDB(*config)
	adminPools.Store(t, db)
	t.Cleanup(func() { adminPools.Delete(t); db.Close() })
	return db
}
