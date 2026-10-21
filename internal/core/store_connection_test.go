package core

import (
	"aegishook/internal/teststore"
	"context"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresRejectedOpenDoesNotLeakSessions(t *testing.T) {
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") == "" {
		t.Skip("requires disposable Postgres")
	}
	// Prove explicit cleanup rather than letting an unrelated GC/finalizer hide
	// a rejected connection. Restore the process-local GC setting after the test.
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	dir := teststore.Dir(t, t.TempDir())
	app := "tg-sentry-session-" + ID()
	dsn := os.Getenv("TG_SENTRY_DATABASE_URL")
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid disposable test URL")
		}
		query := u.Query()
		query.Set("application_name", app)
		u.RawQuery = query.Encode()
		dsn = u.String()
	} else {
		dsn += " application_name=" + app
	}
	t.Setenv("TG_SENTRY_DATABASE_URL", dsn)
	config, err := pgx.ParseConfig(os.Getenv("TG_SENTRY_MIGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal("invalid disposable test URL")
	}
	// Keep the observer separate from the application's session count.
	config.RuntimeParams["application_name"] = app + "-observer"
	observer := stdlib.OpenDB(*config)
	defer observer.Close()
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	const sessions = "SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1"
	var before int
	if err := observer.QueryRow(sessions, app).Scan(&before); err != nil || before != 1 {
		t.Fatalf("expected one owned query session, got %d: %v", before, err)
	}
	if second, err := Open(t.TempDir()); err == nil {
		second.Close()
		t.Fatal("second writer unexpectedly admitted")
	}
	// Use the existing SQLite busy_timeout budget while the server processes
	// the connection's Terminate packet; do not rely on a fixed sleep.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	after := before
	for {
		if err := observer.QueryRowContext(ctx, sessions, app).Scan(&after); err != nil {
			t.Fatalf("rejected Open did not release its session (baseline=%d last observed=%d): %v", before, after, err)
		}
		if after == before {
			t.Logf("application sessions: before=%d after rejected Open=%d", before, after)
			break
		}
	}
}
