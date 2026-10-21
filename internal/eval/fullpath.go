package eval

import (
	"aegishook/internal/core"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type PathResult struct {
	Decision          string
	ReviewPath        string
	UnavailableReason string
	LatencyMS         float64
}

// OpenIsolated never uses teststore or an environment-selected application DB.
// It seeds the existing records KV schema (core/store_database.go), then opens
// through core.Open so the deployed migrations/review lifecycle stay in use.
func OpenIsolated(c FrozenConfig, parent string) (*core.Engine, func() error, error) {
	for _, key := range []string{"TG_SENTRY_DATABASE_URL", "TG_SENTRY_MIGRATION_DATABASE_URL"} {
		if _, set := os.LookupEnv(key); set {
			return nil, nil, errors.New("isolated evaluation refuses database environment")
		}
	}
	dir, err := os.MkdirTemp(parent, "eval-store-")
	if err != nil {
		return nil, nil, errors.New("cannot create isolated store")
	}
	cleanup := func() error { return os.RemoveAll(dir) }
	if err = seedStore(dir, c); err != nil {
		cleanup()
		return nil, nil, err
	}
	e, err := core.Open(dir)
	if err != nil {
		cleanup()
		return nil, nil, errors.New("cannot open isolated evaluation store")
	}
	loadedRules, ruleErr := e.Rules()
	expectedRules := append([]core.Rule(nil), c.Rules...)
	sort.Slice(loadedRules, func(i, j int) bool { return loadedRules[i].ID < loadedRules[j].ID })
	sort.Slice(expectedRules, func(i, j int) bool { return expectedRules[i].ID < expectedRules[j].ID })
	if ruleErr != nil || Digest(loadedRules) != Digest(expectedRules) {
		e.Close()
		cleanup()
		return nil, nil, errors.New("core changed frozen rules during open")
	}
	if Digest(e.Config()) != Digest(c.Settings) {
		e.Close()
		cleanup()
		return nil, nil, errors.New("core changed frozen settings during open")
	}
	return e, func() error { return errors.Join(e.Close(), cleanup()) }, nil
}
func seedStore(dir string, c FrozenConfig) error {
	// Same schema/tenant as core's local store. No core API performs a version-
	// preserving settings import, so seed BEFORE Open (no live engine mutation).
	db, err := sql.Open("sqlite", filepath.Join(dir, "aegishook.db"))
	if err != nil {
		return errors.New("cannot seed evaluation store")
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE records(tenant_id TEXT NOT NULL,kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(tenant_id,kind,id))`); err != nil {
		return errors.New("cannot create evaluation schema")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	put := func(kind, id string, v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		_, e = tx.Exec(`INSERT INTO records(tenant_id,kind,id,payload) VALUES('default',?,?,?)`, kind, id, string(b))
		return e
	}
	if err = put("settings", "current", c.Settings); err != nil {
		return err
	}
	for _, r := range c.Rules {
		if err = put("rules", r.ID, r); err != nil {
			return err
		}
	}
	for _, s := range c.Scopes {
		if err = put("scopes", s.ID, s); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return errors.New("cannot seed frozen configuration")
	}
	return nil
}
func FullPath(ctx context.Context, e *core.Engine, item Item, poll time.Duration) (PathResult, error) {
	if ctx.Err() != nil {
		return PathResult{UnavailableReason: "deadline"}, nil
	}
	if item.Review == nil {
		return PathResult{}, errors.New("full-path item requires ReviewInput")
	}
	instance := core.ID()
	if err := e.Register(core.Instance{ID: instance, SessionID: instance, Agent: "claude", Cwd: e.Dir, HookVersion: core.Version}); err != nil {
		return PathResult{}, errors.New("evaluation registration failed")
	}
	in := *item.Review
	in.InstanceID = instance
	in.CallID = item.ID
	start := time.Now()
	r, err := e.Submit(in)
	if err != nil {
		return PathResult{}, errors.New("evaluation submission failed")
	}
	stored, err := waitReview(ctx, r, poll, e.Review)
	out := PathResult{Decision: stored.Decision, ReviewPath: stored.ReviewPath, LatencyMS: float64(time.Since(start)) / float64(time.Millisecond)}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		out.UnavailableReason = "deadline"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if strings.HasPrefix(stored.RuleID, "E_") {
		out.UnavailableReason = stored.RuleID
	}
	return out, nil
}
func waitReview(ctx context.Context, r core.Review, poll time.Duration, read func(string) (core.Review, error)) (core.Review, error) {
	if poll <= 0 {
		return r, errors.New("positive polling interval required")
	}
	deadline, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		stored, err := read(r.ID)
		if err != nil {
			return r, errors.New("cannot read stored terminal review")
		}
		if stored.Decision != "pending" || stored.Result != "" {
			return stored, nil
		}
		select {
		case <-deadline.Done():
			return stored, deadline.Err()
		case <-ticker.C:
		}
	}
}
