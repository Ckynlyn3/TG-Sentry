package core

import (
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testActorContext() context.Context {
	return WithActor(context.Background(), SystemActor("test"))
}

func assertAuditActors(t *testing.T, e *Engine) {
	t.Helper()
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		// Export tests deliberately insert historical rows without an action.
		if audit.Action == "" {
			continue
		}
		if audit.Actor.Kind == "" || (audit.Actor.Kind == "system" && (audit.Actor.Component == "" || audit.Actor.Component == "unattributed")) {
			t.Errorf("audit %s (%s) has missing/unattributed actor: %+v", audit.ID, audit.Action, audit.Actor)
		}
	}
}

func TestChangeRecordsActor(t *testing.T) {
	e := engine(t)
	actor := Actor{Issuer: "https://issuer.example", Subject: "subject", Name: "Display name", Kind: "human"}
	ctx := WithActor(context.Background(), actor)
	key, err := e.CreateEnrollment(ctx, "actor fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeEnrollment(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	r, err := e.ReviewProtection(ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "actor fixture", Rules: []TemplateRule{}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.ConfirmProtection(ctx, r.ID, 0, true, "templates", "", false); err != nil {
		t.Fatal(err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, audit := range audits {
		if audit.Action == "instance.register" {
			continue
		}
		if audit.Actor != actor {
			t.Fatalf("actor not persisted on %s: %+v", audit.Action, audit.Actor)
		}
		seen[audit.Action] = true
	}
	for _, action := range []string{"client.enrollment.create", "client.enrollment.revoke", "protection.templates.publish"} {
		if !seen[action] {
			t.Fatalf("missing audit %s", action)
		}
	}
}

func TestConcurrentActorsRemainDistinct(t *testing.T) {
	e := engine(t)
	actors := []Actor{
		{Issuer: "https://issuer.example", Subject: "alice", Kind: "human"},
		{Issuer: "https://issuer.example", Subject: "bob", Kind: "human"},
	}
	var wg sync.WaitGroup
	for _, actor := range actors {
		wg.Go(func() {
			ctx := WithActor(context.Background(), actor)
			if err := e.SaveScope(ctx, Scope{ID: actor.Subject, Name: actor.Subject, Project: t.TempDir()}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, audit := range audits {
		if audit.Action == "scope.save" {
			count++
			if audit.Actor.Subject != audit.Subject || audit.Actor.Issuer != actors[0].Issuer {
				t.Fatalf("concurrent actors crossed: %+v", audit)
			}
		}
	}
	if count != len(actors) {
		t.Fatalf("got %d scope audits", count)
	}
}

func TestChangeFailureRollsBackAuditAndResource(t *testing.T) {
	e := engine(t)
	before, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(t, e)
	if _, err := e.CreateEnrollment(testActorContext(), "rollback"); err == nil {
		t.Fatal("failed audit allowed resource commit")
	}
	keys, err := e.Enrollments()
	if err != nil || len(keys) != 0 {
		t.Fatalf("resource not rolled back: %+v %v", keys, err)
	}
	after, err := e.Audits()
	if err != nil || len(after) != len(before) {
		t.Fatalf("audit changed after failed transaction: %v", err)
	}
}

func TestSystemActorForBackgroundPaths(t *testing.T) {
	e := engine(t)
	r, err := e.Submit(input("expire", "fixture", map[string]any{"value": "safe"}))
	if err != nil || r.Decision != "pending" {
		t.Fatalf("pending fixture: %+v %v", r, err)
	}
	e.mu.Lock()
	e.clock = func() time.Time { return r.Deadline.Add(time.Second) }
	e.mu.Unlock()
	e.Expire()
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, audit := range audits {
		if audit.Action == "review.timeout" {
			seen = true
			if audit.Actor != SystemActor("review-expiry") {
				t.Fatalf("background actor: %+v", audit.Actor)
			}
		}
	}
	if !seen {
		t.Fatal("background path was not exercised")
	}
}

func TestEveryChangeRecordsActor(t *testing.T) {
	// The same assertion is registered by engine(t) across the store suite.
	e := engine(t)
	ctx := testActorContext()
	if err := e.SaveScope(ctx, Scope{ID: "actor", Name: "actor", Project: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteScope(ctx, "actor"); err != nil {
		t.Fatal(err)
	}
	key, err := e.CreateEnrollment(ctx, "device")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.EnrollClient(key.Code, "linux"); err != nil {
		t.Fatal(err)
	}
	assertAuditActors(t, e)
}

func TestActorContextFallbackAndLegacyAudit(t *testing.T) {
	if got := ActorFromContext(context.Background()); got != SystemActor("unattributed") {
		t.Fatalf("missing context must be visible: %+v", got)
	}
	var old Audit
	if err := json.Unmarshal([]byte(`{"id":"legacy","action":"settings.update"}`), &old); err != nil || old.Actor != (Actor{}) {
		t.Fatalf("legacy audit no longer readable: %+v %v", old, err)
	}
}

func TestBindingsFileGrantsAdmin(t *testing.T) {
	e := engine(t)
	principal := Principal{Issuer: "https://issuer.example", Subject: "subject"}
	if ok, err := e.IsRecoveryAdmin(principal); err != nil || ok {
		t.Fatalf("absent file grants admin: %v %v", ok, err)
	}
	if err := e.BindAdmin(principal, "Display name"); err != nil {
		t.Fatal(err)
	}
	if err := e.BindAdmin(principal, "Renamed"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.Dir, "admin-bindings.json")
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("bindings permissions: %v %v", stat, err)
	}
	for _, tc := range []struct {
		principal Principal
		want      bool
	}{
		{principal, true},
		{Principal{Issuer: "https://other.example", Subject: principal.Subject}, false},
		{Principal{Issuer: principal.Issuer, Subject: "other"}, false},
	} {
		if ok, err := e.IsRecoveryAdmin(tc.principal); err != nil || ok != tc.want {
			t.Fatalf("binding match %+v: %v %v", tc.principal, ok, err)
		}
	}
	if err := e.UnbindAdmin(principal); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.IsRecoveryAdmin(principal); err != nil || ok {
		t.Fatalf("removed binding still grants admin: %v %v", ok, err)
	}
	if err := e.BindAdmin(Principal{}, "invalid"); err == nil {
		t.Fatal("empty identity accepted")
	}
	if err := os.WriteFile(path, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.IsRecoveryAdmin(principal); err == nil || ok {
		t.Fatalf("malformed bindings must fail closed: %v %v", ok, err)
	}
	if err := e.BindAdmin(principal, "must not overwrite malformed data"); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("malformed file was overwritten", err)
	}
}

func TestHumanDecisionRecordsActor(t *testing.T) {
	e := engine(t)
	r, err := e.Submit(input("actor-decision", "fixture", map[string]any{"value": "safe"}))
	if err != nil || r.Decision != "pending" {
		t.Fatalf("pending fixture: %+v %v", r, err)
	}
	actor := Actor{Issuer: "https://issuer.example", Subject: "approver", Kind: "human"}
	if _, err := e.Decide(WithActor(context.Background(), actor), r.ID, r.Digest, "approve", ""); err != nil {
		t.Fatal(err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if audit.Action == "review.human" {
			if audit.Actor != actor {
				t.Fatalf("human decision actor: %+v", audit.Actor)
			}
			return
		}
	}
	t.Fatal("human decision audit missing")
}

func TestStartupAuditRecordsSystemActor(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Register(Instance{ID: "startup", SessionID: "startup", Cwd: t.TempDir(), HookVersion: Version}); err != nil {
		e.Close()
		t.Fatal(err)
	}
	r, err := e.Submit(ReviewInput{InstanceID: "startup", CallID: "startup", ToolName: "fixture", Arguments: map[string]any{"value": "safe"}})
	if err != nil || r.Decision != "pending" {
		e.Close()
		t.Fatalf("pending fixture: %+v %v", r, err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if audit.Action == "review.restart" {
			if audit.Actor != SystemActor("startup") {
				t.Fatalf("startup actor: %+v", audit.Actor)
			}
			assertAuditActors(t, e)
			return
		}
	}
	t.Fatal("startup path was not exercised")
}
