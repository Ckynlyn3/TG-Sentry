package core

import (
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCredentialRecoveryConcurrencyAndValidation(t *testing.T) {
	t.Setenv("TG_SENTRY_CREDENTIALS_KEK_FILE", "")
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { e.Close() }()
	ctx := WithActor(context.Background(), SystemActor("test"))
	input := Credential{Name: "fixture", Type: "api_key", Env: "FIXTURE_KEY", Bindings: []CredentialBinding{{NodeID: "node", AgentID: "main"}, {NodeID: "node", AgentID: "asserted-other"}}}
	for _, invalid := range []Credential{{Name: "bad name", Type: "api_key", Env: "KEY"}, {Name: "valid", Type: "oauth", Env: "KEY"}, {Name: "valid", Type: "api_key", Env: "bad"}, {Name: "valid", Type: "api_key", Env: "KEY", Bindings: []CredentialBinding{{}}}} {
		if _, err := e.CreateCredential(ctx, invalid, "synthetic"); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	if _, err := e.CreateCredential(ctx, input, ""); err == nil {
		t.Fatal("empty secret accepted")
	}
	// Reuse two writers to exercise serialization, not a performance threshold.
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.CreateCredential(ctx, input, "synthetic-concurrent"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	records, err := e.Credentials()
	if err != nil || len(records) != 2 {
		t.Fatal("concurrent creation failed")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir)
	if err != nil {
		t.Fatal("existing KEK did not recover")
	}
	c := records[0]
	// Authorization is node-level: any process on this node can assert either
	// label that the administrator bound. This is deliberately not attestation.
	if _, err := e.ResolveCredential(c.ID, "node", "asserted-other"); err != nil {
		t.Fatal("same-node assertion denied")
	}
	if _, err := e.RotateCredential(ctx, c.ID, ""); err == nil {
		t.Fatal("empty rotation accepted")
	}
	if _, err := e.RotateCredential(ctx, "missing", "synthetic"); err == nil {
		t.Fatal("missing rotation accepted")
	}
	if err := e.DeleteCredential(ctx, "missing"); err == nil {
		t.Fatal("missing deletion accepted")
	}
	var stored storedCredential
	if err := e.get("credentials", c.ID, &stored); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(stored)
	if bytes.Contains(payload, []byte("synthetic-concurrent")) {
		t.Fatal("plaintext persisted")
	}
	corrupt := stored
	corrupt.Sealed.Ciphertext = bytes.Clone(stored.Sealed.Ciphertext)
	corrupt.Sealed.Ciphertext[0] ^= 1
	if err := e.put("credentials", c.ID, corrupt); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ResolveCredential(c.ID, "node", "main"); err == nil {
		t.Fatal("corrupt payload resolved")
	}
	if err := e.DeleteCredential(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ResolveCredential(c.ID, "node", "main"); err == nil {
		t.Fatal("deleted credential resolved")
	}
	if _, err := credentialAEAD([]byte("short")); err == nil {
		t.Fatal("invalid key length accepted")
	}
	if _, err := sealCredential([]byte("short"), "default", "id", "value"); err == nil {
		t.Fatal("invalid sealing key accepted")
	}
	if _, err := unsealCredential([]byte("short"), "default", "id", sealedValue{}); err == nil {
		t.Fatal("invalid unsealing key accepted")
	}
	// A configured malformed fixture key must fail without replacing it.
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "invalid-fixture.kek")
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TG_SENTRY_CREDENTIALS_KEK_FILE", path)
	if reopened, err := Open(dir); err == nil {
		reopened.Close()
		t.Fatal("configured invalid KEK accepted")
	}
}
