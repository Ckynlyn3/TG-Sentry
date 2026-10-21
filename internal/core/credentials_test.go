package core

import (
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialEnvelope(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, 32)
	blob, err := sealCredential(kek, "default", "same-id", "synthetic-vault-roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	value, err := unsealCredential(kek, "default", "same-id", blob)
	if err != nil || value != "synthetic-vault-roundtrip" {
		t.Fatal("roundtrip failed")
	}
	for _, tc := range []struct {
		name, tenant, id string
		mutate           func(*sealedValue)
	}{
		{"tenant", "other", "same-id", nil},
		{"id", "default", "other-id", nil},
		{"ciphertext", "default", "same-id", func(b *sealedValue) { b.Ciphertext[len(b.Ciphertext)/2] ^= 1 }},
		{"tag", "default", "same-id", func(b *sealedValue) { b.Ciphertext[len(b.Ciphertext)-1] ^= 1 }},
		{"nonce", "default", "same-id", func(b *sealedValue) { b.Ciphertext[0] ^= 1 }},
		{"wrap", "default", "same-id", func(b *sealedValue) { b.DEKWrapped[len(b.DEKWrapped)-1] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := sealedValue{Ciphertext: bytes.Clone(blob.Ciphertext), DEKWrapped: bytes.Clone(blob.DEKWrapped)}
			if tc.mutate != nil {
				tc.mutate(&copy)
			}
			// NIST SP 800-38D §7.2: authentication failure returns FAIL, not plaintext.
			// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
			if value, err := unsealCredential(kek, tc.tenant, tc.id, copy); err == nil || value != "" {
				t.Fatal("tamper accepted or plaintext returned")
			}
		})
	}
	t.Run("wrong-KEK", func(t *testing.T) {
		if value, err := unsealCredential(bytes.Repeat([]byte{8}, len(kek)), "default", "same-id", blob); err == nil || value != "" {
			t.Fatal("wrong KEK accepted or plaintext returned")
		}
	})
}

func TestCredentialDeliveryBudget(t *testing.T) {
	t.Setenv("TG_SENTRY_CREDENTIALS_KEK_FILE", "")
	e, err := Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := WithActor(context.Background(), SystemActor("test"))
	input := Credential{Name: "budget", Type: "api_key", Env: "FIXTURE_KEY", Bindings: []CredentialBinding{{NodeID: "node", AgentID: "agent"}}}
	// Derive the budget from the existing OpenClaw limit and actual JSON framing.
	const limit = SecretResolveLimit
	for _, env := range []string{"A", input.Env, strings.Repeat("E", 128)} { // credentialEnv ceiling.
		for _, unit := range []string{"x", "\n", "<"} {
			input.Env = env
			id := ID()
			frame, _ := json.Marshal(ResolvedCredential{ID: id, Env: env})
			execFrame, _ := json.Marshal(map[string]any{"protocolVersion": 1, "values": map[string]string{id: ""}})
			encodedUnit, _ := json.Marshal(unit)
			available := limit - max(len(frame), len(execFrame)) - len("\n")
			unitBytes := len(encodedUnit) - len(`""`)
			value := strings.Repeat(unit, available/unitBytes) + strings.Repeat("x", available%unitBytes)
			encoded, _ := json.Marshal(ResolvedCredential{ID: id, Env: env, Value: value})
			execEncoded, _ := json.Marshal(map[string]any{"protocolVersion": 1, "values": map[string]string{id: value}})
			if max(len(encoded), len(execEncoded))+len("\n") != limit {
				t.Fatal("boundary setup did not reach delivery limit")
			}
			c, err := e.CreateCredential(ctx, input, value)
			if err != nil {
				t.Fatalf("at-limit create rejected: %v", err)
			}
			if _, err := e.RotateCredential(ctx, c.ID, value); err != nil {
				t.Fatalf("at-limit rotate rejected: %v", err)
			}
			if _, err := e.CreateCredential(ctx, input, value+"x"); err == nil {
				t.Error("limit+1 create accepted")
			}
			if _, err := e.RotateCredential(ctx, c.ID, value+"x"); err == nil {
				t.Error("limit+1 rotate accepted")
			}
			resolved, err := e.ResolveCredential(c.ID, "node", "agent")
			if err != nil || resolved.Value != value {
				t.Fatal("failed rotation changed deliverable value")
			}
		}
	}
}

func TestCredentialDenialAudit(t *testing.T) {
	t.Setenv("TG_SENTRY_CREDENTIALS_KEK_FILE", "")
	e, err := Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	secret := "synthetic-denial-audit-secret"
	c, err := e.CreateCredential(WithActor(context.Background(), SystemActor("test")), Credential{Name: "audit", Type: "api_key", Env: "FIXTURE_KEY", Bindings: []CredentialBinding{{NodeID: "node", AgentID: "agent"}}}, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, node, agent string }{{"unknown", "node", "agent"}, {c.ID, "other", "agent"}, {c.ID, "node", "other"}} {
		before, err := e.Audits()
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := e.ResolveCredential(tc.id, tc.node, tc.agent)
		if !errors.Is(err, ErrCredentialDenied) || resolved != (ResolvedCredential{}) {
			t.Fatal("denial error or plaintext response not uniform")
		}
		after, err := e.Audits()
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before)+1 {
			t.Fatal("denied resolve audit missing")
		}
		found := false
		for _, a := range after {
			if a.Action == "credential.fetch.denied" && a.Subject == tc.id && a.Actor == (Actor{Kind: "device", Subject: tc.node}) && a.Detail == "agent="+tc.agent {
				found = true
			}
			encoded, _ := json.Marshal(a)
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("denial audit leaked value")
			}
		}
		if !found {
			t.Fatal("value-free device denial audit missing")
		}
	}
}

func TestCredentialLifecycleAndKEK(t *testing.T) {
	t.Setenv("TG_SENTRY_CREDENTIALS_KEK_FILE", "")
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithActor(context.Background(), SystemActor("test"))
	input := Credential{Name: "fixture", Type: "api_key", Env: "FIXTURE_KEY", Bindings: []CredentialBinding{{NodeID: "node", AgentID: "agent"}}}
	first, err := e.CreateCredential(ctx, input, "synthetic-secret-first")
	if err != nil {
		t.Fatal(err)
	}
	var before storedCredential
	if err := e.get("credentials", first.ID, &before); err != nil {
		t.Fatal(err)
	}
	rotated, err := e.RotateCredential(ctx, first.ID, "synthetic-secret-second")
	if err != nil || rotated.ID != first.ID {
		t.Fatal("rotation failed")
	}
	var after storedCredential
	if err := e.get("credentials", first.ID, &after); err != nil {
		t.Fatal(err)
	}
	wrap, err := credentialAEAD(e.credentialsKey)
	if err != nil {
		t.Fatal(err)
	}
	aad := credentialAAD(eventTenant(), first.ID)
	beforeDEK, err := wrap.Open(nil, nil, before.Sealed.DEKWrapped, aad)
	if err != nil {
		t.Fatal(err)
	}
	afterDEK, err := wrap.Open(nil, nil, after.Sealed.DEKWrapped, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(beforeDEK, afterDEK) {
		t.Fatal("DEK reused")
	}
	for _, pair := range [][2]string{{"other", "agent"}, {"node", "other"}} {
		if _, err := e.ResolveCredential(first.ID, pair[0], pair[1]); err == nil {
			t.Fatal("unbound access")
		}
	}
	resolved, err := e.ResolveCredential(first.ID, "node", "agent")
	if err != nil || resolved.Value != "synthetic-secret-second" {
		t.Fatal("resolution failed")
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range audits {
		if a.Action == "credential.fetch" {
			found = a.Actor.Kind == "device" && a.Actor.Subject == "node"
		}
	}
	if !found {
		t.Fatal("device audit missing")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.kek")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("KEK permissions")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir); err == nil {
		reopened.Close()
		t.Fatal("generated KEK over sealed records")
	}
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir); err == nil {
		reopened.Close()
		t.Fatal("accepted invalid KEK")
	}
}
