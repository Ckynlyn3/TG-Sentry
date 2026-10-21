package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Credentials are metadata-only, following GitHub Actions' secrets API.
// https://docs.github.com/en/rest/actions/secrets#get-a-repository-secret
// Values never belong in this projection, policy bundles, or audit details.
type CredentialBinding struct {
	NodeID  string `json:"nodeId"`
	AgentID string `json:"agentId"`
}
type Credential struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Type        string              `json:"type"`
	Env         string              `json:"env"`
	Description string              `json:"description"`
	Bindings    []CredentialBinding `json:"bindings"`
	CreatedAt   time.Time           `json:"createdAt"`
	RotatedAt   *time.Time          `json:"rotatedAt,omitempty"`
}
type sealedValue struct {
	DEKWrapped []byte `json:"dekWrapped"`
	Ciphertext []byte `json:"ciphertext"`
}
type storedCredential struct {
	Credential
	Sealed sealedValue `json:"sealed"`
}
type ResolvedCredential struct {
	ID    string `json:"id"`
	Env   string `json:"env"`
	Value string `json:"value"`
}

// SecretResolveLimit is OpenClaw's existing 1 MiB exec-provider output limit.
// https://docs.openclaw.ai/gateway/secrets/secretref-contract
const SecretResolveLimit = 1 << 20

var ErrCredentialDenied = errors.New("credential unavailable for this device and agent")
var credentialName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// OpenClaw env identifier contract, cited in the frozen #45 plan §3.
var credentialEnv = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

// Envelope encryption per https://docs.cloud.google.com/kms/docs/envelope-encryption.
// AES-256 keys; NewGCMWithRandomNonce embeds its nonce, so Seal/Open use nil.
// https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce
func credentialAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("credential key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}
func credentialAAD(tenant, id string) []byte {
	// JSON array is unambiguous even when IDs contain delimiters; tenant and kind
	// are server-owned. Same tuple authenticates both ciphertext and DEK wrap.
	b, _ := json.Marshal([3]string{tenant, "credentials", id})
	return b
}
func sealCredential(kek []byte, tenant, id, value string) (sealedValue, error) {
	wrap, err := credentialAEAD(kek)
	if err != nil {
		return sealedValue{}, err
	}
	dek := make([]byte, 32) // Fresh on every write, including rotation (#45 E3).
	if _, err := rand.Read(dek); err != nil {
		return sealedValue{}, err
	}
	seal, err := credentialAEAD(dek)
	if err != nil {
		return sealedValue{}, err
	}
	aad := credentialAAD(tenant, id)
	return sealedValue{DEKWrapped: wrap.Seal(nil, nil, dek, aad), Ciphertext: seal.Seal(nil, nil, []byte(value), aad)}, nil
}
func unsealCredential(kek []byte, tenant, id string, blob sealedValue) (string, error) {
	wrap, err := credentialAEAD(kek)
	if err != nil {
		return "", err
	}
	aad := credentialAAD(tenant, id)
	dek, err := wrap.Open(nil, nil, blob.DEKWrapped, aad)
	if err != nil {
		return "", errors.New("credential authentication failed")
	}
	seal, err := credentialAEAD(dek)
	if err != nil {
		return "", err
	}
	plaintext, err := seal.Open(nil, nil, blob.Ciphertext, aad)
	if err != nil {
		return "", errors.New("credential authentication failed")
	}
	return string(plaintext), nil
}

// Caller holds e.mu (or the startup process.lock). Reuse the process lock plus
// atomicFile pattern; never replace a missing key while sealed records exist.
func (e *Engine) loadCredentialKey(create bool) error {
	path := os.Getenv("TG_SENTRY_CREDENTIALS_KEK_FILE")
	if path == "" {
		path = filepath.Join(e.Dir, "credentials.kek")
	}
	key, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		records, listErr := e.Credentials()
		if listErr != nil {
			return fmt.Errorf("check sealed credentials: %w", listErr)
		}
		if len(records) != 0 {
			return errors.New("credentials KEK missing: restore the original key before starting")
		}
		if !create {
			return nil
		}
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return fmt.Errorf("generate credentials KEK: %w", err)
		}
		if err = AtomicFile(path, key, 0600); err != nil {
			return fmt.Errorf("write credentials KEK: %w", err)
		}
	} else if err != nil {
		return errors.New("cannot read credentials KEK")
	}
	if len(key) != 32 {
		return errors.New("credentials KEK must contain exactly 32 bytes")
	}
	if err = os.Chmod(path, 0600); err != nil {
		return errors.New("cannot restrict credentials KEK permissions")
	}
	e.credentialsKey = key
	return nil
}
func validateCredential(c Credential, value string) error {
	if !credentialName.MatchString(c.Name) || c.Type != "api_key" || !credentialEnv.MatchString(c.Env) || value == "" {
		return errors.New("invalid credential metadata or missing value")
	}
	// #45 plan §§2–3: a single value must fit both the device HTTP JSON and
	// exec-provider JSON, including their newline and JSON escaping.
	id := c.ID
	if id == "" {
		id = ID() // Same generated ID shape used by CreateCredential below.
	}
	delivery, err := json.Marshal(ResolvedCredential{ID: id, Env: c.Env, Value: value})
	if err != nil || len(delivery)+len("\n") > SecretResolveLimit {
		return errors.New("credential exceeds resolver delivery budget")
	}
	execDelivery, err := json.Marshal(struct {
		ProtocolVersion int               `json:"protocolVersion"`
		Values          map[string]string `json:"values"`
	}{1, map[string]string{id: value}})
	if err != nil || len(execDelivery)+len("\n") > SecretResolveLimit {
		return errors.New("credential exceeds resolver delivery budget")
	}
	for _, b := range c.Bindings {
		if b.NodeID == "" || b.AgentID == "" {
			return errors.New("credential bindings require nodeId and agentId")
		}
	}
	return nil
}
func (e *Engine) Credentials() ([]Credential, error) { return list[Credential](e, "credentials") }
func (e *Engine) Credential(id string) (Credential, error) {
	var c Credential
	err := e.get("credentials", id, &c)
	return c, err
}
func (e *Engine) CreateCredential(ctx context.Context, input Credential, value string) (Credential, error) {
	if err := validateCredential(input, value); err != nil {
		return Credential{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.credentialsKey) == 0 {
		if err := e.loadCredentialKey(true); err != nil {
			return Credential{}, err
		}
	}
	c := input
	c.ID, c.CreatedAt, c.RotatedAt = ID(), e.clock(), nil
	c.Bindings = append([]CredentialBinding{}, input.Bindings...)
	blob, err := sealCredential(e.credentialsKey, eventTenant(), c.ID, value)
	if err != nil {
		return Credential{}, err
	}
	if err := e.change(ctx, "credentials", c.ID, storedCredential{c, blob}, "credential.create", credentialAuditDetail(c)); err != nil {
		return Credential{}, err
	}
	return c, nil
}
func credentialAuditDetail(c Credential) string {
	b, _ := json.Marshal(struct {
		Name, Type, Env string
		Bindings        []CredentialBinding
	}{c.Name, c.Type, c.Env, c.Bindings})
	return string(b) // Never serialize the write request or secret value.
}
func (e *Engine) RotateCredential(ctx context.Context, id, value string) (Credential, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, err := e.Credential(id)
	if err != nil {
		return Credential{}, err
	}
	if err := validateCredential(c, value); err != nil {
		return Credential{}, err
	}
	blob, err := sealCredential(e.credentialsKey, eventTenant(), id, value)
	if err != nil {
		return Credential{}, err
	}
	now := e.clock()
	c.RotatedAt = &now
	if err := e.change(ctx, "credentials", id, storedCredential{c, blob}, "credential.rotate", credentialAuditDetail(c)); err != nil {
		return Credential{}, err
	}
	return c, nil
}
func (e *Engine) DeleteCredential(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.Credential(id); err != nil {
		return err
	}
	return e.change(ctx, "credentials", id, nil, "credential.delete", "")
}
func (e *Engine) ResolveCredential(id, node, agent string) (ResolvedCredential, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var c storedCredential
	if err := e.get("credentials", id, &c); err != nil {
		return ResolvedCredential{}, e.denyCredentialFetch(id, node, agent)
	}
	bound := false
	for _, b := range c.Bindings {
		if node != "" && agent != "" && b.NodeID == node && b.AgentID == agent {
			bound = true
		}
	}
	if !bound {
		return ResolvedCredential{}, e.denyCredentialFetch(id, node, agent)
	}
	value, err := unsealCredential(e.credentialsKey, eventTenant(), id, c.Sealed)
	if err != nil {
		return ResolvedCredential{}, err
	}
	if err := e.auditCredentialFetch("credential.fetch", id, node, agent); err != nil {
		return ResolvedCredential{}, err
	}
	return ResolvedCredential{ID: id, Env: c.Env, Value: value}, nil
}
func (e *Engine) auditCredentialFetch(action, id, node, agent string) error {
	// Audit-only append, following discovery_store.go:109–124; value-free for
	// successes and denials. OWASP Secrets Management Cheat Sheet §2.6.
	// https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html#26-auditing
	audit := Audit{Actor: Actor{Kind: "device", Subject: node}, ID: ID(), Action: action, Subject: id, Detail: "agent=" + agent, CreatedAt: e.clock()}
	return e.put("audit", audit.ID, audit)
}
func (e *Engine) denyCredentialFetch(id, node, agent string) error {
	if err := e.auditCredentialFetch("credential.fetch.denied", id, node, agent); err != nil {
		return fmt.Errorf("%w: denial audit failed: %w", ErrCredentialDenied, err)
	}
	return ErrCredentialDenied
}
