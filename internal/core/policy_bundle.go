package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// PolicyBundle is the shared server/endpoint contract, not an OPA tarball.
// Named local format single-json-bundle: encoding/json's deterministic struct
// fields and the runtime selector's deterministic rule sequence; RFC 8032
// Ed25519 signs these exact UTF-8 bytes.
// Unlike OPA's multi-file hash manifest, this single file needs no hash indirection.
// https://www.openpolicyagent.org/docs/management-bundles#signature-verification
// No expiry: ARCHITECTURE §2.3 / issue #15 deliberately chooses none.
type PolicyBundle struct {
	Revision int    `json:"revision"`
	NodeID   string `json:"nodeId"`
	Rules    []Rule `json:"rules"`
}

// []byte uses JSON base64: transporting opaque signed bytes avoids JSON
// reformatting by an envelope serializer invalidating a detached signature.
type SignedPolicyBundle struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
	KeyID     string `json:"keyId,omitempty"`
}

// PolicyBundleETag is a strong content validator (RFC 9110 §8.8.3). Revision
// and node identity are inside the signed payload; signatures are deterministic.
func PolicyBundleETag(s SignedPolicyBundle) string {
	sum := sha256.Sum256(s.Payload)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// Startup and operator mutation run under Open's existing process lock. No
// hot reload: the committed manifest alone selects the signer (issue #65 §3.3).
func (e *Engine) loadBundleKey() error {
	manifest, err := e.readBundleManifest()
	if os.IsNotExist(err) {
		keyPath := filepath.Join(e.Dir, "bundle-signing.key")
		if _, err = os.Stat(keyPath); os.IsNotExist(err) {
			_, key, generateErr := ed25519.GenerateKey(rand.Reader)
			if generateErr != nil {
				return generateErr
			}
			if err = AtomicFile(keyPath, key, 0600); err != nil {
				return err
			}
		}
		key, err := readBundlePrivateKey(keyPath)
		if err != nil {
			return err
		}
		pub := key.Public().(ed25519.PublicKey)
		record, err := SignTrustRecord(TrustRecord{Version: 1, Keys: []TrustKey{{KeyID: BundleKeyID(pub), PublicKey: pub}}}, key)
		if err != nil {
			return err
		}
		manifest = bundleManifest{Records: []SignedTrustRecord{record}, Signer: BundleKeyID(pub)}
		if err = e.writeBundleManifest(manifest, AtomicFile); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("load bundle manifest: %w", err)
	}
	key, err := e.loadManifestKeys(manifest)
	if err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(e.Dir, "bundle-trust.json"), 0600); err != nil {
		return err
	}
	if err := e.reportBundleOrphans(manifest); err != nil {
		return err
	}
	e.bundleKey, e.bundleManifest = key, manifest
	return nil
}

func readBundlePrivateKey(path string) (ed25519.PrivateKey, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load bundle signing key: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) {
		return nil, errors.New("invalid bundle signing key")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(key), nil
}

func validateBundleManifest(manifest bundleManifest) (TrustRecord, error) {
	if len(manifest.Records) == 0 {
		return TrustRecord{}, errors.New("empty bundle trust history")
	}
	first, err := parseTrustRecord(manifest.Records[0])
	if err != nil {
		return TrustRecord{}, err
	}
	if first.Version != 1 || len(first.Keys) != 1 {
		return TrustRecord{}, errors.New("invalid initial bundle trust record")
	}
	current, err := VerifyTrustBootstrap(manifest.Records[0], first.Keys[0].PublicKey)
	if err != nil {
		return TrustRecord{}, err
	}
	for _, next := range manifest.Records[1:] {
		current, err = VerifyTrustRecord(next, current)
		if err != nil {
			return TrustRecord{}, err
		}
	}
	for _, key := range current.Keys {
		if key.KeyID == manifest.Signer {
			return current, nil
		}
	}
	return TrustRecord{}, errors.New("bundle signer is not in current trust record")
}

// Only v1's original key can fall back to the legacy filename. A manifest keyId
// is validated before being interpolated into a path; file content must match it.
func (e *Engine) bundlePrivateKeyPath(id string, manifest bundleManifest) string {
	path := filepath.Join(e.Dir, "bundle-signing."+id+".key")
	first, _ := parseTrustRecord(manifest.Records[0])
	if id == first.Keys[0].KeyID {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return filepath.Join(e.Dir, "bundle-signing.key")
		}
	}
	return path
}

func (e *Engine) loadManifestKeys(manifest bundleManifest) (ed25519.PrivateKey, error) {
	current, err := validateBundleManifest(manifest)
	if err != nil {
		return nil, err
	}
	var signer ed25519.PrivateKey
	for _, trusted := range current.Keys {
		key, err := readBundlePrivateKey(e.bundlePrivateKeyPath(trusted.KeyID, manifest))
		if err != nil {
			return nil, err
		}
		if BundleKeyID(key.Public().(ed25519.PublicKey)) != trusted.KeyID {
			return nil, errors.New("bundle private key identity mismatch")
		}
		if trusted.KeyID == manifest.Signer {
			signer = key
		}
	}
	return signer, nil
}

func (e *Engine) reportBundleOrphans(manifest bundleManifest) error {
	referenced := map[string]bool{}
	for _, signed := range manifest.Records {
		record, err := parseTrustRecord(signed)
		if err != nil {
			return err
		}
		for _, key := range record.Keys {
			referenced["bundle-signing."+key.KeyID+".key"] = true
		}
	}
	entries, err := os.ReadDir(e.Dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "bundle-signing.") && strings.HasSuffix(name, ".key") && name != "bundle-signing.key" && !referenced[name] {
			log.Printf("unreferenced bundle signing key retained: %s", name)
		}
	}
	return nil
}

func (e *Engine) BundleTrustVersion() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.bundleManifest.Records)
}

// BundleTrustRecord returns a detached snapshot. The handler maps ErrNotExist to
// 404; no caller may mutate the Engine's committed history through this accessor.
func (e *Engine) BundleTrustRecord(version int) (SignedTrustRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if version < 1 || version > len(e.bundleManifest.Records) {
		return SignedTrustRecord{}, os.ErrNotExist
	}
	return cloneSignedTrustRecord(e.bundleManifest.Records[version-1]), nil
}

func (e *Engine) RotateBundleKey() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	current, err := validateBundleManifest(e.bundleManifest)
	if err != nil {
		return err
	}
	if len(current.Keys) != 1 {
		return errors.New("retire the previous bundle key before rotating again")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public := key.Public().(ed25519.PublicKey)
	return e.appendBundleTrust(append(current.Keys, TrustKey{KeyID: BundleKeyID(public), PublicKey: public}), key)
}

func (e *Engine) RetireBundleKey(keyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	current, err := validateBundleManifest(e.bundleManifest)
	if err != nil {
		return err
	}
	if keyID == e.bundleManifest.Signer {
		return errors.New("cannot retire the current bundle signer")
	}
	keys := []TrustKey{}
	found := false
	for _, key := range current.Keys {
		if key.KeyID == keyID {
			found = true
		} else {
			keys = append(keys, key)
		}
	}
	if !found {
		return errors.New("bundle key is not current")
	}
	return e.appendBundleTrust(keys, nil)
}

// Caller holds e.mu. Version validation also rejects integer overflow in N+1.
func (e *Engine) appendBundleTrust(keys []TrustKey, newKey ed25519.PrivateKey) error {
	signer, signingKeys := e.bundleManifest.Signer, []ed25519.PrivateKey{e.bundleKey}
	if newKey != nil {
		signer = BundleKeyID(newKey.Public().(ed25519.PublicKey))
		signingKeys = append(signingKeys, newKey)
	}
	record, err := SignTrustRecord(TrustRecord{Version: len(e.bundleManifest.Records) + 1, Keys: keys}, signingKeys...)
	if err != nil {
		return err
	}
	records := append(append([]SignedTrustRecord(nil), e.bundleManifest.Records...), record)
	return e.commitBundleManifest(bundleManifest{Records: records, Signer: signer}, newKey, AtomicFile)
}

// Key data + directory sync precede validation and the manifest commit. A failed
// write never activates in-memory state. Post-rename fsync errors have ambiguous
// durability: return the error and let the stopped-server CLI exit; restart reads
// the actual manifest, never guesses or rolls back over possibly committed bytes.
func (e *Engine) commitBundleManifest(manifest bundleManifest, newKey ed25519.PrivateKey, write func(string, []byte, os.FileMode) error) error {
	if _, err := validateBundleManifest(manifest); err != nil {
		return err
	}
	if newKey != nil {
		if len(newKey) != ed25519.PrivateKeySize {
			return errors.New("invalid new bundle signing key")
		}
		id := BundleKeyID(newKey.Public().(ed25519.PublicKey))
		if id != manifest.Signer {
			return errors.New("new bundle key is not manifest signer")
		}
		if err := write(filepath.Join(e.Dir, "bundle-signing."+id+".key"), newKey, 0600); err != nil {
			return err
		}
	}
	key, err := e.loadManifestKeys(manifest)
	if err != nil {
		return err
	}
	// Prove that the loaded signer signs, not merely that its length is valid.
	probe := ed25519.Sign(key, manifest.Records[len(manifest.Records)-1].Payload)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), manifest.Records[len(manifest.Records)-1].Payload, probe) {
		return errors.New("bundle signer self-check failed")
	}
	if err := e.writeBundleManifest(manifest, write); err != nil {
		return err
	}
	e.bundleKey, e.bundleManifest = key, manifest
	return nil
}

func (e *Engine) ClientPolicyBundle(nodeID string) (SignedPolicyBundle, error) {
	// ponytail: existing single-writer mutex gives a coherent revision/rule/scope
	// snapshot; multi-writer control planes require transaction-level snapshots.
	e.mu.Lock()
	defer e.mu.Unlock()
	var node ClientNode
	if nodeID == "" || e.get("client_nodes", nodeID, &node) != nil || node.Revoked {
		return SignedPolicyBundle{}, errors.New("device unavailable")
	}
	rules, err := e.Rules()
	if err != nil {
		return SignedPolicyBundle{}, err
	}
	scopes, err := e.Scopes()
	if err != nil {
		return SignedPolicyBundle{}, err
	}
	applicable := []Scope{}
	for _, scope := range scopes {
		if scope.NodeID == nodeID {
			applicable = append(applicable, scope)
		}
	}
	rules, err = e.protectionRules(rules, applicable, nodeID)
	if err != nil {
		return SignedPolicyBundle{}, err
	}
	// Settings.Version advances atomically with rule, scope/binding, protection
	// template/policy/tag confirmation and settings writes (store.change), plus
	// builtin upgrades (upgradeBuiltinRules). Use Submit's exact shared selector.
	payload, err := json.Marshal(PolicyBundle{Revision: e.Settings.Version, NodeID: nodeID, Rules: rules})
	if err != nil {
		return SignedPolicyBundle{}, err
	}
	return SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(e.bundleKey, payload), KeyID: e.bundleManifest.Signer}, nil
}

func VerifyPolicyBundle(s SignedPolicyBundle, publicKey []byte, nodeID string) (PolicyBundle, error) {
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, s.Payload, s.Signature) {
		return PolicyBundle{}, errors.New("invalid policy bundle signature")
	}
	var bundle PolicyBundle
	if err := json.Unmarshal(s.Payload, &bundle); err != nil {
		return PolicyBundle{}, fmt.Errorf("decode signed policy bundle: %w", err)
	}
	if nodeID == "" || bundle.NodeID != nodeID || bundle.Revision < 1 || bundle.Rules == nil {
		return PolicyBundle{}, errors.New("invalid policy bundle identity or revision")
	}
	return bundle, nil
}

// PolicyBundleDeny cannot authorize an offline call. Reuse the native local
// matcher (including local symlink resolution) with reject rules only. The
// existing bridge failure default still rejects non-matches and cached permits.
func PolicyBundleDeny(bundle PolicyBundle, in ReviewInput, cwd string) *Decision {
	rules := []Rule{}
	for _, saved := range bundle.Rules {
		rule := normalizeRule(saved)
		if rule.Decision == "reject" {
			rules = append(rules, rule)
		}
	}
	return evaluateAt(in, rules, cwd)
}
