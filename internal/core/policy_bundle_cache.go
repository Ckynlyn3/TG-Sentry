package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Reuse the bridge's existing 2 MiB JSON response budget, not a new policy limit.
const PolicyBundleMaxBytes = 2 << 20

// DecodePolicyBundle bounds both HTTP and disk input. The extra byte detects
// overflow rather than accepting a valid prefix followed by truncated padding.
// Callers must still verify the detached signature before trusting any payload.
func DecodePolicyBundle(r io.Reader) (SignedPolicyBundle, error) {
	data, err := io.ReadAll(io.LimitReader(r, PolicyBundleMaxBytes+1))
	if err != nil {
		return SignedPolicyBundle{}, err
	}
	if len(data) > PolicyBundleMaxBytes {
		return SignedPolicyBundle{}, errors.New("policy bundle exceeds response budget")
	}
	var signed SignedPolicyBundle
	if err = json.Unmarshal(data, &signed); err != nil {
		return SignedPolicyBundle{}, err
	}
	return signed, nil
}

// ReadPolicyBundle follows connection.json's regular-file checks. Always verify
// persisted bytes against the enrollment-pinned key before trusting the cache.
func ReadPolicyBundle(path string, publicKey []byte, nodeID string) (SignedPolicyBundle, error) {
	signed, _, err := readSignedPolicyCache(path)
	if err != nil {
		return SignedPolicyBundle{}, err
	}
	if _, err = VerifyPolicyBundle(signed, publicKey, nodeID); err != nil {
		return SignedPolicyBundle{}, err
	}
	return signed, nil
}

// The local envelope preserves the optional keyId independently of the exact
// signed payload. A missing hint remains valid for pre-rotation caches.
type policyCacheEnvelope struct {
	SignedPolicyBundle
	KeyID string `json:"keyId,omitempty"`
}

func readPolicyCacheBytes(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("policy cache must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("policy cache must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, PolicyBundleMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > PolicyBundleMaxBytes {
		return nil, errors.New("policy cache exceeds response budget")
	}
	return data, nil
}

func readSignedPolicyCache(path string) (SignedPolicyBundle, string, error) {
	data, err := readPolicyCacheBytes(path)
	if err != nil {
		return SignedPolicyBundle{}, "", err
	}
	var envelope policyCacheEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return SignedPolicyBundle{}, "", err
	}
	return envelope.SignedPolicyBundle, envelope.KeyID, nil
}

func CachePolicyBundle(path string, signed SignedPolicyBundle, publicKey []byte, nodeID string) (PolicyBundle, error) {
	bundle, err := VerifyPolicyBundle(signed, publicKey, nodeID)
	if err != nil {
		return PolicyBundle{}, err
	}
	lock, err := lockPolicyCache(path)
	if err != nil {
		return PolicyBundle{}, err
	}
	defer lock.Close()
	previous, err := ReadPolicyBundle(path, publicKey, nodeID)
	if err == nil {
		trusted, err := VerifyPolicyBundle(previous, publicKey, nodeID)
		if err != nil {
			return PolicyBundle{}, err
		}
		if err := checkPolicyCacheRevision(bundle, signed, trusted, previous); err != nil {
			return PolicyBundle{}, err
		}
	} else if !os.IsNotExist(err) {
		return PolicyBundle{}, err
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return PolicyBundle{}, err
	}
	if len(data) > PolicyBundleMaxBytes {
		return PolicyBundle{}, errors.New("policy bundle exceeds response budget")
	}
	if err = AtomicFile(path, data, 0600); err != nil {
		return PolicyBundle{}, err
	}
	return bundle, nil
}

// Reuse the installer's cross-platform nonblocking lock for both files. Every
// writer compares against the latest durable state, never a caller's stale copy.
func lockPolicyCache(path string) (*os.File, error) {
	lockPath := path + ".lock"
	if st, err := os.Lstat(lockPath); err == nil && !st.Mode().IsRegular() {
		return nil, errors.New("policy cache lock must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockProcessFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("policy cache busy: %w", err)
	}
	return lock, nil
}

func policyTrustPath(bundlePath string) string {
	return filepath.Join(filepath.Dir(bundlePath), "trust.json")
}

// TUF §5.4.3.2: new version >= trusted version. Equal versions preserve identity
// per §5.4.3.1; re-signing identical payload bytes never resets the revision floor.
// https://theupdateframework.github.io/specification/latest/
func checkPolicyCacheRevision(bundle PolicyBundle, signed SignedPolicyBundle, trusted PolicyBundle, previous SignedPolicyBundle) error {
	if bundle.Revision < trusted.Revision || (bundle.Revision == trusted.Revision && !bytes.Equal(signed.Payload, previous.Payload)) {
		return errors.New("policy bundle rollback or revision conflict")
	}
	return nil
}

// ReadPolicyTrust loads private local state, structurally validated by S1 rather
// than re-verifying discarded predecessors. A missing file alone uses bootstrap;
// corrupt or downgraded state never resets the trusted version or revision floor.
func ReadPolicyTrust(bundlePath string, bootstrap TrustState) (TrustState, error) {
	anchor, _, err := parseTrustState(bootstrap)
	if err != nil {
		return TrustState{}, fmt.Errorf("policy trust bootstrap: %w", err)
	}
	data, err := readPolicyCacheBytes(policyTrustPath(bundlePath))
	if os.IsNotExist(err) {
		return bootstrap, nil
	}
	if err != nil {
		return TrustState{}, err
	}
	var state TrustState
	if err := json.Unmarshal(data, &state); err != nil {
		return TrustState{}, fmt.Errorf("decode policy trust state: %w", err)
	}
	current, _, err := parseTrustState(state)
	if err != nil {
		return TrustState{}, err
	}
	if current.Version < anchor.Version {
		return TrustState{}, errors.New("policy trust version below bootstrap")
	}
	return state, nil
}

// CachePolicyTrustRecord persists exactly one verified N+1 before the next fetch
// (TUF §5.3). D6 retains the existing cache record across arbitrarily long catch-up.
func CachePolicyTrustRecord(bundlePath string, next SignedTrustRecord, bootstrap TrustState, nodeID string) (TrustState, error) {
	lock, err := lockPolicyCache(bundlePath)
	if err != nil {
		return TrustState{}, err
	}
	defer lock.Close()
	state, err := ReadPolicyTrust(bundlePath, bootstrap)
	if err != nil {
		return TrustState{}, err
	}
	state, err = recoverPolicyCacheTrust(bundlePath, state, nodeID)
	if err != nil {
		return TrustState{}, err
	}
	state, err = AdvanceTrustState(state, next)
	if err != nil {
		return TrustState{}, err
	}
	if err := AtomicFile(policyTrustPath(bundlePath), mustJSON(state), 0600); err != nil {
		return TrustState{}, fmt.Errorf("write policy trust state: %w", err)
	}
	return state, nil
}

// Recover a crash after bundle replacement but before pruning. If the bundle
// no longer verifies cache but does verify current, current must become the next
// cache anchor. Otherwise D6 keeps the existing cache record unchanged.
func recoverPolicyCacheTrust(path string, state TrustState, nodeID string) (TrustState, error) {
	if state.Cache == nil {
		return state, nil
	}
	signed, keyID, err := readSignedPolicyCache(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return TrustState{}, err
	}
	if _, _, err := VerifyCachedPolicyBundle(signed, keyID, TrustState{Current: *state.Cache}, nodeID); err == nil {
		return state, nil
	}
	if compacted, err := TrustStateAfterBundle(state, signed, keyID, nodeID); err == nil {
		return compacted, nil
	}
	// Neither authority verified: never discard records or adopt the bad bundle.
	// Cache acceptance still fails closed; the revision floor is not reset.
	return state, nil
}

// ReadPolicyBundleWithTrust is local-cache acceptance (current ∪ cache), never
// network acceptance. Its verified signer also covers envelopes without keyId.
func ReadPolicyBundleWithTrust(path string, state TrustState, nodeID string) (SignedPolicyBundle, string, error) {
	signed, keyID, err := readSignedPolicyCache(path)
	if err != nil {
		return SignedPolicyBundle{}, "", err
	}
	_, signer, err := VerifyCachedPolicyBundle(signed, keyID, state, nodeID)
	if err != nil {
		return SignedPolicyBundle{}, "", err
	}
	return signed, signer, nil
}

// CachePolicyBundleWithTrust verifies network authority against current only,
// then enforces the durable old cache's revision floor. D6 drops cache authority
// only AFTER the re-signed bundle is written; a crash between writes is safe.
func CachePolicyBundleWithTrust(path string, signed SignedPolicyBundle, keyID string, bootstrap TrustState, nodeID string) (PolicyBundle, error) {
	lock, err := lockPolicyCache(path)
	if err != nil {
		return PolicyBundle{}, err
	}
	defer lock.Close()
	state, err := ReadPolicyTrust(path, bootstrap)
	if err != nil {
		return PolicyBundle{}, err
	}
	current, _, err := parseTrustState(state)
	if err != nil {
		return PolicyBundle{}, err
	}
	bundle, _, err := VerifyPolicyBundleWithTrust(signed, keyID, current, nodeID)
	if err != nil {
		return PolicyBundle{}, err
	}
	previous, previousID, err := ReadPolicyBundleWithTrust(path, state, nodeID)
	if err == nil {
		trusted, _, err := VerifyCachedPolicyBundle(previous, previousID, state, nodeID)
		if err != nil {
			return PolicyBundle{}, err
		}
		if err := checkPolicyCacheRevision(bundle, signed, trusted, previous); err != nil {
			return PolicyBundle{}, err
		}
	} else if !os.IsNotExist(err) {
		return PolicyBundle{}, err
	}
	if err := writePolicyBundleWithTrust(path, signed, keyID, state, nodeID); err != nil {
		return PolicyBundle{}, err
	}
	return bundle, nil
}

// Caller holds bundle.json.lock through both durable replacements.
func writePolicyBundleWithTrust(path string, signed SignedPolicyBundle, keyID string, state TrustState, nodeID string) error {
	data, err := json.Marshal(policyCacheEnvelope{SignedPolicyBundle: signed, KeyID: keyID})
	if err != nil {
		return err
	}
	if len(data) > PolicyBundleMaxBytes {
		return errors.New("policy bundle exceeds response budget")
	}
	// Establish the bootstrap on disk before installing a first bundle.
	if _, err := os.Stat(policyTrustPath(path)); os.IsNotExist(err) {
		if err := AtomicFile(policyTrustPath(path), mustJSON(state), 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := AtomicFile(path, data, 0600); err != nil {
		return err
	}
	state, err = TrustStateAfterBundle(state, signed, keyID, nodeID)
	if err != nil {
		return err
	}
	if err := AtomicFile(policyTrustPath(path), mustJSON(state), 0600); err != nil {
		return err
	}
	return nil
}

// Like client uninstall's resource hashes, remove only a cache verifiably owned
// by the installed connection. A new enrollment must not inherit the old node's
// high-water mark. Keep the lock inode stable, as for client.lock.
func removeClientPolicyBundle(dir, connectionHash string) []string {
	return removeClientPolicyState(dir, connectionHash)
}
