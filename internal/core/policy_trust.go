package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Named local key-set bound (issue #65 §9.2). A transition can contain the
// union of two such sets, hence at most four distinct Ed25519 signatures.
const maxTrustKeys = 2
const maxTrustSignatures = 2 * maxTrustKeys

// TrustKey binds an Ed25519 public key to its exact BundleKeyID.
type TrustKey struct {
	KeyID     string `json:"keyId"`
	PublicKey []byte `json:"publicKey"`
}

// TrustRecord is the Engine-wide key set, not a node-specific policy. TUF §4.3
// and §5.3 supply the sequential-version/old-and-new-authority rules.
// https://theupdateframework.github.io/specification/latest/#update-root
// Named local exception (issue #65 §9.2): at most two keys, threshold one.
type TrustRecord struct {
	Version int        `json:"version"`
	Keys    []TrustKey `json:"keys"`
}

type TrustSignature struct {
	KeyID     string `json:"keyId"`
	Signature []byte `json:"signature"`
}

// SignedTrustRecord transports exact signed bytes as JSON base64, just like
// SignedPolicyBundle. Signatures may include a previous key absent from Payload.
type SignedTrustRecord struct {
	Payload    []byte           `json:"payload"`
	Signatures []TrustSignature `json:"signatures"`
}

// TrustState is trusted local state, not a network bootstrap. D6 of issue #65
// retains at most current + cache: TUF §5.3 replaces the current root, while the
// named local cache exception (§3.5/§9.5) retains the old cache's authority until
// a current-key bundle is durably installed. Cache is omitted when equal to Current.
type TrustState struct {
	Current SignedTrustRecord  `json:"current"`
	Cache   *SignedTrustRecord `json:"cache,omitempty"`
}

// BundleKeyID is the named local full-SHA-256 identifier (issue #65 §9.1),
// following Go note key hashes and RFC 7517 §4.5's optional key selection hint.
// An invalid Ed25519 key has no identifier.
func BundleKeyID(publicKey []byte) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func validateTrustRecord(record TrustRecord) error {
	// Named local bound, issue #65 §9.2, not a general TUF limit.
	if record.Version < 1 || len(record.Keys) < 1 || len(record.Keys) > maxTrustKeys {
		return errors.New("invalid trust version or key count")
	}
	seen := make(map[string]bool, len(record.Keys))
	for _, key := range record.Keys {
		if key.KeyID == "" || BundleKeyID(key.PublicKey) != key.KeyID || seen[key.KeyID] {
			return errors.New("invalid or duplicate trust key")
		}
		seen[key.KeyID] = true
	}
	return nil
}

// TrustRecordBytes uses the existing named local single-json-bundle format:
// compact json.Marshal of ordered struct fields, not TUF canonical JSON. RFC
// 8032 Ed25519 signs these exact bytes; key order is preserved, not re-sorted.
func TrustRecordBytes(record TrustRecord) ([]byte, error) {
	if err := validateTrustRecord(record); err != nil {
		return nil, err
	}
	return json.Marshal(record)
}

// validateTrustSignatures rejects duplicate keyids like python-tuf Metadata.from_dict:
// https://github.com/theupdateframework/python-tuf/blob/80f6126e277120f216bbc8023efcc4809727240a/tuf/api/metadata.py#L193-L201
// Fixed keyId/signature lengths and the old/new union bound prevent unsigned
// envelope padding from defeating D6. With no records, validate only structure
// for trusted persisted state whose immediate predecessors are no longer kept.
func validateTrustSignatures(signed SignedTrustRecord, records ...TrustRecord) error {
	limit := maxTrustSignatures
	allowed := make(map[string]bool)
	for _, record := range records {
		for _, key := range record.Keys {
			allowed[key.KeyID] = true
		}
	}
	if len(records) != 0 {
		limit = len(allowed)
	}
	if len(signed.Signatures) > limit {
		return errors.New("too many trust signatures")
	}
	seen := make(map[string]bool, len(signed.Signatures))
	for _, signature := range signed.Signatures {
		id := signature.KeyID
		if len(id) != hex.EncodedLen(sha256.Size) || len(signature.Signature) != ed25519.SignatureSize {
			return errors.New("invalid trust signature keyId or length")
		}
		decoded, err := hex.DecodeString(id)
		if err != nil || hex.EncodeToString(decoded) != id || seen[id] {
			return errors.New("malformed or duplicate trust signature keyId")
		}
		if len(records) != 0 && !allowed[id] {
			return errors.New("trust signature keyId outside applicable key sets")
		}
		seen[id] = true
	}
	return nil
}

// parseTrustRecord validates representation only, never authority. Its callers
// must already trust the local record or verify signatures/bootstrap separately.
func parseTrustRecord(signed SignedTrustRecord) (TrustRecord, error) {
	if len(signed.Payload) > PolicyBundleMaxBytes {
		return TrustRecord{}, errors.New("trust record exceeds response budget")
	}
	if err := validateTrustSignatures(signed); err != nil {
		return TrustRecord{}, err
	}
	var record TrustRecord
	if err := json.Unmarshal(signed.Payload, &record); err != nil {
		return TrustRecord{}, fmt.Errorf("decode trust record: %w", err)
	}
	canonical, err := TrustRecordBytes(record)
	if err != nil {
		return TrustRecord{}, err
	}
	if !bytes.Equal(canonical, signed.Payload) {
		return TrustRecord{}, errors.New("noncanonical trust record")
	}
	return record, nil
}

// SignTrustRecord signs once per distinct key. Previous-set keys need not occur
// in the new record (TUF §5.3). Private-key validation mirrors loadBundleKey.
func SignTrustRecord(record TrustRecord, privateKeys ...ed25519.PrivateKey) (SignedTrustRecord, error) {
	payload, err := TrustRecordBytes(record)
	if err != nil {
		return SignedTrustRecord{}, err
	}
	if len(privateKeys) == 0 {
		return SignedTrustRecord{}, errors.New("trust record requires a signer")
	}
	signed := SignedTrustRecord{Payload: payload, Signatures: []TrustSignature{}}
	seen := make(map[string]bool, len(privateKeys))
	for _, key := range privateKeys {
		if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) {
			return SignedTrustRecord{}, errors.New("invalid trust signing key")
		}
		id := BundleKeyID(key.Public().(ed25519.PublicKey))
		if !seen[id] {
			signed.Signatures = append(signed.Signatures, TrustSignature{KeyID: id, Signature: ed25519.Sign(key, payload)})
			seen[id] = true
		}
	}
	if _, err := parseTrustRecord(signed); err != nil {
		return SignedTrustRecord{}, err
	}
	return signed, nil
}

// hasTrustSignature applies TUF §4.3/§5.3's distinct-key counting. The approved
// threshold is one in each set; repeated signatures cannot add any authority.
// One key shared by both sets may satisfy both thresholds (including retirement).
func hasTrustSignature(signed SignedTrustRecord, record TrustRecord) bool {
	for _, key := range record.Keys {
		for _, signature := range signed.Signatures {
			if signature.KeyID == key.KeyID && ed25519.Verify(key.PublicKey, signed.Payload, signature.Signature) {
				return true
			}
		}
	}
	return false
}

// VerifyTrustRecord accepts only N+1 signed under both the previous and new key
// sets, following TUF §5.3. It never bootstraps trust from an unsigned network record.
// The caller must persist this accepted step before requesting another one.
func VerifyTrustRecord(next SignedTrustRecord, previous TrustRecord) (TrustRecord, error) {
	if err := validateTrustRecord(previous); err != nil {
		return TrustRecord{}, fmt.Errorf("previous trust record: %w", err)
	}
	record, err := parseTrustRecord(next)
	if err != nil {
		return TrustRecord{}, err
	}
	// Subtraction after the ordered comparison avoids N+1 integer overflow.
	if record.Version <= previous.Version || record.Version-previous.Version != 1 {
		return TrustRecord{}, errors.New("trust record must be the next version")
	}
	if err := validateTrustSignatures(next, previous, record); err != nil {
		return TrustRecord{}, err
	}
	if !hasTrustSignature(next, previous) || !hasTrustSignature(next, record) {
		return TrustRecord{}, errors.New("trust record lacks previous or new key authority")
	}
	return record, nil
}

// VerifyTrustBootstrap validates an authenticated enrollment snapshot (issue #65
// §3.4): the enrollment pin must be a member and the new set must self-sign.
// The authenticated enrollment channel supplies the previous-set authority;
// this function must not be used to adopt unauthenticated network records.
func VerifyTrustBootstrap(signed SignedTrustRecord, pin []byte) (TrustRecord, error) {
	record, err := parseTrustRecord(signed)
	if err != nil {
		return TrustRecord{}, err
	}
	if err := validateTrustSignatures(signed, record); err != nil {
		return TrustRecord{}, err
	}
	for _, key := range record.Keys {
		if key.KeyID == BundleKeyID(pin) && hasTrustSignature(signed, record) {
			return record, nil
		}
	}
	return TrustRecord{}, errors.New("trust bootstrap pin or signature mismatch")
}

// LegacyTrustState locally synthesizes implicit v1 from the already-enrolled
// pin, per issue #65 §3.4. No signature can be manufactured from a public key;
// this anchor is never a signed network bootstrap or successor record.
func LegacyTrustState(pin []byte) (TrustState, error) {
	payload, err := TrustRecordBytes(TrustRecord{Version: 1, Keys: []TrustKey{{KeyID: BundleKeyID(pin), PublicKey: pin}}})
	if err != nil {
		return TrustState{}, err
	}
	return TrustState{Current: SignedTrustRecord{Payload: payload}}, nil
}

// VerifyPolicyBundleWithTrust is network acceptance: only the current record
// is applicable (issue #65 §3.5). An explicit keyId must match exactly; an absent
// RFC 7517 §4.5 hint tries the record's at-most-two keys. Existing bundle signature,
// node and revision validation stays in VerifyPolicyBundle, not duplicated here.
// The returned signer ID also identifies legacy bundles without a hint.
func VerifyPolicyBundleWithTrust(signed SignedPolicyBundle, keyID string, current TrustRecord, nodeID string) (PolicyBundle, string, error) {
	if err := validateTrustRecord(current); err != nil {
		return PolicyBundle{}, "", err
	}
	for _, key := range current.Keys {
		if keyID != "" && key.KeyID != keyID {
			continue
		}
		if bundle, err := VerifyPolicyBundle(signed, key.PublicKey, nodeID); err == nil {
			return bundle, key.KeyID, nil
		}
	}
	return PolicyBundle{}, "", errors.New("policy bundle has no valid signature for the applicable trust keys")
}

func parseTrustState(state TrustState) (TrustRecord, *TrustRecord, error) {
	current, err := parseTrustRecord(state.Current)
	if err != nil {
		return TrustRecord{}, nil, err
	}
	if state.Cache == nil {
		return current, nil, nil
	}
	cache, err := parseTrustRecord(*state.Cache)
	if err != nil {
		return TrustRecord{}, nil, err
	}
	if cache.Version >= current.Version {
		return TrustRecord{}, nil, errors.New("cache trust record must precede current")
	}
	return current, &cache, nil
}

// VerifyCachedPolicyBundle is private-local-cache acceptance, not network
// acceptance (issue #65 §3.5 and D6): either of the at-most-two persisted records
// may verify it. A retired key here must never authorize a network response.
// S4 must supply already-trusted private local state: historical signature
// membership is not re-established after D6 drops predecessors. Persisted
// envelopes still require distinct lowercase SHA-256 keyIds, 64-byte Ed25519
// signatures and at most maxTrustSignatures entries; no normalization occurs.
func VerifyCachedPolicyBundle(signed SignedPolicyBundle, keyID string, state TrustState, nodeID string) (PolicyBundle, string, error) {
	current, cache, err := parseTrustState(state)
	if err != nil {
		return PolicyBundle{}, "", err
	}
	bundle, signer, err := VerifyPolicyBundleWithTrust(signed, keyID, current, nodeID)
	if err == nil || cache == nil {
		return bundle, signer, err
	}
	return VerifyPolicyBundleWithTrust(signed, keyID, *cache, nodeID)
}

func cloneSignedTrustRecord(record SignedTrustRecord) SignedTrustRecord {
	cloned := SignedTrustRecord{Payload: bytes.Clone(record.Payload)}
	if record.Signatures != nil {
		cloned.Signatures = make([]TrustSignature, len(record.Signatures))
		for i, signature := range record.Signatures {
			cloned.Signatures[i] = TrustSignature{KeyID: signature.KeyID, Signature: bytes.Clone(signature.Signature)}
		}
	}
	return cloned
}

// AdvanceTrustState is D6's pure N→N+1 transition, following TUF §5.3. The cache
// record is unchanged across catch-up, including when it is older than N.
// Persist the result atomically before fetching the next step; this does no IO.
func AdvanceTrustState(state TrustState, next SignedTrustRecord) (TrustState, error) {
	current, _, err := parseTrustState(state)
	if err != nil {
		return TrustState{}, err
	}
	if _, err := VerifyTrustRecord(next, current); err != nil {
		return TrustState{}, err
	}
	anchor := state.Current
	if state.Cache != nil {
		anchor = *state.Cache
	}
	cache := cloneSignedTrustRecord(anchor)
	return TrustState{Current: cloneSignedTrustRecord(next), Cache: &cache}, nil
}

// TrustStateAfterBundle is D6's pure post-re-sign transition. Call only AFTER
// revision-floor/identity checks and the current-key bundle's durable write;
// it verifies current authority and drops the obsolete cache record, without IO.
func TrustStateAfterBundle(state TrustState, signed SignedPolicyBundle, keyID, nodeID string) (TrustState, error) {
	current, _, err := parseTrustState(state)
	if err != nil {
		return TrustState{}, err
	}
	if _, _, err := VerifyPolicyBundleWithTrust(signed, keyID, current, nodeID); err != nil {
		return TrustState{}, err
	}
	return TrustState{Current: cloneSignedTrustRecord(state.Current)}, nil
}
