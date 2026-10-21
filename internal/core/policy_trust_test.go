package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

func trustTestKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func trustTestRecord(version int, privateKeys ...ed25519.PrivateKey) TrustRecord {
	record := TrustRecord{Version: version, Keys: []TrustKey{}}
	for _, private := range privateKeys {
		public := private.Public().(ed25519.PublicKey)
		record.Keys = append(record.Keys, TrustKey{KeyID: BundleKeyID(public), PublicKey: public})
	}
	return record
}

func trustTestSign(t *testing.T, record TrustRecord, privateKeys ...ed25519.PrivateKey) SignedTrustRecord {
	t.Helper()
	signed, err := SignTrustRecord(record, privateKeys...)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func trustTestBundle(private ed25519.PrivateKey) SignedPolicyBundle {
	payload := mustJSON(PolicyBundle{Revision: 7, NodeID: "node", Rules: []Rule{}})
	return SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}
}

func TestTrustCanonicalEncodingAndKeyID(t *testing.T) {
	a := trustTestKey("A")
	record := trustTestRecord(1, a)
	payload, err := TrustRecordBytes(record)
	if err != nil || !bytes.Equal(payload, mustJSON(record)) || bytes.Contains(payload, []byte("\n")) {
		t.Fatalf("canonical compact JSON: %s, %v", payload, err)
	}
	signed := trustTestSign(t, record, a)
	got, err := parseTrustRecord(signed)
	if err != nil || !reflect.DeepEqual(got, record) {
		t.Fatalf("record round trip: %v", err)
	}
	public, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a") // RFC 8032 §7.1 test 1.
	// Golden SHA-256 independently computed with Python hashlib, not BundleKeyID.
	if id := BundleKeyID(public); id != "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9" {
		t.Fatal("keyId is not full lowercase SHA-256")
	}
	if BundleKeyID(nil) != "" {
		t.Fatal("invalid public key has an identifier")
	}
}

func TestTrustRotationChainAndRetirement(t *testing.T) {
	a, b, c := trustTestKey("A"), trustTestKey("B"), trustTestKey("C")
	previous := trustTestRecord(1, a)
	for _, next := range []SignedTrustRecord{
		trustTestSign(t, trustTestRecord(2, a, b), a, b),
		trustTestSign(t, trustTestRecord(3, b), b),
		trustTestSign(t, trustTestRecord(4, b, c), b, c),
		trustTestSign(t, trustTestRecord(5, c), c),
	} {
		got, err := VerifyTrustRecord(next, previous)
		if err != nil || got.Version != previous.Version+1 {
			t.Fatalf("chain step from %d: %v", previous.Version, err)
		}
		previous = got
	}
}

func TestTrustRejectsUnauthorisedSuccessors(t *testing.T) {
	a, b, c := trustTestKey("A"), trustTestKey("B"), trustTestKey("C")
	previous := trustTestRecord(1, a)
	valid := trustTestSign(t, trustTestRecord(2, b), a, b)
	duplicate := valid
	duplicate.Signatures = []TrustSignature{valid.Signatures[0], valid.Signatures[0]}
	wrongID := valid
	wrongID.Signatures = append([]TrustSignature(nil), valid.Signatures...)
	wrongID.Signatures[1].KeyID = BundleKeyID(c.Public().(ed25519.PublicKey))
	for _, tc := range []struct {
		name string
		next SignedTrustRecord
	}{
		{"version skip", trustTestSign(t, trustTestRecord(3, b), a, b)},
		{"version rollback", trustTestSign(t, trustTestRecord(1, b), a, b)},
		{"old signature only", trustTestSign(t, trustTestRecord(2, b), a)},
		{"new signature only", trustTestSign(t, trustTestRecord(2, b), b)},
		{"unrelated signature", trustTestSign(t, trustTestRecord(2, b), c)},
		{"duplicate key cannot count as new authority", duplicate},
		{"wrong keyId", wrongID},
		{"unsigned v1 from network", SignedTrustRecord{Payload: mustJSON(previous)}},
		{"unsigned successor", SignedTrustRecord{Payload: valid.Payload}},
		{"tampered payload", SignedTrustRecord{Payload: append(append([]byte(nil), valid.Payload...), ' '), Signatures: valid.Signatures}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyTrustRecord(tc.next, previous); err == nil {
				t.Fatal("unauthorised record accepted")
			}
		})
	}
	valid.Signatures = append(valid.Signatures, valid.Signatures[0])
	if _, err := VerifyTrustRecord(valid, previous); err == nil {
		t.Fatal("duplicate signatures accepted despite valid distinct authorities")
	}
}

func TestTrustRejectsMalformedRecords(t *testing.T) {
	a, b, c := trustTestKey("A"), trustTestKey("B"), trustTestKey("C")
	valid := trustTestRecord(2, b)
	duplicate := trustTestRecord(2, b, b)
	wrongID := trustTestRecord(2, b)
	wrongID.Keys[0].KeyID = "wrong"
	badLength := trustTestRecord(2, b)
	badLength.Keys[0].PublicKey = []byte("short")
	for _, record := range []TrustRecord{
		{Version: 0, Keys: valid.Keys},
		{Version: -1, Keys: valid.Keys},
		{Version: 2},
		trustTestRecord(2, a, b, c),
		duplicate, wrongID, badLength,
	} {
		if _, err := TrustRecordBytes(record); err == nil {
			t.Fatalf("encoded invalid record: %+v", record)
		}
		signed := SignedTrustRecord{Payload: mustJSON(record)}
		signed.Signatures = []TrustSignature{{KeyID: BundleKeyID(a.Public().(ed25519.PublicKey)), Signature: ed25519.Sign(a, signed.Payload)}}
		if _, err := VerifyTrustRecord(signed, trustTestRecord(1, a)); err == nil {
			t.Fatal("accepted signed malformed record")
		}
	}
	for _, payload := range [][]byte{[]byte("not JSON"), []byte("null"), []byte(`{"version":2,"keys":[]}`), bytes.Repeat([]byte(" "), PolicyBundleMaxBytes+1)} {
		if _, err := parseTrustRecord(SignedTrustRecord{Payload: payload}); err == nil {
			t.Fatal("malformed/oversized record parsed")
		}
	}
	oversize := trustTestSign(t, valid, a, b)
	oversize.Signatures = []TrustSignature{{KeyID: strings.Repeat("x", PolicyBundleMaxBytes)}}
	if _, err := parseTrustRecord(oversize); err == nil {
		t.Fatal("oversized envelope parsed")
	}
	if _, err := VerifyTrustRecord(trustTestSign(t, valid, a, b), TrustRecord{}); err == nil {
		t.Fatal("invalid previous authority accepted")
	}
	for _, private := range []ed25519.PrivateKey{nil, make([]byte, ed25519.PrivateKeySize)} {
		if _, err := SignTrustRecord(valid, private); err == nil {
			t.Fatal("malformed private key accepted")
		}
	}
	if _, err := SignTrustRecord(valid); err == nil {
		t.Fatal("unsigned record emitted")
	}
	if _, err := SignTrustRecord(TrustRecord{}, a); err == nil {
		t.Fatal("signed invalid record")
	}
	one := trustTestSign(t, valid, a)
	twice := trustTestSign(t, valid, a, a)
	if !reflect.DeepEqual(one, twice) {
		t.Fatal("signing counted one private key twice")
	}
	maxVersion := int(^uint(0) >> 1)
	if _, err := VerifyTrustRecord(trustTestSign(t, trustTestRecord(1, a), a), trustTestRecord(maxVersion, a)); err == nil {
		t.Fatal("version wraparound accepted")
	}
}

func TestTrustBootstrapAndLegacy(t *testing.T) {
	a, b := trustTestKey("A"), trustTestKey("B")
	public := a.Public().(ed25519.PublicKey)
	signed := trustTestSign(t, trustTestRecord(5, a, b), b)
	if record, err := VerifyTrustBootstrap(signed, public); err != nil || record.Version != 5 {
		t.Fatal("authenticated enrollment bootstrap rejected", err)
	}
	for _, tc := range []struct {
		signed SignedTrustRecord
		pin    []byte
	}{
		{signed, nil},
		{signed, trustTestKey("C").Public().(ed25519.PublicKey)},
		{SignedTrustRecord{Payload: signed.Payload}, public},
		{SignedTrustRecord{Payload: []byte("invalid")}, public},
	} {
		if _, err := VerifyTrustBootstrap(tc.signed, tc.pin); err == nil {
			t.Fatal("invalid bootstrap accepted")
		}
	}
	state, err := LegacyTrustState(public)
	if err != nil || state.Cache != nil {
		t.Fatal("legacy state", err)
	}
	record, err := parseTrustRecord(state.Current)
	if err != nil || record.Version != 1 || !reflect.DeepEqual(record.Keys, trustTestRecord(1, a).Keys) {
		t.Fatal("legacy is not implicit v1 pin", err)
	}
	if _, err := VerifyTrustBootstrap(state.Current, public); err == nil {
		t.Fatal("unsigned locally synthesized anchor accepted as network bootstrap")
	}
	if _, err := LegacyTrustState(nil); err == nil {
		t.Fatal("invalid legacy pin accepted")
	}
}

func TestTrustBundleKeyIDAndTrialVerification(t *testing.T) {
	a, b, c := trustTestKey("A"), trustTestKey("B"), trustTestKey("C")
	for _, record := range []TrustRecord{trustTestRecord(1, b), trustTestRecord(2, a, b)} {
		for _, id := range []string{"", BundleKeyID(b.Public().(ed25519.PublicKey))} {
			bundle, signer, err := VerifyPolicyBundleWithTrust(trustTestBundle(b), id, record, "node")
			if err != nil || bundle.Revision != 7 || signer != BundleKeyID(b.Public().(ed25519.PublicKey)) {
				t.Fatalf("keyId/trial verification: signer=%q, %v", signer, err)
			}
		}
	}
	for _, tc := range []struct {
		signed   SignedPolicyBundle
		id, node string
		record   TrustRecord
	}{
		{trustTestBundle(b), BundleKeyID(a.Public().(ed25519.PublicKey)), "node", trustTestRecord(2, a, b)},
		{trustTestBundle(b), "unknown", "node", trustTestRecord(2, a, b)},
		{trustTestBundle(c), "", "node", trustTestRecord(2, a, b)},
		{trustTestBundle(b), "", "other", trustTestRecord(2, a, b)},
		{trustTestBundle(b), "", "node", TrustRecord{}},
	} {
		if _, _, err := VerifyPolicyBundleWithTrust(tc.signed, tc.id, tc.record, tc.node); err == nil {
			t.Fatal("invalid bundle/identity accepted")
		}
	}
}

func TestTrustStateCatchUpRetainsCacheAndDropsAfterResign(t *testing.T) {
	a, b, c := trustTestKey("A"), trustTestKey("B"), trustTestKey("C")
	state, err := LegacyTrustState(a.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	original := mustJSON(state)
	anchor := state.Current
	for _, next := range []SignedTrustRecord{
		trustTestSign(t, trustTestRecord(2, a, b), a, b),
		trustTestSign(t, trustTestRecord(3, b), b),
		trustTestSign(t, trustTestRecord(4, b, c), b, c),
		trustTestSign(t, trustTestRecord(5, c), c),
	} {
		before := mustJSON(state)
		advanced, err := AdvanceTrustState(state, next)
		if err != nil || advanced.Cache == nil || !reflect.DeepEqual(*advanced.Cache, anchor) {
			t.Fatal("catch-up lost original cache authority", err)
		}
		if !bytes.Equal(mustJSON(state), before) {
			t.Fatal("advance mutated input")
		}
		// Simulate a restart at every accepted-record boundary, without filesystem IO.
		if err := json.Unmarshal(mustJSON(advanced), &state); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(a), "", state, "node"); err != nil {
			t.Fatal("old cache not loadable at interruption", err)
		}
	}
	if !bytes.Equal(mustJSON(TrustState{Current: anchor}), original) {
		t.Fatal("anchor mutated")
	}
	current, err := parseTrustRecord(state.Current)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPolicyBundleWithTrust(trustTestBundle(a), "", current, "node"); err == nil {
		t.Fatal("retired network signer accepted")
	}
	if _, err := TrustStateAfterBundle(state, trustTestBundle(a), "", "node"); err == nil {
		t.Fatal("cache dropped before current-key bundle replacement")
	}
	if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(b), "", state, "node"); err == nil {
		t.Fatal("intermediate key wrongly persisted as cache authority")
	}
	if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(a), BundleKeyID(c.Public().(ed25519.PublicKey)), state, "node"); err == nil {
		t.Fatal("cache verification ignored wrong keyId")
	}
	finished, err := TrustStateAfterBundle(state, trustTestBundle(c), "", "node")
	if err != nil || finished.Cache != nil || state.Cache == nil {
		t.Fatal("re-sign transition did not drop only output cache", err)
	}
	if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(c), "", finished, "node"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(a), "", finished, "node"); err == nil {
		t.Fatal("retired cache accepted after pruning")
	}
	if _, err := AdvanceTrustState(finished, trustTestSign(t, trustTestRecord(7, a), c, a)); err == nil {
		t.Fatal("state skipped version")
	}
}

func TestTrustStateNeverExceedsTwoRecords(t *testing.T) {
	a, b := trustTestKey("A"), trustTestKey("B")
	property := func(steps []bool) bool {
		state, err := LegacyTrustState(a.Public().(ed25519.PublicKey))
		if err != nil {
			return false
		}
		previousKey, cacheKey := a, a
		for i, replace := range steps {
			nextKey := b
			if bytes.Equal(previousKey, b) {
				nextKey = a
			}
			next := trustTestSign(t, trustTestRecord(i+2, nextKey), previousKey, nextKey)
			state, err = AdvanceTrustState(state, next)
			if err != nil {
				return false
			}
			if _, _, err = VerifyCachedPolicyBundle(trustTestBundle(cacheKey), "", state, "node"); err != nil {
				return false
			}
			if replace {
				state, err = TrustStateAfterBundle(state, trustTestBundle(nextKey), "", "node")
				if err != nil {
					return false
				}
				cacheKey = nextKey
			}
			var persisted map[string]json.RawMessage
			data := mustJSON(state)
			if len(data) > PolicyBundleMaxBytes || json.Unmarshal(data, &persisted) != nil || len(persisted) > 2 {
				return false
			}
			previousKey = nextKey
		}
		return true
	}
	if err := quick.Check(property, nil); err != nil {
		t.Fatal(err)
	}
}

func TestTrustStateTransitionsDoNotAliasInputs(t *testing.T) {
	a, b := trustTestKey("A"), trustTestKey("B")
	state := TrustState{Current: trustTestSign(t, trustTestRecord(1, a), a)}
	next := trustTestSign(t, trustTestRecord(2, b), a, b)
	before, nextBefore := mustJSON(state), mustJSON(next)
	advanced, err := AdvanceTrustState(state, next)
	if err != nil {
		t.Fatal(err)
	}
	advanced.Current.Payload[0] ^= 1
	advanced.Current.Signatures[0].Signature[0] ^= 1
	advanced.Cache.Payload[0] ^= 1
	advanced.Cache.Signatures[0].Signature[0] ^= 1
	if !bytes.Equal(before, mustJSON(state)) || !bytes.Equal(nextBefore, mustJSON(next)) {
		t.Fatal("transition output aliases input buffers")
	}
	finished, err := TrustStateAfterBundle(state, trustTestBundle(a), "", "node")
	if err != nil {
		t.Fatal(err)
	}
	finished.Current.Signatures[0].Signature[0] ^= 1
	if !bytes.Equal(before, mustJSON(state)) {
		t.Fatal("post-bundle output aliases input signature")
	}
}

func TestTrustStateRejectsMalformedAuthorities(t *testing.T) {
	a := trustTestKey("A")
	current := trustTestSign(t, trustTestRecord(2, a), a)
	future := trustTestSign(t, trustTestRecord(3, a), a)
	for _, state := range []TrustState{
		{},
		{Current: current, Cache: &SignedTrustRecord{}},
		{Current: current, Cache: &current},
		{Current: current, Cache: &future},
	} {
		if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(a), "", state, "node"); err == nil {
			t.Fatal("invalid state verified cache")
		}
		if _, err := AdvanceTrustState(state, future); err == nil {
			t.Fatal("invalid state advanced")
		}
		if _, err := TrustStateAfterBundle(state, trustTestBundle(a), "", "node"); err == nil {
			t.Fatal("invalid state pruned")
		}
	}
}

// Regression from the independent review probe: unsigned duplicate padding must
// be rejected before two individually in-budget envelopes can overflow D6 state.
func TestTrustRejectsPaddedDuplicateSignatures(t *testing.T) {
	a := trustTestKey("A")
	state, err := LegacyTrustState(a.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	for version := 2; version <= 3; version++ {
		valid := trustTestSign(t, trustTestRecord(version, a), a)
		padded := valid
		first := valid.Signatures[0]
		// Same count as the reviewer: derive padding from the existing wire budget.
		count := PolicyBundleMaxBytes/(len(mustJSON(first))+1) - 1
		padded.Signatures = make([]TrustSignature, count)
		for i := range padded.Signatures {
			padded.Signatures[i] = first
		}
		if len(mustJSON(padded)) > PolicyBundleMaxBytes {
			t.Fatal("invalid regression fixture: envelope already over budget")
		}
		previous, err := parseTrustRecord(state.Current)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyTrustRecord(padded, previous); err == nil {
			t.Error("network accepted duplicate-padded envelope")
		}
		if _, err := VerifyTrustBootstrap(padded, a.Public().(ed25519.PublicKey)); err == nil {
			t.Error("bootstrap accepted duplicate-padded envelope")
		}
		if _, err := AdvanceTrustState(state, padded); err == nil {
			t.Error("state accepted duplicate-padded envelope")
		}
		if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(a), "", TrustState{Current: padded}, "node"); err == nil {
			t.Error("cache accepted duplicate-padded envelope")
		}
		state, err = AdvanceTrustState(state, valid)
		if err != nil {
			t.Fatal(err)
		}
		state, err = TrustStateAfterBundle(state, trustTestBundle(a), "", "node")
		if err != nil {
			t.Fatal(err)
		}
		if len(mustJSON(state)) > PolicyBundleMaxBytes {
			t.Fatal("D6 state exceeds the unchanged read budget")
		}
	}
}

func TestTrustRejectsMalformedSignatureEnvelopes(t *testing.T) {
	a := trustTestKey("A")
	valid := trustTestSign(t, trustTestRecord(2, a), a)
	first := valid.Signatures[0]
	tooMany := []TrustSignature{first}
	// More than the derived maximum: two old keys plus two new keys.
	for _, label := range []string{"B", "C", "D", "E"} {
		tooMany = append(tooMany, trustTestSign(t, trustTestRecord(2, a), trustTestKey(label)).Signatures[0])
	}
	if _, err := SignTrustRecord(trustTestRecord(2, a), a, trustTestKey("B"), trustTestKey("C"), trustTestKey("D"), trustTestKey("E")); err == nil {
		t.Fatal("signer emitted more than the old/new union maximum")
	}
	for name, signatures := range map[string][]TrustSignature{
		"duplicate":         {first, first},
		"too many":          tooMany,
		"short ID":          {{KeyID: "short", Signature: first.Signature}},
		"long ID":           {{KeyID: first.KeyID + "0", Signature: first.Signature}},
		"nonhex ID":         {{KeyID: strings.Repeat("z", len(first.KeyID)), Signature: first.Signature}},
		"uppercase ID":      {{KeyID: strings.ToUpper(first.KeyID), Signature: first.Signature}},
		"missing signature": {{KeyID: first.KeyID}},
		"long signature":    {{KeyID: first.KeyID, Signature: append(bytes.Clone(first.Signature), 0)}},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := SignedTrustRecord{Payload: valid.Payload, Signatures: signatures}
			if _, err := VerifyTrustRecord(invalid, trustTestRecord(1, a)); err == nil {
				t.Error("network accepted malformed signature envelope")
			}
			if _, err := VerifyTrustBootstrap(invalid, a.Public().(ed25519.PublicKey)); err == nil {
				t.Error("bootstrap accepted malformed signature envelope")
			}
			for _, state := range []TrustState{
				{Current: invalid},
				{Current: trustTestSign(t, trustTestRecord(3, a), a), Cache: &invalid},
			} {
				if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(a), "", state, "node"); err == nil {
					t.Error("cache accepted malformed signature envelope")
				}
			}
		})
	}
}

func TestTrustNetworkRejectsSignersOutsideApplicableKeySet(t *testing.T) {
	a, b, c := trustTestKey("A"), trustTestKey("B"), trustTestKey("C")
	// A third-party signature cannot pad an otherwise valid A→B transition.
	extra := trustTestSign(t, trustTestRecord(2, b), a, b, c)
	if _, err := VerifyTrustRecord(extra, trustTestRecord(1, a)); err == nil {
		t.Error("network accepted signer outside old union new")
	}
	// Bootstrap is stricter: predecessor-only signatures are not its authority.
	bootstrap := trustTestSign(t, trustTestRecord(2, b), b, a)
	if _, err := VerifyTrustBootstrap(bootstrap, b.Public().(ed25519.PublicKey)); err == nil {
		t.Error("bootstrap accepted signer outside its own keys")
	}
}

func TestTrustDisjointChainAndPruneRetainBoundedEnvelopes(t *testing.T) {
	a, b, c, d, e := trustTestKey("A"), trustTestKey("B"), trustTestKey("C"), trustTestKey("D"), trustTestKey("E")
	// Four signatures is the derived maximum (two previous plus two new keys).
	state := TrustState{Current: trustTestSign(t, trustTestRecord(1, a, b), a, b)}
	next := trustTestSign(t, trustTestRecord(2, c, d), a, b, c, d)
	state, err := AdvanceTrustState(state, next)
	if err != nil {
		t.Fatal(err)
	}
	state, err = TrustStateAfterBundle(state, trustTestBundle(c), "", "node")
	if err != nil || state.Cache != nil {
		t.Fatal("first prune failed", err)
	}
	state, err = AdvanceTrustState(state, trustTestSign(t, trustTestRecord(3, e), c, d, e))
	if err != nil {
		t.Fatal(err)
	}
	// A/B no longer occur in current/cache key sets, but are legitimate historical
	// signatures on the persisted cache record. D6 does not re-walk the chain.
	if _, _, err := VerifyCachedPolicyBundle(trustTestBundle(c), "", state, "node"); err != nil {
		t.Fatal("disjoint cross-signed cache rejected", err)
	}
	if len(mustJSON(state)) > PolicyBundleMaxBytes {
		t.Fatal("valid maximum-signature D6 state exceeds read budget")
	}
	state, err = TrustStateAfterBundle(state, trustTestBundle(e), "", "node")
	if err != nil || state.Cache != nil {
		t.Fatal("final prune failed", err)
	}
}
