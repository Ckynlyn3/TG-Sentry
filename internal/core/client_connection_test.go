package core

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// Enrollment/retry serialization belongs to S2/S7. S4 validates the snapshot
// supplied over that authenticated channel, including fresh enrollment at v3.
func TestClientBootstrapValidation(t *testing.T) {
	a, b := trustTestKey("bootstrap A"), trustTestKey("bootstrap B")
	valid := trustTestSign(t, trustTestRecord(3, a), a)
	unsigned := SignedTrustRecord{Payload: valid.Payload}
	wrongPin := trustTestSign(t, trustTestRecord(3, b), b)
	tampered := valid
	tampered.Payload = append(bytes.Clone(valid.Payload), ' ')
	for _, record := range []SignedTrustRecord{unsigned, wrongPin, tampered, {Payload: []byte("null")}} {
		if _, err := BootstrapPolicyTrust(a.Public().(ed25519.PublicKey), &record); err == nil {
			t.Fatal("invalid enrollment trust accepted")
		}
	}
	state, err := BootstrapPolicyTrust(a.Public().(ed25519.PublicKey), &valid)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := parseTrustState(state)
	if err != nil || current.Version != 3 {
		t.Fatal("bootstrap reset to v1", err)
	}
	if _, _, err := VerifyCachedPolicyBundle(cacheTestBundle(a, 7), "", state, "node"); err != nil {
		t.Fatal("fresh v3 enrollment needs history", err)
	}
	state, err = BootstrapPolicyTrust(a.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err = parseTrustState(state)
	if err != nil || current.Version != 1 {
		t.Fatal("legacy connection not implicit v1", err)
	}
	if _, err := BootstrapPolicyTrust(nil, nil); err == nil {
		t.Fatal("missing pin accepted")
	}
}
