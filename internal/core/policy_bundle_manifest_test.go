package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The manifest is the sole commit point (issue #65 §3.3), not a key glob.
type testBundleManifest struct {
	Records []SignedTrustRecord `json:"records"`
	Signer  string              `json:"signer"`
}

func readTestBundleManifest(t *testing.T, dir string) testBundleManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "bundle-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest testBundleManifest
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func testBundleKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testBundleRecord(t *testing.T, version int, keys ...ed25519.PrivateKey) SignedTrustRecord {
	t.Helper()
	record := TrustRecord{Version: version}
	for _, key := range keys {
		public := key.Public().(ed25519.PublicKey)
		record.Keys = append(record.Keys, TrustKey{KeyID: BundleKeyID(public), PublicKey: public})
	}
	signed, err := SignTrustRecord(record, keys...)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestBundleManifestSynthesisAndCommitBoundaries(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "legacy"}[legacy], func(t *testing.T) {
			dir := t.TempDir()
			var original ed25519.PrivateKey
			if legacy {
				original = testBundleKey(t)
				if err := AtomicFile(filepath.Join(dir, "bundle-signing.key"), original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			e := &Engine{Dir: dir}
			if err := e.loadBundleKey(); err != nil {
				t.Fatal(err)
			}
			manifest := readTestBundleManifest(t, dir)
			if len(manifest.Records) != 1 || manifest.Signer != BundleKeyID(e.bundleKey.Public().(ed25519.PublicKey)) {
				t.Fatal("invalid initial manifest")
			}
			record, err := VerifyTrustBootstrap(manifest.Records[0], e.bundleKey.Public().(ed25519.PublicKey))
			if err != nil || record.Version != 1 {
				t.Fatal("invalid v1 bootstrap", err)
			}
			if legacy && !bytes.Equal(original, e.bundleKey) {
				t.Fatal("legacy key replaced")
			}
			for _, name := range []string{"bundle-signing.key", "bundle-trust.json"} {
				st, err := os.Stat(filepath.Join(dir, name))
				if err != nil || st.Mode().Perm() != 0600 {
					t.Fatal("nonprivate signing state", name, err)
				}
			}
			restarted := &Engine{Dir: dir}
			if err := restarted.loadBundleKey(); err != nil || !bytes.Equal(e.bundleKey, restarted.bundleKey) {
				t.Fatal("restart changed signer", err)
			}
		})
	}
	t.Run("crash after new key before manifest", func(t *testing.T) {
		dir := t.TempDir()
		e := &Engine{Dir: dir}
		if err := e.loadBundleKey(); err != nil {
			t.Fatal(err)
		}
		old := append([]byte(nil), e.bundleKey...)
		orphan := testBundleKey(t)
		name := "bundle-signing." + BundleKeyID(orphan.Public().(ed25519.PublicKey)) + ".key"
		if err := AtomicFile(filepath.Join(dir, name), orphan, 0600); err != nil {
			t.Fatal(err)
		}
		// Restart after the key-first write, with the old manifest still committed.
		var report bytes.Buffer
		output := log.Writer()
		log.SetOutput(&report)
		defer log.SetOutput(output)
		restarted := &Engine{Dir: dir}
		if err := restarted.loadBundleKey(); err != nil || !bytes.Equal(old, restarted.bundleKey) {
			t.Fatal("orphan activated", err)
		}
		if !strings.Contains(report.String(), name) {
			t.Fatal("orphan not reported")
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal("orphan removed", err)
		}
	})
	t.Run("manifest write fails after durable initial key", func(t *testing.T) {
		dir := t.TempDir()
		manifestPath := filepath.Join(dir, "bundle-trust.json")
		if err := os.Mkdir(manifestPath, 0700); err != nil {
			t.Fatal(err)
		}
		e := &Engine{Dir: dir}
		if err := e.loadBundleKey(); err == nil {
			t.Fatal("manifest commit failure ignored")
		}
		// A failure is not success and may not publish an in-memory signer.
		if len(e.bundleKey) != 0 {
			t.Fatal("uncommitted signer published")
		}
	})
}

func TestBundleManifestRejectsCorruption(t *testing.T) {
	for _, fault := range []string{"missing signer key", "malformed signer key", "missing overlap key", "wrong key identity", "bad signer", "broken chain", "malformed manifest"} {
		t.Run(fault, func(t *testing.T) {
			dir := t.TempDir()
			a, b := testBundleKey(t), testBundleKey(t)
			aID, bID := BundleKeyID(a.Public().(ed25519.PublicKey)), BundleKeyID(b.Public().(ed25519.PublicKey))
			if err := AtomicFile(filepath.Join(dir, "bundle-signing.key"), a, 0600); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(dir, "bundle-signing."+bID+".key")
			if err := AtomicFile(keyPath, b, 0600); err != nil {
				t.Fatal(err)
			}
			manifest := testBundleManifest{Records: []SignedTrustRecord{testBundleRecord(t, 1, a), testBundleRecord(t, 2, a, b)}, Signer: bID}
			switch fault {
			case "missing signer key":
				os.Remove(keyPath)
			case "malformed signer key":
				os.WriteFile(keyPath, []byte("corrupt"), 0600)
			case "missing overlap key":
				os.Remove(filepath.Join(dir, "bundle-signing.key"))
			case "wrong key identity":
				os.WriteFile(keyPath, a, 0600)
			case "bad signer":
				manifest.Signer = aID + "/../key"
			case "broken chain":
				manifest.Records[1] = testBundleRecord(t, 3, a, b)
			}
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "malformed manifest" {
				data = []byte("{")
			}
			if err := AtomicFile(filepath.Join(dir, "bundle-trust.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			e := &Engine{Dir: dir}
			if err := e.loadBundleKey(); err == nil {
				t.Fatal("invalid committed state accepted")
			}
			if len(e.bundleKey) != 0 {
				t.Fatal("invalid state published signer")
			}
		})
	}
}

func TestBundleManifestSignerAndEnrollmentWire(t *testing.T) {
	e := engine(t)
	original := e.bundleKey
	// Commit A→{A,B}→{B,C}; fresh enrollment must bootstrap at v3.
	b, c := testBundleKey(t), testBundleKey(t)
	v1 := testBundleRecord(t, 1, original)
	v2 := testBundleRecord(t, 2, original, b)
	v3 := testBundleRecord(t, 3, b, c)
	for _, key := range []ed25519.PrivateKey{b, c} {
		id := BundleKeyID(key.Public().(ed25519.PublicKey))
		if err := AtomicFile(filepath.Join(e.Dir, "bundle-signing."+id+".key"), key, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cID := BundleKeyID(c.Public().(ed25519.PublicKey))
	data, err := json.Marshal(testBundleManifest{Records: []SignedTrustRecord{v1, v2, v3}, Signer: cID})
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicFile(filepath.Join(e.Dir, "bundle-trust.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.loadBundleKey(); err != nil {
		t.Fatal(err)
	}
	for _, flow := range []string{"setup key", "approved request"} {
		t.Run(flow, func(t *testing.T) {
			var conn ClientConnection
			if flow == "setup key" {
				code, err := e.CreateEnrollment(testActorContext(), "wire")
				if err != nil {
					t.Fatal(err)
				}
				conn, err = e.EnrollClient(code.Code, "linux")
				if err != nil {
					t.Fatal(err)
				}
			} else {
				ticket, err := e.CreateClientRequest("wire", "linux", "192.0.2.65")
				if err != nil {
					t.Fatal(err)
				}
				if err := e.DecideClientRequest(testActorContext(), ticket.ID, "approve"); err != nil {
					t.Fatal(err)
				}
				result, err := e.PollClientRequest(ticket.ID, ticket.Secret, "192.0.2.65")
				if err != nil || result.Connection == nil {
					t.Fatal("request enrollment", err)
				}
				conn = *result.Connection
			}
			wire, err := json.Marshal(conn)
			if err != nil || len(wire) > 8192 {
				t.Fatal("enrollment response exceeds installer decoder bound", err)
			}
			var response struct {
				BundleTrust *SignedTrustRecord `json:"bundleTrust"`
			}
			if err := json.Unmarshal(wire, &response); err != nil || response.BundleTrust == nil {
				t.Fatal("missing bundleTrust", err)
			}
			record, err := VerifyTrustBootstrap(*response.BundleTrust, conn.BundlePublicKey)
			if err != nil || record.Version != 3 || !bytes.Equal(conn.BundlePublicKey, c.Public().(ed25519.PublicKey)) {
				t.Fatal("wrong enrollment bootstrap", err)
			}
			signed, err := e.ClientPolicyBundle(conn.NodeID)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := json.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			var hint struct {
				KeyID string `json:"keyId"`
			}
			if err := json.Unmarshal(envelope, &hint); err != nil || hint.KeyID != cID {
				t.Fatal("missing or wrong emitted keyId", err)
			}
			if _, _, err := VerifyPolicyBundleWithTrust(signed, hint.KeyID, record, conn.NodeID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBundleEmitsKeyID(t *testing.T) {
	e := engine(t)
	setup, err := e.CreateEnrollment(testActorContext(), "hint")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(setup.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		KeyID string `json:"keyId"`
	}
	if err := json.Unmarshal(b, &wire); err != nil || wire.KeyID != BundleKeyID(conn.BundlePublicKey) {
		t.Fatal("bundle keyId not emitted", err)
	}
}

func TestBundleRotationAndRetirement(t *testing.T) {
	e := engine(t)
	setup, err := e.CreateEnrollment(testActorContext(), "rotate")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(setup.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	before, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	aID := BundleKeyID(conn.BundlePublicKey)
	if err := e.RotateBundleKey(); err != nil {
		t.Fatal(err)
	}
	if e.BundleTrustVersion() != 2 {
		t.Fatal("rotation did not advance trust")
	}
	first, err := e.BundleTrustRecord(1)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := VerifyTrustBootstrap(first, conn.BundlePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.BundleTrustRecord(2)
	if err != nil {
		t.Fatal(err)
	}
	overlap, err := VerifyTrustRecord(next, previous)
	if err != nil || len(overlap.Keys) != 2 {
		t.Fatal("invalid rotation", err)
	}
	after, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	bID := BundleKeyID(e.bundleKey.Public().(ed25519.PublicKey))
	if bID == aID || PolicyBundleETag(before) != PolicyBundleETag(after) || !bytes.Equal(before.Payload, after.Payload) {
		t.Fatal("rotation changed payload or retained signer")
	}
	if err := e.RotateBundleKey(); err == nil {
		t.Fatal("rotation without retiring predecessor accepted")
	}
	for _, id := range []string{bID, "", "../invalid"} {
		if err := e.RetireBundleKey(id); err == nil {
			t.Fatal("unsafe retirement accepted", id)
		}
	}
	if err := e.RetireBundleKey(aID); err != nil {
		t.Fatal(err)
	}
	retired, err := e.BundleTrustRecord(3)
	if err != nil {
		t.Fatal(err)
	}
	current, err := VerifyTrustRecord(retired, overlap)
	if err != nil || len(current.Keys) != 1 || current.Keys[0].KeyID != bID {
		t.Fatal("invalid retirement", err)
	}
	if err := e.RetireBundleKey(aID); err == nil {
		t.Fatal("unknown-key retirement accepted")
	}
	if _, err := e.BundleTrustRecord(4); !os.IsNotExist(err) {
		t.Fatal("missing trust version not reported", err)
	}
	if _, err := e.BundleTrustRecord(0); !os.IsNotExist(err) {
		t.Fatal("invalid trust version accepted", err)
	}
	first.Payload[0] ^= 1
	intact, err := e.BundleTrustRecord(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTrustBootstrap(intact, conn.BundlePublicKey); err != nil {
		t.Fatal("record accessor leaked mutable state", err)
	}
	restarted := &Engine{Dir: e.Dir}
	if err := restarted.loadBundleKey(); err != nil || !bytes.Equal(e.bundleKey, restarted.bundleKey) || restarted.BundleTrustVersion() != 3 {
		t.Fatal("rotated state lost on restart", err)
	}
	for _, name := range []string{"bundle-trust.json", "bundle-signing." + bID + ".key"} {
		st, err := os.Stat(filepath.Join(e.Dir, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("rotation state not private", name, err)
		}
	}
}

func TestBundleCommitWriteFaults(t *testing.T) {
	for _, failAt := range []string{"key", "manifest", "key directory sync", "manifest directory sync"} {
		t.Run(failAt, func(t *testing.T) {
			e := &Engine{Dir: t.TempDir()}
			if err := e.loadBundleKey(); err != nil {
				t.Fatal(err)
			}
			old := append([]byte(nil), e.bundleKey...)
			oldManifest := readTestBundleManifest(t, e.Dir)
			key := testBundleKey(t)
			id := BundleKeyID(key.Public().(ed25519.PublicKey))
			next := bundleManifest{Records: append(oldManifest.Records, testBundleRecord(t, 2, e.bundleKey, key)), Signer: id}
			sentinel := errors.New("injected write fault")
			writes := []string{}
			write := func(path string, data []byte, mode os.FileMode) error {
				writes = append(writes, filepath.Base(path))
				if (failAt == "key" && len(writes) == 1) || (failAt == "manifest" && len(writes) == 2) {
					return sentinel
				}
				if (failAt == "key directory sync" && len(writes) == 1) || (failAt == "manifest directory sync" && len(writes) == 2) {
					return atomicFile(path, data, mode, func(string) error { return sentinel })
				}
				return AtomicFile(path, data, mode)
			}
			if err := e.commitBundleManifest(next, key, write); !errors.Is(err, sentinel) {
				t.Fatal("write fault lost", err)
			}
			if !bytes.Equal(old, e.bundleKey) || e.BundleTrustVersion() != 1 {
				t.Fatal("failed commit published signer")
			}
			restarted := &Engine{Dir: e.Dir}
			if err := restarted.loadBundleKey(); err != nil {
				t.Fatal("failed commit left unloadable state", err)
			}
			want := old
			if failAt == "manifest directory sync" {
				// Rename happened but durability was not acknowledged. Restart
				// reads the actual visible manifest rather than guessing rollback.
				want = key
			}
			if !bytes.Equal(want, restarted.bundleKey) {
				t.Fatal("restart ignored actual manifest commit point")
			}
			if writes[0] != "bundle-signing."+id+".key" {
				t.Fatal("key not written before manifest")
			}
			if failAt == "manifest" {
				if len(writes) != 2 || writes[1] != "bundle-trust.json" {
					t.Fatal("invalid commit order")
				}
				if _, err := os.Stat(filepath.Join(e.Dir, writes[0])); err != nil {
					t.Fatal("orphan not retained", err)
				}
			}
		})
	}
}
