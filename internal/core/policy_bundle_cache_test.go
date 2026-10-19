package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func cacheTestBootstrap(t *testing.T, version int, key ed25519.PrivateKey) TrustState {
	t.Helper()
	return TrustState{Current: trustTestSign(t, trustTestRecord(version, key), key)}
}

func cacheTestBundle(key ed25519.PrivateKey, revision int) SignedPolicyBundle {
	payload := mustJSON(PolicyBundle{Revision: revision, NodeID: "node", Rules: []Rule{}})
	return SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(key, payload)}
}

func TestPolicyTrustCacheRotationAndRestart(t *testing.T) {
	a, b, c := trustTestKey("cache A"), trustTestKey("cache B"), trustTestKey("cache C")
	bootstrap := cacheTestBootstrap(t, 3, a)
	path := filepath.Join(t.TempDir(), "bundle.json")
	old := cacheTestBundle(a, 7)
	if _, err := CachePolicyBundleWithTrust(path, old, "", bootstrap, "node"); err != nil {
		t.Fatal(err)
	}
	for _, record := range []SignedTrustRecord{
		trustTestSign(t, trustTestRecord(4, a, b), a, b),
		trustTestSign(t, trustTestRecord(5, b), b),
		trustTestSign(t, trustTestRecord(6, b, c), b, c),
		trustTestSign(t, trustTestRecord(7, c), c),
	} {
		if _, err := CachePolicyTrustRecord(path, record, bootstrap, "node"); err != nil {
			t.Fatal(err)
		}
		state, err := ReadPolicyTrust(path, bootstrap)
		if err != nil || state.Cache == nil || !bytes.Equal(state.Cache.Payload, bootstrap.Current.Payload) {
			t.Fatalf("lost cache authority on restart: %+v %v", state, err)
		}
		if _, _, err := ReadPolicyBundleWithTrust(path, state, "node"); err != nil {
			t.Fatalf("old cache lost during catch-up: %v", err)
		}
	}
	for _, tc := range []struct {
		name   string
		signed SignedPolicyBundle
		id     string
	}{
		{"retired network key", old, ""},
		{"forged hint", cacheTestBundle(c, 7), BundleKeyID(a.Public().(ed25519.PublicKey))},
		{"revision rollback", cacheTestBundle(c, 6), ""},
		{"revision identity conflict", cacheTestBundle(c, 7), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed := tc.signed
			if tc.name == "revision identity conflict" {
				signed.Payload = mustJSON(PolicyBundle{Revision: 7, NodeID: "node", Rules: []Rule{{ID: "changed"}}})
				signed.Signature = ed25519.Sign(c, signed.Payload)
			}
			if _, err := CachePolicyBundleWithTrust(path, signed, tc.id, bootstrap, "node"); err == nil {
				t.Fatal("invalid network bundle accepted")
			}
		})
	}
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(c, 7), "", bootstrap, "node"); err != nil {
		t.Fatal("equal-payload re-sign rejected", err)
	}
	state, err := ReadPolicyTrust(path, bootstrap)
	if err != nil || state.Cache != nil {
		t.Fatalf("obsolete cache record not dropped: %v", err)
	}
	for _, name := range []string{"trust.json", "bundle.json"} {
		st, err := os.Stat(filepath.Join(filepath.Dir(path), name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("%s permissions: %v", name, err)
		}
	}
}

func TestPolicyTrustPersistenceRejectsDowngradeAndCorruption(t *testing.T) {
	a, b := trustTestKey("persist A"), trustTestKey("persist B")
	bootstrap := cacheTestBootstrap(t, 3, a)
	newer := cacheTestBootstrap(t, 4, b).Current
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"below bootstrap", mustJSON(cacheTestBootstrap(t, 2, a))},
		{"malformed", []byte("{")},
		{"oversized", bytes.Repeat([]byte(" "), PolicyBundleMaxBytes+1)},
		{"cache newer than current", mustJSON(TrustState{Current: bootstrap.Current, Cache: &newer})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(filepath.Join(filepath.Dir(path), "trust.json"), tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadPolicyTrust(path, bootstrap); err == nil {
				t.Fatal("invalid persisted state accepted")
			}
			if _, err := CachePolicyTrustRecord(path, trustTestSign(t, trustTestRecord(4, b), a, b), bootstrap, "node"); err == nil {
				t.Fatal("corruption silently reset")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	state, err := ReadPolicyTrust(path, bootstrap)
	if err != nil || !bytes.Equal(state.Current.Payload, bootstrap.Current.Payload) {
		t.Fatal("bootstrap not used", err)
	}
	next := trustTestSign(t, trustTestRecord(4, b), a, b)
	if _, err := CachePolicyTrustRecord(path, next, bootstrap, "node"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "trust.json"))
	for _, invalid := range []SignedTrustRecord{bootstrap.Current, next, trustTestSign(t, trustTestRecord(6, b), b)} {
		if _, err := CachePolicyTrustRecord(path, invalid, bootstrap, "node"); err == nil {
			t.Fatal("non-successor accepted")
		}
	}
	after, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "trust.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected record changed durable state")
	}
}

func TestPolicyTrustLegacyCacheMigration(t *testing.T) {
	a, b := trustTestKey("legacy A"), trustTestKey("legacy B")
	pin := a.Public().(ed25519.PublicKey)
	bootstrap, err := BootstrapPolicyTrust(pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if _, err := CachePolicyBundle(path, cacheTestBundle(a, 7), pin, "node"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(policyTrustPath(path)); !os.IsNotExist(err) {
		t.Fatal("legacy cache unexpectedly has trust state")
	}
	state, err := CachePolicyTrustRecord(path, trustTestSign(t, trustTestRecord(2, b), a, b), bootstrap, "node")
	if err != nil {
		t.Fatal(err)
	}
	if _, signer, err := ReadPolicyBundleWithTrust(path, state, "node"); err != nil || signer != BundleKeyID(pin) {
		t.Fatal("pre-upgrade unsigned-anchor cache lost", err)
	}
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(b, 6), "", bootstrap, "node"); err == nil {
		t.Fatal("migration reset revision floor")
	}
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(b, 7), "", bootstrap, "node"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyTrustUsesExistingCacheLock(t *testing.T) {
	a := trustTestKey("locked cache")
	bootstrap := cacheTestBootstrap(t, 1, a)
	path := filepath.Join(t.TempDir(), "bundle.json")
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := lockProcessFile(lock); err != nil {
		t.Fatal(err)
	}
	if _, err := CachePolicyTrustRecord(path, trustTestSign(t, trustTestRecord(2, a), a), bootstrap, "node"); err == nil {
		t.Fatal("record bypassed bundle lock")
	}
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(a, 7), "", bootstrap, "node"); err == nil {
		t.Fatal("bundle bypassed bundle lock")
	}
}

func TestPolicyTrustCacheEnvelopeAndFailureBoundaries(t *testing.T) {
	a, b := trustTestKey("envelope A"), trustTestKey("envelope B")
	bootstrap := cacheTestBootstrap(t, 1, a)
	next := trustTestSign(t, trustTestRecord(2, b), a, b)
	for _, name := range []string{"bad bootstrap", "missing directory", "trust is directory", "lock is directory", "bundle is directory", "bundle is corrupt", "bundle has wrong hint", "bundle exceeds budget"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.json")
			anchor := bootstrap
			signed := cacheTestBundle(a, 7)
			switch name {
			case "bad bootstrap":
				anchor = TrustState{}
			case "missing directory":
				path = filepath.Join(filepath.Dir(path), "missing", "bundle.json")
			case "trust is directory":
				if err := os.Mkdir(policyTrustPath(path), 0700); err != nil {
					t.Fatal(err)
				}
			case "lock is directory":
				if err := os.Mkdir(path+".lock", 0700); err != nil {
					t.Fatal(err)
				}
			case "bundle is directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "bundle is corrupt":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "bundle has wrong hint":
				if err := os.WriteFile(path, mustJSON(policyCacheEnvelope{SignedPolicyBundle: signed, KeyID: BundleKeyID(b.Public().(ed25519.PublicKey))}), 0600); err != nil {
					t.Fatal(err)
				}
			case "bundle exceeds budget":
				signed.Payload = mustJSON(PolicyBundle{Revision: 7, NodeID: "node", Rules: []Rule{{ID: strings.Repeat("x", PolicyBundleMaxBytes)}}})
				signed.Signature = ed25519.Sign(a, signed.Payload)
			}
			if _, err := CachePolicyBundleWithTrust(path, signed, "", anchor, "node"); err == nil {
				t.Fatal("invalid cache operation accepted")
			}
			if name == "bad bootstrap" || name == "missing directory" || name == "trust is directory" || name == "lock is directory" {
				if _, err := CachePolicyTrustRecord(path, next, anchor, "node"); err == nil {
					t.Fatal("invalid record operation accepted")
				}
			}
		})
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	id := BundleKeyID(a.Public().(ed25519.PublicKey))
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(a, 7), id, bootstrap, "node"); err != nil {
		t.Fatal(err)
	}
	if _, signer, err := ReadPolicyBundleWithTrust(path, bootstrap, "node"); err != nil || signer != id {
		t.Fatal("explicit hint round trip", err)
	}
	if _, _, err := ReadPolicyBundleWithTrust(path, bootstrap, "other"); err == nil {
		t.Fatal("wrong node accepted")
	}
	state, err := CachePolicyTrustRecord(path, next, bootstrap, "node")
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the exact durable boundary after bundle replace but before D6's
	// final trust-state replace. Restart must accept the new bundle with cache
	// authority still retained, then safely finish dropping it.
	resigned := cacheTestBundle(b, 7)
	if err := AtomicFile(path, mustJSON(policyCacheEnvelope{SignedPolicyBundle: resigned, KeyID: BundleKeyID(b.Public().(ed25519.PublicKey))}), 0600); err != nil {
		t.Fatal(err)
	}
	state, err = ReadPolicyTrust(path, bootstrap)
	if err != nil || state.Cache == nil {
		t.Fatal("cache record dropped before bundle boundary", err)
	}
	if _, _, err := ReadPolicyBundleWithTrust(path, state, "node"); err != nil {
		t.Fatal("bundle-write interruption unrecoverable", err)
	}
	// The server may rotate again before the interrupted client returns. Keep
	// the record that verifies the bundle actually on disk, not an obsolete one.
	state, err = CachePolicyTrustRecord(path, trustTestSign(t, trustTestRecord(3, a), b, a), bootstrap, "node")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadPolicyBundleWithTrust(path, state, "node"); err != nil {
		t.Fatal("next rotation lost interrupted bundle authority", err)
	}
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(a, 7), "", bootstrap, "node"); err != nil {
		t.Fatal(err)
	}
	state, err = ReadPolicyTrust(path, bootstrap)
	if err != nil || state.Cache != nil {
		t.Fatal("bundle-write recovery failed", err)
	}
}

// D6: cumulative server history exceeds the existing response read budget, but
// each client write retains only current + the old bundle's authority. The child
// is killed immediately after a randomly selected durable record write.
func TestCatchUpBeyondReadBudget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX SIGKILL interruption")
	}
	a := trustTestKey("budget 1")
	bootstrap := cacheTestBootstrap(t, 1, a)
	if path := os.Getenv("TG_TEST_CATCHUP_PATH"); path != "" {
		stop, err := strconv.Atoi(os.Getenv("TG_TEST_CATCHUP_STOP"))
		if err != nil {
			t.Fatal(err)
		}
		for version := 2; version <= stop; version++ {
			previous, next := trustTestKey(fmt.Sprint("budget ", version-1)), trustTestKey(fmt.Sprint("budget ", version))
			record := trustTestSign(t, trustTestRecord(version, next), previous, next)
			if _, err := CachePolicyTrustRecord(path, record, bootstrap, "node"); err != nil {
				t.Fatal(err)
			}
		}
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if err := process.Kill(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("kill returned")
	}
	var history []SignedTrustRecord
	total := 0
	for version := 2; total <= PolicyBundleMaxBytes; version++ {
		previous, next := trustTestKey(fmt.Sprint("budget ", version-1)), trustTestKey(fmt.Sprint("budget ", version))
		record := trustTestSign(t, trustTestRecord(version, next), previous, next)
		history = append(history, record)
		total += len(mustJSON(record))
	}
	interruption, err := rand.Int(rand.Reader, big.NewInt(int64(len(history)-1)))
	if err != nil {
		t.Fatal(err)
	}
	stop := int(interruption.Int64()) + 2
	t.Logf("history_bytes=%d records=%d interrupt_after_version=%d", total, len(history), stop)
	path := filepath.Join(t.TempDir(), "bundle.json")
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(a, 7), "", bootstrap, "node"); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestCatchUpBeyondReadBudget$")
	command.Env = append(os.Environ(), "TG_TEST_CATCHUP_PATH="+path, "TG_TEST_CATCHUP_STOP="+strconv.Itoa(stop))
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatal("child survived interruption", string(output))
	} else if !strings.Contains(err.Error(), "killed") {
		t.Fatalf("child did not reach kill boundary: %v %s", err, output)
	}
	state, err := ReadPolicyTrust(path, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := parseTrustState(state)
	if err != nil || current.Version != stop {
		t.Fatalf("progress lost: %d %v", current.Version, err)
	}
	for _, record := range history[stop-1:] {
		state, err = CachePolicyTrustRecord(path, record, bootstrap, "node")
		if err != nil {
			t.Fatal(err)
		}
		cached, _, err := ReadPolicyBundleWithTrust(path, state, "node")
		if err != nil {
			t.Fatal("cache floor lost", err)
		}
		bundle, _, err := VerifyCachedPolicyBundle(cached, "", state, "node")
		if err != nil || bundle.Revision != 7 {
			t.Fatal("revision floor reset", err)
		}
	}
	latest := trustTestKey(fmt.Sprint("budget ", len(history)+1))
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(latest, 6), "", bootstrap, "node"); err == nil {
		t.Fatal("restart reset rollback floor")
	}
	if _, err := CachePolicyBundleWithTrust(path, cacheTestBundle(latest, 7), "", bootstrap, "node"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(path), "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) > 2 || len(data) > PolicyBundleMaxBytes {
		t.Fatal("unbounded trust state", err)
	}
	state, err = ReadPolicyTrust(path, bootstrap)
	if err != nil || state.Cache != nil {
		t.Fatal("post-bundle state not compacted", err)
	}
	if _, _, err := ReadPolicyBundleWithTrust(path, state, "node"); err != nil {
		t.Fatal(err)
	}
}
