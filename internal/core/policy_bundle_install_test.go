package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBundleEnrollmentKeySurvivesInstallAndRetry(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "invalid key"}[invalid], func(t *testing.T) {
			key := []byte(public)
			if invalid {
				key = nil
			}
			connection := ClientConnection{Token: strings.Repeat("a", 64), NodeID: strings.Repeat("b", 32), BundlePublicKey: key}
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(connection) }))
			defer live.Close()
			o := clientFixture(t, "claude")
			o.Endpoint, o.Token, o.EnrollmentCode = live.URL, "", strings.Repeat("c", 64)
			_, err := ClientOperation("install", o)
			if invalid {
				if err == nil {
					t.Fatal("missing enrollment key accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(o.Dir, "adapter", "connection.json")
			read := func() ClientConnection {
				t.Helper()
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var saved ClientConnection
				if err = json.Unmarshal(data, &saved); err != nil || !bytes.Equal(saved.BundlePublicKey, public) {
					t.Fatal("verification key lost during install/retry")
				}
				return saved
			}
			read()
			o.EnrollmentCode = ""
			if _, err = ClientOperation("install", o); err != nil {
				t.Fatal(err)
			}
			saved := read()
			payload := mustJSON(PolicyBundle{Revision: 1, NodeID: saved.NodeID, Rules: []Rule{}})
			cache := filepath.Join(o.Dir, "adapter", "bundle.json")
			if _, err = CachePolicyBundle(cache, SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}, public, saved.NodeID); err != nil {
				t.Fatal(err)
			}
			if _, err = ClientOperation("uninstall", o); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(cache); !os.IsNotExist(err) {
				t.Fatal("uninstall retained obsolete identity cache")
			}
		})
	}
}

// Plan #65 §3.4/§6: retry keeps the authenticated v3 snapshot; live trust never
// rewrites the installer's hash-owned connection.json (§4 and D6).
func TestBundleTrustInstallRetryAndConnectionDigest(t *testing.T) {
	a, b, c := trustTestKey("install A"), trustTestKey("install B"), trustTestKey("install C")
	v1 := trustTestRecord(1, a)
	v2 := trustTestSign(t, trustTestRecord(2, a, b), a, b)
	previous, err := VerifyTrustRecord(v2, v1)
	if err != nil {
		t.Fatal(err)
	}
	v3 := trustTestSign(t, trustTestRecord(3, b, c), b, c)
	if _, err := VerifyTrustRecord(v3, previous); err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh v3", true: "legacy"}[legacy], func(t *testing.T) {
			connection := ClientConnection{Token: strings.Repeat("a", 64), NodeID: strings.Repeat("b", 32), BundlePublicKey: c.Public().(ed25519.PublicKey)}
			if !legacy {
				connection.BundleTrust = &v3
			}
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(connection) }))
			defer live.Close()
			o := clientFixture(t, "claude")
			o.Endpoint, o.Token, o.EnrollmentCode = live.URL, "", strings.Repeat("c", 64)
			resources := o.Resources
			o.Resources = nil // Consumed enrollment must survive a later install failure.
			if _, err := ClientOperation("install", o); err == nil {
				t.Fatal("missing resources accepted")
			}
			connection.Endpoint = live.URL
			pending, err := os.ReadFile(filepath.Join(o.Dir, "enrolled.json"))
			if err != nil || !bytes.Equal(pending, mustJSON(connection)) {
				t.Fatal("enrollment snapshot lost before retry", err)
			}
			o.Resources, o.EnrollmentCode = resources, ""
			if _, err := ClientOperation("install", o); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(o.Dir, "adapter", "connection.json")
			installed, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, mustJSON(connection)) {
				t.Fatal("connection snapshot changed during install", err)
			}
			bootstrap, err := BootstrapPolicyTrust(connection.BundlePublicKey, connection.BundleTrust)
			if err != nil {
				t.Fatal(err)
			}
			current, _, err := parseTrustState(bootstrap)
			if err != nil || (!legacy && current.Version != 3) || (legacy && current.Version != 1) {
				t.Fatal("bootstrap version reset", err)
			}
			cache := filepath.Join(o.Dir, "adapter", "bundle.json")
			payload := mustJSON(PolicyBundle{Revision: 7, NodeID: connection.NodeID, Rules: []Rule{}})
			signed := SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(c, payload)}
			if _, err := CachePolicyBundleWithTrust(cache, signed, BundleKeyID(connection.BundlePublicKey), bootstrap, connection.NodeID); err != nil {
				t.Fatal("fresh bootstrap needed an earlier record", err)
			}
			next := trustTestSign(t, trustTestRecord(current.Version+1, c, a), c, a)
			if _, err := CachePolicyTrustRecord(cache, next, bootstrap, connection.NodeID); err != nil {
				t.Fatal(err)
			}
			if _, err := ClientOperation("install", o); err != nil {
				t.Fatal("live trust changed installer identity", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("live trust changed connection.json bytes", err)
			}
			retried, err := os.Stat(path)
			if err != nil || !os.SameFile(installed, retried) {
				t.Fatal("retry replaced the immutable connection snapshot", err)
			}
			var manifest clientManifest
			data, err := os.ReadFile(filepath.Join(o.Dir, "client.json"))
			if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.Resources["connection.json"] != digestBytes(before) {
				t.Fatal("connection digest changed", err)
			}
		})
	}
}

func TestBundleTrustInstallRejectsInvalidBootstrap(t *testing.T) {
	a, b := trustTestKey("install valid pin"), trustTestKey("install foreign pin")
	for _, record := range []SignedTrustRecord{
		trustTestSign(t, trustTestRecord(3, b), b),
		{Payload: trustTestSign(t, trustTestRecord(3, a), a).Payload},
	} {
		t.Run(string(record.Payload), func(t *testing.T) {
			o := clientFixture(t, "claude")
			connection := ClientConnection{Token: strings.Repeat("a", 64), NodeID: strings.Repeat("b", 32), BundlePublicKey: a.Public().(ed25519.PublicKey), BundleTrust: &record}
			live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(connection) }))
			defer live.Close()
			o.Endpoint, o.Token, o.EnrollmentCode = live.URL, "", strings.Repeat("c", 64)
			if _, err := ClientOperation("install", o); err == nil {
				t.Fatal("invalid bootstrap installed")
			}
			o.EnrollmentCode = ""
			if _, err := ClientOperation("install", o); err == nil {
				t.Fatal("invalid bootstrap accepted on retry")
			}
			if _, err := os.Stat(filepath.Join(o.Dir, "adapter", "connection.json")); !os.IsNotExist(err) {
				t.Fatal("invalid bootstrap activated")
			}
		})
	}
}

// §4 requires re-provable ownership before removal. D6 compaction deliberately
// discards intermediates: a jump is retained/reported, never guessed to be owned.
func TestBundleTrustUninstallCleanupAndRetention(t *testing.T) {
	a, b, c := trustTestKey("cleanup A"), trustTestKey("cleanup B"), trustTestKey("cleanup C")
	bootstrap := cacheTestBootstrap(t, 1, a)
	next := trustTestSign(t, trustTestRecord(2, a, b), a, b)
	for _, name := range []string{"bootstrap", "successor", "successor bundle", "retired cache", "compacted jump", "foreign", "corrupt trust", "oversized trust", "corrupt bundle", "modified connection", "trust only", "bundle only", "neither", "busy lock", "symlink trust", "symlink bundle"} {
		t.Run(name, func(t *testing.T) {
			o := clientFixture(t, "claude")
			o.BundlePublicKey = a.Public().(ed25519.PublicKey)
			if _, err := ClientOperation("install", o); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(o.Dir, "adapter")
			path, trustPath := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "trust.json")
			var conn ClientConnection
			data, err := os.ReadFile(filepath.Join(dir, "connection.json"))
			if err != nil || json.Unmarshal(data, &conn) != nil {
				t.Fatal(err)
			}
			payload := mustJSON(PolicyBundle{Revision: 7, NodeID: conn.NodeID, Rules: []Rule{}})
			signed := SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(a, payload)}
			if _, err := CachePolicyBundleWithTrust(path, signed, "", bootstrap, conn.NodeID); err != nil {
				t.Fatal(err)
			}
			write := func(p string, b []byte) {
				t.Helper()
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(p string) {
				t.Helper()
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "successor", "successor bundle", "retired cache", "compacted jump":
				if _, err := CachePolicyTrustRecord(path, next, bootstrap, conn.NodeID); err != nil {
					t.Fatal(err)
				}
				if name == "retired cache" || name == "compacted jump" {
					if _, err := CachePolicyTrustRecord(path, trustTestSign(t, trustTestRecord(3, b), b), bootstrap, conn.NodeID); err != nil {
						t.Fatal(err)
					}
				}
				if name == "compacted jump" || name == "successor bundle" {
					signed.Signature = ed25519.Sign(b, payload)
					if _, err := CachePolicyBundleWithTrust(path, signed, "", bootstrap, conn.NodeID); err != nil {
						t.Fatal(err)
					}
				}
			case "foreign":
				write(trustPath, mustJSON(cacheTestBootstrap(t, 1, c)))
			case "corrupt trust":
				write(trustPath, []byte("{"))
			case "oversized trust":
				write(trustPath, bytes.Repeat([]byte(" "), PolicyBundleMaxBytes+1))
			case "corrupt bundle":
				write(path, []byte("{"))
			case "modified connection":
				write(filepath.Join(dir, "connection.json"), append(data, '\n'))
			case "trust only":
				remove(path)
			case "bundle only":
				remove(trustPath)
			case "neither":
				remove(path)
				remove(trustPath)
			case "busy lock":
				lock, err := lockPolicyCache(path)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			case "symlink trust", "symlink bundle":
				mustHaveSymlink(t)
				p := path
				if name == "symlink trust" {
					p = trustPath
				}
				remove(p)
				foreign := filepath.Join(t.TempDir(), "foreign.json")
				write(foreign, []byte("{}"))
				if err := os.Symlink(foreign, p); err != nil {
					t.Fatal(err)
				}
			}
			keep := !slices.Contains([]string{"bootstrap", "successor", "successor bundle", "trust only", "bundle only", "neither"}, name)
			before := map[string][]byte{}
			for _, p := range []string{path, trustPath} {
				before[p], _ = os.ReadFile(p)
			}
			result, err := ClientOperation("uninstall", o)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{path, trustPath} {
				_, err := os.Lstat(p)
				if keep {
					after, readErr := os.ReadFile(p)
					if err != nil || readErr != nil || !bytes.Equal(after, before[p]) || !slices.Contains(result.Retained, p) {
						t.Fatalf("unverifiable file not retained/reported: %s, %v", p, result.Retained)
					}
				} else if !os.IsNotExist(err) || slices.Contains(result.Retained, p) {
					t.Fatalf("owned file not cleaned: %s, %v", p, result.Retained)
				}
			}
			if _, err := os.Stat(path + ".lock"); err != nil {
				t.Fatal("lock inode removed", err)
			}
		})
	}
}

// Review probe: the adapter path is a symlink, but its children are regular files.
func TestReviewS7RetainsSymlinkedAdapterTrust(t *testing.T) {
	mustHaveSymlink(t)
	a := trustTestKey("review parent symlink")
	o := clientFixture(t, "claude")
	o.BundlePublicKey = a.Public().(ed25519.PublicKey)
	if _, err := ClientOperation("install", o); err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(o.Dir, "adapter")
	bootstrap := cacheTestBootstrap(t, 1, a)
	if err := os.WriteFile(filepath.Join(adapter, "trust.json"), mustJSON(bootstrap), 0600); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external-adapter")
	if err := os.Rename(adapter, external); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, adapter); err != nil {
		t.Fatal(err)
	}
	result, err := ClientOperation("uninstall", o)
	if err != nil {
		t.Fatal(err)
	}
	retained := result.Retained
	if _, err := os.Stat(filepath.Join(external, "trust.json")); err != nil {
		t.Fatalf("cleanup deleted trust through symlinked adapter; retained=%v: %v", retained, err)
	}
	if !slices.Contains(retained, adapter) || !strings.Contains(result.Warning, "symlink or not a directory") {
		t.Fatalf("symlinked adapter not retained/reported with reason: %+v", result)
	}
	if data, err := os.ReadFile(filepath.Join(external, "trust.json")); err != nil || !bytes.Equal(data, mustJSON(bootstrap)) {
		t.Fatal("external trust changed", err)
	}
	// The shared cleanup entry also protects the machine caller without changes there.
	if retained := removeClientPolicyState(o.Dir, ""); !slices.Contains(retained, adapter) {
		t.Fatalf("shared cleanup followed adapter symlink: %v", retained)
	}
	if _, err := os.Lstat(adapter); err != nil {
		t.Fatal("adapter symlink removed", err)
	}
	if _, err := os.Stat(filepath.Join(external, "bundle.json.lock")); !os.IsNotExist(err) {
		t.Fatal("cleanup touched external lock", err)
	}
	if _, err := os.Stat(filepath.Join(external, "connection.json")); err != nil {
		t.Fatal("cleanup removed external connection", err)
	}
}

func TestBundleTrustCleanupRejectsNonDirectoryAdapter(t *testing.T) {
	o := clientFixture(t, "claude")
	if _, err := ClientOperation("install", o); err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(o.Dir, "adapter")
	saved := filepath.Join(t.TempDir(), "saved-adapter")
	if err := os.Rename(adapter, saved); err != nil {
		t.Fatal(err)
	}
	contents := []byte("not an adapter directory")
	if err := os.WriteFile(adapter, contents, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := ClientOperation("uninstall", o)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(result.Retained, adapter) || result.Warning == "" {
		t.Fatalf("non-directory adapter not retained with reason: %+v", result)
	}
	if data, err := os.ReadFile(adapter); err != nil || !bytes.Equal(data, contents) {
		t.Fatal("non-directory adapter changed", err)
	}
	if retained := removeClientPolicyState(o.Dir, ""); !slices.Contains(retained, adapter) {
		t.Fatalf("shared cleanup did not retain non-directory adapter: %v", retained)
	}
}

func TestBundleTrustCleanupMissingAdapter(t *testing.T) {
	dir := t.TempDir()
	if err := clientAdapterDirectoryError(dir); err != nil {
		t.Fatal(err)
	}
	if retained := removeClientPolicyState(dir, ""); len(retained) != 0 {
		t.Fatalf("missing adapter reported as retained: %v", retained)
	}
	// A regular file in an ancestor makes Lstat fail with ENOTDIR, not absence.
	ancestor := filepath.Join(dir, "file")
	if err := os.WriteFile(ancestor, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := clientAdapterDirectoryError(filepath.Join(ancestor, "child")); err == nil {
		t.Fatal("adapter inspection error accepted")
	}
}
