//go:build unix

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
	"strings"
	"testing"
)

func machineFixture(t *testing.T) MachineOptions {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "TG-Sentry")
	binary := filepath.Join(base, "aegishook")
	if err := os.WriteFile(binary, []byte("binary fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	o := MachineOptions{Root: root, Binary: binary, Endpoint: "https://review.example", ValidatePath: func(path string, private bool) error {
		return validateMachineUnixPath(path, private, uint32(os.Getuid()))
	}}
	if err := os.MkdirAll(MachinePaths(root).Private, 0700); err != nil {
		t.Fatal(err)
	}
	return o
}
func machineWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestMachineInstallLayoutAndNoApproval(t *testing.T) {
	o := machineFixture(t)
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	p := MachinePaths(o.Root)
	for _, path := range []string{p.Run, p.Private, p.Manifest, filepath.Join(p.Private, "client.lock")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(p.Private, "managed")); !os.IsNotExist(err) {
		t.Fatal("machine hooks generated")
	}
	if _, err := os.Stat(p.Connection); !os.IsNotExist(err) {
		t.Fatal("approval fallback created credential")
	}
	if _, err := os.Stat(filepath.Join(p.Private, "request.json")); !os.IsNotExist(err) {
		t.Fatal("approval fallback used")
	}
	if ok := MachineInstalled(o); !ok {
		t.Fatal("installed hash not detected")
	}
	machineWrite(t, o.Binary, []byte("changed binary"))
	if MachineInstalled(o) {
		t.Fatal("changed binary accepted")
	}
}

func TestMachineInstallEnrollmentRollbackRetry(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/client/enroll" {
			t.Errorf("approval fallback or wrong path: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		count++
		json.NewEncoder(w).Encode(ClientConnection{NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: public})
	}))
	defer server.Close()
	o := machineFixture(t)
	o.Endpoint = server.URL
	o.NoCommit = true
	p := MachinePaths(o.Root)
	machineWrite(t, p.Code, []byte(strings.Repeat("c", 64)))
	if _, err = MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	retry, _ := os.ReadFile(p.Enrolled)
	if len(retry) == 0 {
		t.Fatal("retry not durable")
	}
	if _, err = os.Stat(p.Code); !os.IsNotExist(err) {
		t.Fatal("successful setup code retained")
	}
	if _, err = MachineOperation("rollback", o); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p.Enrolled)
	if !bytes.Equal(got, retry) {
		t.Fatal("rollback lost enrollment")
	}
	if _, err = MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("retry consumed another key: %d", count)
	}
	if _, err = MachineOperation("commit", o); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.Enrolled, p.Rollback, p.Code} {
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("commit retained %s", path)
		}
	}
	if _, err = MachineOperation("commit", o); err != nil {
		t.Fatal("commit not idempotent", err)
	}
	o.Endpoint = "https://different.example"
	if _, err = MachineOperation("system-install", o); err == nil {
		t.Fatal("endpoint mismatch accepted")
	}
}

func TestMachineInstallRollbackNeverOverwritesEnrollment(t *testing.T) {
	o := machineFixture(t)
	o.NoCommit = true
	p := MachinePaths(o.Root)
	prior := mustJSON(ClientConnection{Endpoint: o.Endpoint, NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: make([]byte, 32)})
	machineWrite(t, p.Enrolled, prior)
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	next := append([]byte(" "), prior...)
	machineWrite(t, p.Enrolled, next)
	if _, err := MachineOperation("rollback", o); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p.Enrolled)
	if !bytes.Equal(got, next) {
		t.Fatal("rollback overwrote new retry")
	}
}

func TestMachineInstallRefusesUnsafeProvisioning(t *testing.T) {
	for _, kind := range []string{"private-mode", "root-mode", "symlink", "file-mode", "owner", "oversize", "server-dir"} {
		t.Run(kind, func(t *testing.T) {
			o := machineFixture(t)
			p := MachinePaths(o.Root)
			machineWrite(t, p.Code, []byte(strings.Repeat("c", 64)))
			switch kind {
			case "private-mode":
				os.Chmod(p.Private, 0755)
			case "root-mode":
				os.Chmod(p.Root, 0777)
			case "symlink":
				os.Rename(p.Private, p.Private+"-real")
				os.Symlink(p.Private+"-real", p.Private)
			case "file-mode":
				os.Chmod(p.Code, 0644)
			case "owner":
				o.ValidatePath = func(path string, private bool) error { return os.ErrPermission }
			case "oversize":
				machineWrite(t, p.Code, bytes.Repeat([]byte("c"), 8193))
			case "server-dir":
				machineWrite(t, filepath.Join(p.Root, "aegishook.db"), []byte("server"))
			}
			if _, err := MachineOperation("system-install", o); err == nil {
				t.Fatal("unsafe provisioning accepted")
			}
			if _, err := os.Stat(p.Code); err != nil {
				t.Fatal("read/refusal consumed setup code", err)
			}
			if _, err := os.Stat(p.Enrolled); !os.IsNotExist(err) {
				t.Fatal("enrolled before validation")
			}
		})
	}
}

func TestMachineInstallBundleAndUninstallOwnership(t *testing.T) {
	o := machineFixture(t)
	p := MachinePaths(o.Root)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	conn := ClientConnection{Endpoint: o.Endpoint, NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: public}
	machineWrite(t, p.Enrolled, mustJSON(conn))
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	payload := mustJSON(PolicyBundle{Revision: 2, NodeID: conn.NodeID, Rules: []Rule{}})
	signed := SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}
	if _, err := CachePolicyBundle(p.Bundle, signed, public, conn.NodeID); err != nil {
		t.Fatal(err)
	}
	old := mustJSON(PolicyBundle{Revision: 1, NodeID: conn.NodeID, Rules: []Rule{}})
	if _, err := CachePolicyBundle(p.Bundle, SignedPolicyBundle{Payload: old, Signature: ed25519.Sign(private, old)}, public, conn.NodeID); err == nil {
		t.Fatal("machine bundle rollback accepted")
	}
	foreign := filepath.Join(p.Private, "foreign")
	machineWrite(t, foreign, []byte("keep"))
	result, err := MachineOperation("system-uninstall", o)
	if err == nil || len(result.Retained) == 0 {
		t.Fatal("foreign files not reported", err)
	}
	if b, _ := os.ReadFile(foreign); string(b) != "keep" {
		t.Fatal("foreign file removed")
	}
	if _, err := os.Stat(p.Connection); !os.IsNotExist(err) {
		t.Fatal("owned connection retained")
	}
}

func TestMachineInstallUpgradeRollbackRestoresSnapshot(t *testing.T) {
	o := machineFixture(t)
	p := MachinePaths(o.Root)
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	beforeManifest, _ := os.ReadFile(p.Manifest)
	beforeConfig, _ := os.ReadFile(p.Config)
	o.NoCommit = true
	o.Owner = "replacement-owner"
	machineWrite(t, o.Binary, []byte("upgraded binary"))
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	if _, err := MachineOperation("system-install", o); err == nil {
		t.Fatal("nested transaction accepted")
	}
	if _, err := MachineOperation("rollback", o); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{p.Manifest: beforeManifest, p.Config: beforeConfig} {
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, want) {
			t.Fatalf("not restored: %s", path)
		}
	}
	if _, err := MachineOperation("rollback", o); err != nil {
		t.Fatal("rollback not idempotent", err)
	}
}

func TestMachineInstallManagedReferencesAndCorruptOwnership(t *testing.T) {
	for _, kind := range []string{"clean", "managed", "config", "connection", "manifest", "runtime", "foreign-runtime"} {
		t.Run(kind, func(t *testing.T) {
			o := machineFixture(t)
			p := MachinePaths(o.Root)
			machineWrite(t, p.Enrolled, mustJSON(ClientConnection{Endpoint: o.Endpoint, NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: make([]byte, 32)}))
			if _, err := MachineOperation("system-install", o); err != nil {
				t.Fatal(err)
			}
			var modified string
			switch kind {
			case "managed":
				modified = filepath.Join(t.TempDir(), "managed-settings.json")
				machineWrite(t, modified, mustJSON(map[string]string{"command": o.Binary + " hook"}))
				o.ManagedFiles = []string{modified, filepath.Join(t.TempDir(), "absent")}
			case "config":
				modified = p.Config
			case "connection":
				modified = p.Connection
			case "manifest":
				modified = p.Manifest
			case "runtime":
				modified = filepath.Join(p.Private, "adapter", "runtime.json")
			case "foreign-runtime":
				machineWrite(t, p.Manifest, mustJSON(clientManifest{Format: 1, NodeID: strings.Repeat("b", 32), Resources: map[string]string{}}))
				modified = filepath.Join(p.Private, "adapter", "runtime.json")
			}
			if modified != "" && kind != "managed" {
				machineWrite(t, modified, []byte("foreign content"))
			}
			_, err := MachineOperation("system-uninstall", o)
			if kind == "clean" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("modified/managed content not retained")
			}
			if _, err = os.Stat(modified); err != nil {
				t.Fatal("foreign resource removed", err)
			}
			if kind == "managed" {
				if _, err = os.Stat(p.Manifest); err != nil {
					t.Fatal("managed guard mutated machine")
				}
				o.AcknowledgeManaged = true
				if _, err = MachineOperation("system-uninstall", o); err != nil {
					t.Fatal("acknowledgment ineffective", err)
				}
				if _, err = os.Stat(modified); err != nil {
					t.Fatal("managed file removed by ctl")
				}
			}
		})
	}
}

func TestMachineInstallBundleRevalidationAndCommitGarbage(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	mode := "valid"
	node := strings.Repeat("b", 32)
	payload := mustJSON(PolicyBundle{NodeID: node, Revision: 2, Rules: []Rule{}})
	signed := SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(key, payload)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
			t.Error("missing bearer")
		}
		switch mode {
		case "304":
			w.Header().Set("ETag", PolicyBundleETag(signed))
			w.WriteHeader(304)
		case "wrong304":
			w.WriteHeader(304)
		case "bad-json":
			w.Write([]byte("invalid"))
		case "bad-etag":
			w.Header().Set("ETag", "mismatch")
			json.NewEncoder(w).Encode(signed)
		case "revoked":
			w.WriteHeader(403)
		case "redirect":
			http.Redirect(w, r, "/different", http.StatusFound)
		case "oversize":
			w.Write(bytes.Repeat([]byte(" "), PolicyBundleMaxBytes+1))
		case "bad-signature":
			broken := signed
			broken.Signature = make([]byte, 64)
			json.NewEncoder(w).Encode(broken)
		case "rollback":
			old := mustJSON(PolicyBundle{NodeID: node, Revision: 1, Rules: []Rule{}})
			json.NewEncoder(w).Encode(SignedPolicyBundle{Payload: old, Signature: ed25519.Sign(key, old)})
		case "conflict":
			other := mustJSON(PolicyBundle{NodeID: node, Revision: 2, Rules: nil})
			json.NewEncoder(w).Encode(SignedPolicyBundle{Payload: other, Signature: ed25519.Sign(key, other)})
		default:
			w.Header().Set("ETag", PolicyBundleETag(signed))
			json.NewEncoder(w).Encode(signed)
		}
	}))
	defer server.Close()
	o := machineFixture(t)
	o.Endpoint = server.URL
	o.NoCommit = true
	p := MachinePaths(o.Root)
	machineWrite(t, p.Enrolled, mustJSON(ClientConnection{Endpoint: o.Endpoint, Token: strings.Repeat("a", 64), NodeID: node, BundlePublicKey: public}))
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	mode = "wrong304"
	if MachineEnrolled(o) == nil {
		t.Fatal("304 accepted without trusted cache")
	}
	mode = "valid"
	if err := MachineEnrolled(o); err != nil {
		t.Fatal(err)
	}
	mode = "304"
	if err := MachineEnrolled(o); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"wrong304", "bad-json", "bad-etag", "revoked", "redirect", "oversize", "bad-signature", "rollback", "conflict"} {
		mode = bad
		if err := MachineEnrolled(o); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	mode = "304"
	o.NoCommit = false
	if _, err := MachineOperation("system-install", o); err == nil {
		t.Fatal("pending snapshot implicitly committed")
	}
	// Simulate an explicit commit interrupted after its durable marker.
	machineWrite(t, filepath.Join(p.Rollback, ".committed"), []byte("committed\n"))
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal("committed garbage collection failed", err)
	}
	for _, path := range []string{p.Rollback, p.Enrolled} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("D3 garbage retained", path)
		}
	}
	machineWrite(t, p.Bundle, []byte("corrupt cache"))
	if MachineEnrolled(o) == nil {
		t.Fatal("corrupt machine cache accepted")
	}
	server.Close()
	os.Remove(p.Bundle)
	if MachineEnrolled(o) == nil {
		t.Fatal("offline accepted")
	}
}

func TestMachineInstallBoundaryAndRecoveryFailures(t *testing.T) {
	for _, kind := range []string{"action", "root", "empty-code", "bad-code", "no-endpoint", "bad-endpoint", "bad-config", "bad-manifest", "missing-binary", "relative-binary", "missing-private", "unsafe-new-directory"} {
		t.Run(kind, func(t *testing.T) {
			o := machineFixture(t)
			p := MachinePaths(o.Root)
			action := "system-install"
			wantError := true
			switch kind {
			case "action":
				action = "unknown"
			case "root":
				o.Root = string(filepath.Separator)
			case "empty-code":
				machineWrite(t, p.Code, nil)
			case "bad-code":
				machineWrite(t, p.Code, []byte("invalid"))
			case "no-endpoint":
				o.Endpoint = ""
				machineWrite(t, p.Code, []byte(strings.Repeat("c", 64)))
			case "bad-endpoint":
				o.Endpoint = "http://nonloopback.example"
			case "bad-config":
				machineWrite(t, p.Config, []byte("broken"))
			case "bad-manifest":
				machineWrite(t, p.Manifest, []byte("broken"))
			case "missing-binary":
				os.Remove(o.Binary)
			case "relative-binary":
				o.Binary = "relative"
			case "missing-private":
				os.Remove(p.Private)
				wantError = false
			case "unsafe-new-directory":
				os.Remove(p.Private)
				o.ValidatePath = func(path string, private bool) error {
					if path == p.Private {
						return os.ErrPermission
					}
					return nil
				}
			}
			_, err := MachineOperation(action, o)
			if (err != nil) != wantError {
				t.Fatalf("error=%v, wantError=%v", err, wantError)
			}
		})
	}
	// Failure after enrollment must not require another setup key.
	o := machineFixture(t)
	p := MachinePaths(o.Root)
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := os.MkdirAll(filepath.Dir(p.Manifest), 0700); err != nil {
			t.Error(err)
		}
		// The caller is a privileged failure fixture, not an untrusted writer.
		os.Mkdir(p.Manifest, 0700)
		json.NewEncoder(w).Encode(ClientConnection{NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: public})
	}))
	defer server.Close()
	o.Endpoint = server.URL
	o.NoCommit = true
	machineWrite(t, p.Code, []byte(strings.Repeat("c", 64)))
	if _, err := MachineOperation("system-install", o); err == nil {
		t.Fatal("forced post-enrollment failure not reached")
	}
	if _, err := os.Stat(p.Enrolled); err != nil {
		t.Fatal("lost retry credential", err)
	}
	os.Remove(p.Manifest)
	if _, err := MachineOperation("rollback", o); err != nil {
		t.Fatal(err)
	}
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal("retry failed", err)
	}
}

func TestMachineInstallUserHookStatusUsesActualConfig(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "cursor", "grok", "opencode", "pi"} {
		t.Run(agent, func(t *testing.T) {
			home := t.TempDir()
			o := clientFixture(t, agent)
			o.Dir = filepath.Join(home, ".aegishook-client")
			if ClientHooksConfigured(home) {
				t.Fatal("missing hooks reported configured")
			}
			r, err := ClientOperation("install", o)
			if err != nil {
				t.Fatal(err)
			}
			if !ClientHooksConfigured(home) {
				t.Fatal("real hooks missed")
			}
			if agent == "pi" {
				os.Remove(r.Entry)
			} else {
				machineWrite(t, r.Entry, []byte("{}"))
			}
			if ClientHooksConfigured(home) {
				t.Fatal("modified/deleted hook reported configured")
			}
		})
	}
}

func TestMachineInstallSecureSubtreeAllowsAncestorCreateRights(t *testing.T) {
	o := machineFixture(t)
	p := MachinePaths(o.Root)
	if err := os.Chmod(filepath.Dir(o.Root), 0777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal("ancestor create rights over-rejected", err)
	}
	if err := os.Chmod(p.Private, 0500); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineUnixPath(p.Private, true, uint32(os.Getuid())); err != nil {
		t.Fatal("equivalent root-only permissions rejected", err)
	}
	os.Chmod(p.Private, 0700)
	if err := os.Chmod(p.Config, 0400); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineUnixPath(p.Config, true, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineUnixPath(filepath.Join(p.Private, "absent"), true, uint32(os.Getuid())); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestMachineInstallCommitNoEnrollmentAndDefaultValidation(t *testing.T) {
	o := machineFixture(t)
	o.NoCommit = true
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	if _, err := MachineOperation("commit", o); err != nil {
		t.Fatal("unenrolled install cannot commit", err)
	}
	p := MachinePaths(o.Root)
	machineWrite(t, p.Enrolled, []byte("retry"))
	if _, err := MachineOperation("commit", o); err == nil {
		t.Fatal("discarded uninstalled retry")
	}
	if _, err := os.Stat(p.Enrolled); err != nil {
		t.Fatal(err)
	}
	if MachineEnrolled(o) == nil {
		t.Fatal("missing connection enrolled")
	}
	o.ValidatePath = nil
	if os.Getuid() == 0 {
		if _, err := MachineOperation("rollback", o); err != nil {
			t.Fatal("native root validation failed", err)
		}
	}
	if DefaultRoot() == "" || PackageRoot() == "" {
		t.Fatal("missing machine paths")
	}
}

func TestMachineInstallReviewEnrolledNestedTransaction(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node := strings.Repeat("b", 32)
	payload := mustJSON(PolicyBundle{NodeID: node, Revision: 2, Rules: []Rule{}})
	signed := SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(key, payload)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(signed) }))
	defer server.Close()
	o := machineFixture(t)
	o.Endpoint = server.URL
	o.Owner = "original"
	p := MachinePaths(o.Root)
	machineWrite(t, p.Enrolled, mustJSON(ClientConnection{Endpoint: o.Endpoint, NodeID: node, Token: strings.Repeat("a", 64), BundlePublicKey: public}))
	if _, err = MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(p.Config)
	if err != nil {
		t.Fatal(err)
	}
	o.NoCommit = true
	o.Owner = "pending"
	if _, err = MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	baseline, _ := os.ReadFile(filepath.Join(p.Rollback, "config.json"))
	retry, _ := os.ReadFile(p.Enrolled)
	for _, noCommit := range []bool{false, true} {
		o.NoCommit = noCommit
		if _, err = MachineOperation("system-install", o); err == nil {
			t.Fatal("nested pending transaction accepted")
		}
		got, _ := os.ReadFile(filepath.Join(p.Rollback, "config.json"))
		if !bytes.Equal(got, baseline) {
			t.Fatal("pending baseline changed")
		}
		got, _ = os.ReadFile(p.Enrolled)
		if !bytes.Equal(got, retry) {
			t.Fatal("pending retry changed")
		}
	}
	if _, err = MachineOperation("rollback", o); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p.Config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("second no-commit accepted and lost rollback baseline: got %s want %s", got, original)
	}
}

func TestMachineInstallReviewInterruptedRollbackCleanup(t *testing.T) {
	o := machineFixture(t)
	o.Owner = "original"
	p := MachinePaths(o.Root)
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	o.NoCommit = true
	o.Owner = "pending"
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	// Force disposal to fail after actual restoration and marker publication.
	cleanup := p.Rollback + ".cleanup"
	if err := os.Mkdir(cleanup, 0700); err != nil {
		t.Fatal(err)
	}
	machineWrite(t, filepath.Join(cleanup, "block"), []byte("fixture"))
	if err := machineRollback(p); err == nil {
		t.Fatal("disposal failure not reached")
	}
	if !machineSnapshotMarked(p, ".rolled-back") {
		t.Fatal("rollback cleanup started before durable terminal marker")
	}
	if err := os.RemoveAll(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(p.Rollback, "client.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := MachineOperation("rollback", o); err != nil {
		t.Fatal(err)
	}
	if !MachineInstalled(o) {
		t.Fatal("restarting rollback after partial snapshot cleanup deleted the restored original manifest")
	}
}

func TestMachineInstallReviewCursorStagingNotActiveConfiguration(t *testing.T) {
	home := t.TempDir()
	o := clientFixture(t, "cursor")
	o.Dir = filepath.Join(home, ".aegishook-client")
	o.Scope = "enterprise"
	o.Project = ""
	result, err := ClientOperation("install", o)
	if err != nil {
		t.Fatal(err)
	}
	if result.Warning == "" {
		t.Fatal("fixture did not create staged-only config")
	}
	if ClientHooksConfigured(home) {
		t.Fatalf("staged-only enterprise file incorrectly reports configured before admin deployment: %s", result.Entry)
	}
}

func TestMachineInstallReviewReplaceableApplicationRoot(t *testing.T) {
	o := machineFixture(t)
	parent := filepath.Dir(o.Root)
	originalValidate := o.ValidatePath
	o.ValidatePath = func(path string, private bool) error {
		if path == parent {
			return validateMachineUnixPath(path, private, uint32(os.Getuid()))
		}
		return originalValidate(path, private)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if err := validateMachineTree(o); err == nil {
		t.Fatal("validator accepted application subtree in replaceable non-sticky ancestor")
	}
}

func TestMachineInstallReviewTerminalCleanupRetry(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "after-rename", true: "partial-removal"}[partial], func(t *testing.T) {
			o := machineFixture(t)
			o.Owner = "original"
			p := MachinePaths(o.Root)
			if _, err := MachineOperation("system-install", o); err != nil {
				t.Fatal(err)
			}
			original, _ := os.ReadFile(p.Manifest)
			o.NoCommit = true
			o.Owner = "pending"
			if _, err := MachineOperation("system-install", o); err != nil {
				t.Fatal(err)
			}
			// Reproduce restoration and terminal publication, then a process exit during disposal.
			if err := filepath.WalkDir(p.Rollback, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(p.Rollback, path)
				if rel == "." {
					return nil
				}
				dest := filepath.Join(p.Private, rel)
				if d.IsDir() {
					return os.MkdirAll(dest, 0700)
				}
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				return AtomicFile(dest, b, 0600)
			}); err != nil {
				t.Fatal(err)
			}
			retry := []byte("retained retry")
			machineWrite(t, p.Enrolled, retry)
			machineWrite(t, filepath.Join(p.Rollback, ".rolled-back"), []byte("rolled-back\n"))
			cleanup := p.Rollback + ".cleanup"
			if err := os.Rename(p.Rollback, cleanup); err != nil {
				t.Fatal(err)
			}
			if partial {
				os.Remove(filepath.Join(cleanup, "client.json"))
				os.Remove(filepath.Join(cleanup, ".rolled-back"))
			}
			// All maintenance entries must discard cleanup state without interpreting its omissions.
			for _, action := range []string{"system-install", "rollback", "commit"} {
				if _, err := MachineOperation(action, o); err != nil {
					t.Fatal(action, err)
				}
				got, _ := os.ReadFile(p.Manifest)
				if !bytes.Equal(got, original) {
					t.Fatal(action, "changed restored state")
				}
				got, _ = os.ReadFile(p.Enrolled)
				if !bytes.Equal(got, retry) {
					t.Fatal(action, "lost retry credential")
				}
				if action != "commit" {
					os.Mkdir(cleanup, 0700)
					machineWrite(t, filepath.Join(cleanup, ".rolled-back"), []byte("rolled-back\n"))
				}
			}
		})
	}
}

func TestMachineInstallReviewCommitMarkerPrecedesCleanup(t *testing.T) {
	o := machineFixture(t)
	o.NoCommit = true
	p := MachinePaths(o.Root)
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.Code, 0700); err != nil {
		t.Fatal(err)
	}
	machineWrite(t, filepath.Join(p.Code, "block"), []byte("fixture"))
	if _, err := MachineOperation("commit", o); err == nil {
		t.Fatal("cleanup failure not reached")
	}
	if !machineSnapshotMarked(p, ".committed") {
		t.Fatal("commit cleanup started before durable terminal marker")
	}
	if _, err := MachineOperation("rollback", o); err == nil {
		t.Fatal("committed snapshot restored")
	}
	if err := os.RemoveAll(p.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := MachineOperation("commit", o); err != nil {
		t.Fatal(err)
	}
}
