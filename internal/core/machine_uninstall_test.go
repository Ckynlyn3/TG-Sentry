//go:build unix

package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMachineUninstallRefusalLeavesFilesUntouched(t *testing.T) {
	for _, name := range []string{"foreign", "adapter/foreign", "config.json", "adapter/runtime.json", "adapter/connection.json", "client.json", "request.json", "enrolled.json", "adapter/bundle.json", "adapter/trust.json", "adapter/bundle.json.lock", "setup-code", "foreign-without-cache-lock", "busy-cache-lock", "adapter-file"} {
		t.Run(name, func(t *testing.T) {
			o := machineFixture(t)
			p := MachinePaths(o.Root)
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			conn := ClientConnection{Endpoint: o.Endpoint, NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: public}
			machineWrite(t, p.Enrolled, mustJSON(conn))
			if _, err := MachineOperation("system-install", o); err != nil {
				t.Fatal(err)
			}
			machineWrite(t, filepath.Join(p.Private, "request.json"), mustJSON(ClientRequestTicket{ID: strings.Repeat("c", 32), Secret: strings.Repeat("d", 64)}))
			payload := mustJSON(PolicyBundle{Revision: 2, NodeID: conn.NodeID, Rules: []Rule{}})
			if _, err := CachePolicyBundle(p.Bundle, SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}, public, conn.NodeID); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(p.Private, filepath.FromSlash(name))
			if name == "adapter-file" {
				foreign = filepath.Join(p.Private, "adapter")
				if err := os.RemoveAll(foreign); err != nil {
					t.Fatal(err)
				}
			}
			if name == "busy-cache-lock" {
				foreign = p.Bundle + ".lock"
				lock, err := lockPolicyCache(p.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			} else {
				machineWrite(t, foreign, []byte("foreign content"))
			}
			if name == "foreign-without-cache-lock" {
				if err := os.Remove(p.Bundle + ".lock"); err != nil {
					t.Fatal(err)
				}
			}
			before := machinePrivateFiles(t, p.Private)

			result, err := MachineOperation("system-uninstall", o)
			if err == nil {
				t.Fatal("foreign or corrupt state accepted")
			}
			if name != "client.json" && !slices.Contains(result.Retained, foreign) && !slices.Contains(result.Retained, filepath.Dir(foreign)) {
				t.Fatalf("foreign state not reported: %v", result.Retained)
			}
			after := machinePrivateFiles(t, p.Private)
			if len(after) != len(before) {
				t.Errorf("refusal changed file count: before %d, after %d", len(before), len(after))
			}
			for path, want := range before {
				if got, ok := after[path]; !ok || !bytes.Equal(got, want) {
					t.Errorf("refusal removed or changed %s", path)
				}
			}
			if name == "foreign" || name == "foreign-without-cache-lock" {
				if err := os.Remove(foreign); err != nil {
					t.Fatal(err)
				}
				if result, err := MachineOperation("system-uninstall", o); err != nil || len(result.Retained) != 0 {
					t.Fatal("uninstall after resolving foreign file", result, err)
				}
				if files := machinePrivateFiles(t, p.Private); len(files) != 1 || files[filepath.Join(p.Private, "client.lock")] == nil {
					t.Fatal("clean uninstall left resources besides client.lock", files)
				}
			}
		})
	}
}

func TestMachineUninstallCacheContentionAfterPreflightLeavesFilesUntouched(t *testing.T) {
	o := machineFixture(t)
	p := MachinePaths(o.Root)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conn := ClientConnection{Endpoint: o.Endpoint, NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: public}
	machineWrite(t, p.Enrolled, mustJSON(conn))
	if _, err := MachineOperation("system-install", o); err != nil {
		t.Fatal(err)
	}
	machineWrite(t, filepath.Join(p.Private, "request.json"), mustJSON(ClientRequestTicket{ID: strings.Repeat("c", 32), Secret: strings.Repeat("d", 64)}))
	payload := mustJSON(PolicyBundle{Revision: 2, NodeID: conn.NodeID, Rules: []Rule{}})
	if _, err := CachePolicyBundle(p.Bundle, SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}, public, conn.NodeID); err != nil {
		t.Fatal(err)
	}
	before := machinePrivateFiles(t, p.Private)
	preflight := machineUninstallPreflight
	var cacheLock *os.File
	t.Cleanup(func() {
		machineUninstallPreflight = preflight
		if cacheLock != nil {
			cacheLock.Close()
		}
	})
	// Match ValidateMachinePath's replaceable-function seam: acquire the real
	// cache writer lock only after successful read-only preflight has returned.
	machineUninstallPreflight = func(p MachineLayout, m clientManifest) ([]string, error) {
		retained, err := preflight(p, m)
		if err == nil && len(retained) == 0 {
			cacheLock, err = lockPolicyCache(p.Bundle)
		}
		return retained, err
	}
	result, err := MachineOperation("system-uninstall", o)
	if cacheLock == nil || err == nil || err.Error() != "machine uninstall retained foreign or modified resources" || !slices.Contains(result.Retained, p.Bundle) {
		t.Fatalf("cache contention after preflight was not refused: %v, %v", result, err)
	}
	after := machinePrivateFiles(t, p.Private)
	if len(after) != len(before) {
		t.Errorf("refusal changed file count: before %d, after %d", len(before), len(after))
	}
	for path, want := range before {
		if got, ok := after[path]; !ok || !bytes.Equal(got, want) {
			t.Errorf("refusal removed or changed %s", path)
		}
	}
}

func machinePrivateFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil {
			files[path] = data
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
