//go:build unix

package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMachineContextCancelsBundleReadAndRetainsPending(t *testing.T) {
	for _, repair := range []bool{false, true} {
		t.Run(fmt.Sprint(repair), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, cancelled := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("{"))
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
				close(cancelled)
			}))
			defer server.Close()
			o := machineFixture(t)
			o.Endpoint, o.NoCommit = server.URL, true
			p := MachinePaths(o.Root)
			machineWrite(t, p.Enrolled, mustJSON(ClientConnection{Endpoint: server.URL, NodeID: strings.Repeat("b", 32), Token: strings.Repeat("a", 64), BundlePublicKey: make([]byte, ed25519.PublicKeySize)}))
			if _, err := MachineOperation("system-install", o); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if repair {
					done <- MachineRepairContext(ctx, o)
				} else {
					done <- MachineEnrolledContext(ctx, o)
				}
			}()
			<-started
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal("HTTP body cancellation not propagated", err)
			}
			<-cancelled
			if _, err := os.Stat(p.Rollback); err != nil {
				t.Fatal("pending snapshot removed", err)
			}
			if _, err := os.Stat(filepath.Join(p.Rollback, ".committed")); !os.IsNotExist(err) {
				t.Fatal("cancellation committed a pending snapshot")
			}
			if err := MachineEnrolledContext(ctx, o); !errors.Is(err, context.Canceled) {
				t.Fatal("pre-cancelled context was ignored", err)
			}
		})
	}
}

func TestMachineRepairTerminalCleanupOnly(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node := strings.Repeat("b", 32)
	payload := mustJSON(PolicyBundle{NodeID: node, Revision: 1, Rules: []Rule{}})
	signed := SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(key, payload)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(signed) }))
	defer server.Close()
	for _, kind := range []string{"pending", "committed", "cleanup", "no-snapshot", "unenrolled", "locked", "unsafe", "relative"} {
		t.Run(kind, func(t *testing.T) {
			o := machineFixture(t)
			o.Endpoint, o.NoCommit = server.URL, true
			p := MachinePaths(o.Root)
			machineWrite(t, p.Enrolled, mustJSON(ClientConnection{Endpoint: server.URL, NodeID: node, Token: strings.Repeat("a", 64), BundlePublicKey: public}))
			if _, err := MachineOperation("system-install", o); err != nil {
				t.Fatal(err)
			}
			snapshot := p.Rollback
			switch kind {
			case "committed", "unenrolled":
				machineWrite(t, filepath.Join(p.Rollback, ".committed"), []byte("committed\n"))
			case "cleanup":
				snapshot += ".cleanup"
				if err := os.Rename(p.Rollback, snapshot); err != nil {
					t.Fatal(err)
				}
			case "no-snapshot":
				if err := os.RemoveAll(p.Rollback); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "unenrolled" {
				os.Remove(p.Connection)
			}
			if kind == "unsafe" {
				os.Chmod(p.Private, 0755)
			}
			if kind == "relative" {
				o.Root = "relative"
			}
			if kind == "locked" {
				lock, err := os.OpenFile(filepath.Join(p.Private, "client.lock"), os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err := lockProcessFile(lock); err != nil {
					t.Fatal(err)
				}
			}
			err := MachineRepair(o)
			wantError := kind == "unenrolled" || kind == "locked" || kind == "unsafe" || kind == "relative"
			if (err != nil) != wantError {
				t.Fatalf("err=%v wantError=%v", err, wantError)
			}
			_, statErr := os.Stat(snapshot)
			if kind == "pending" || wantError {
				if statErr != nil {
					t.Fatal("repair removed pending/unverified snapshot", statErr)
				}
			} else if !os.IsNotExist(statErr) {
				t.Fatal("terminal snapshot retained", statErr)
			}
			if kind == "pending" {
				if _, err := os.Stat(filepath.Join(p.Rollback, ".committed")); !os.IsNotExist(err) {
					t.Fatal("pending transaction committed")
				}
				if _, err := os.Stat(p.Enrolled); err != nil {
					t.Fatal("retry credential removed", err)
				}
			}
		})
	}
}
