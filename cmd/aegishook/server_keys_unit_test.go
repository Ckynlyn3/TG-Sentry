package main

import (
	"aegishook/internal/core"
	"aegishook/internal/teststore"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerKeysHelpAndValidation(t *testing.T) {
	var general bytes.Buffer
	_, _ = parseOptions([]string{"-h"}, &general)
	if !strings.Contains(general.String(), "server      Manage bundle signing keys (server stopped)") {
		t.Fatal("general help does not expose server commands")
	}
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}, {"help", "rotate-bundle-key"}, {"rotate-bundle-key", "-h"}, {"retire-bundle-key", "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			if err := runServerKeys(args, &out); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"Usage:", "rotate-bundle-key", "retire-bundle-key", "-data-dir"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("help missing %q", want)
				}
			}
		})
	}
	for _, args := range [][]string{nil, {"bogus"}, {"--unknown"}, {"rotate-bundle-key", "extra"}, {"rotate-bundle-key", "--key-id", "id"}, {"retire-bundle-key"}, {"retire-bundle-key", "--key-id", ""}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "must-not-exist")
			args = append(args, "--data-dir", dir)
			if err := runServerKeys(args, io.Discard); err == nil {
				t.Fatal("invalid invocation accepted")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("invalid invocation opened server state")
			}
		})
	}
}

func TestServerKeysMainHelpDispatch(t *testing.T) {
	out, err := os.Create(filepath.Join(t.TempDir(), "help-output"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	args, stdout := os.Args, os.Stdout
	defer func() { os.Args, os.Stdout = args, stdout }()
	os.Args, os.Stdout = []string{"aegishook", "server", "--help"}, out
	main()
	data, err := os.ReadFile(out.Name())
	if err != nil || !strings.Contains(string(data), "rotate-bundle-key") {
		t.Fatal("main did not dispatch server help", err)
	}
}

func TestServerKeysOperationsAndErrors(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	var out bytes.Buffer
	if err := runServerKeys([]string{"rotate-bundle-key", "--data-dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	e, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	record := serverKeysRecord(t, e)
	oldID, newID := record.Keys[0].KeyID, record.Keys[1].KeyID
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"rotate-bundle-key"}, {"retire-bundle-key", "--key-id", newID}, {"retire-bundle-key", "--key-id", "unknown"}} {
		if err := runServerKeys(append(args, "--data-dir", dir), io.Discard); !errors.Is(err, errServerKeysUnavailable) {
			t.Fatal("unsafe operation must report the key-management error category")
		}
	}
	if err := runServerKeys([]string{"retire-bundle-key", "--key-id", oldID, "--data-dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"rotate-bundle-key"}, {"retire-bundle-key", "--key-id", newID}} {
		err := runServerKeys(append(args, "--data-dir", dir), failingCtlWriter{})
		if err == nil || !strings.Contains(err.Error(), "fixture write failure") {
			t.Fatalf("output failure not propagated: %v", err)
		}
	}
	badDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(badDir, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runServerKeys([]string{"rotate-bundle-key", "--data-dir", badDir}, io.Discard); !errors.Is(err, errServerKeysUnavailable) {
		t.Fatal("open failure must report the key-management error category")
	}
}
