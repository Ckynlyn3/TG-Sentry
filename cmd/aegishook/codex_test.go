package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientCodexConfigGeneration(t *testing.T) {
	for _, action := range []string{"codex-config", "codex-requirements"} {
		var out bytes.Buffer
		connection := filepath.Join(t.TempDir(), "connection.json")
		if err := runClient([]string{action, "--connection", connection}, strings.NewReader("unused"), &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "[[hooks.PreToolUse.hooks]]") || strings.Contains(out.String(), "allow_managed_hooks_only = true") != (action == "codex-requirements") {
			t.Fatal(out.String())
		}
	}
	for _, args := range [][]string{{"codex-config"}, {"codex-requirements", "--connection", "relative"}, {"codex-config", "--bogus"}, {"codex-config", "unexpected"}, {"codex-config", "--binary", "relative", "--connection", filepath.Join(t.TempDir(), "c.json")}} {
		if err := runClient(args, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatal("invalid arguments accepted", args)
		}
	}
	var help bytes.Buffer
	if err := runClient([]string{"codex-requirements", "--help"}, strings.NewReader(""), &help); err != nil || !strings.Contains(help.String(), "connection") {
		t.Fatal(err, help.String())
	}
}
