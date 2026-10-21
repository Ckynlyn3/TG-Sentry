package service

import (
	"aegishook/internal/core"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestMachineContract(t *testing.T) {
	p := core.MachinePaths(t.TempDir())
	if p.Private != filepath.Join(p.Root, "private") || p.Connection != filepath.Join(p.Private, "adapter", "connection.json") || p.Socket != filepath.Join(p.Root, "run", "ctl.sock") {
		t.Fatal(p)
	}
	for _, verb := range []string{"status", "repair"} {
		data, err := json.Marshal(Request{Verb: verb})
		if err != nil {
			t.Fatal(err)
		}
		var r Request
		if json.Unmarshal(data, &r) != nil || r.Validate() != nil {
			t.Fatal(string(data))
		}
	}
	if (Request{Verb: "install"}).Validate() == nil {
		t.Fatal("unexpected control verb accepted")
	}
	if _, err := Call(p.Root, Request{Verb: "status"}); err == nil {
		t.Fatal("unimplemented platform did not fail closed")
	}
	if err := Run(p.Root); err == nil {
		t.Fatal("unimplemented service did not fail closed")
	}
}

func TestStatusN1(t *testing.T) {
	good := Status{Installed: true, Service: true, Enrolled: true, Hooks: "configured", Loaded: "unknown"}
	cases := []struct {
		require string
		state   Status
		code    int
	}{
		{"installed", good, 0}, {"hooks", good, 0}, {"invalid", good, 2},
		{"hooks", Status{}, 10}, {"hooks", Status{Installed: true}, 20},
		{"hooks", Status{Installed: true, Service: true}, 30},
		{"hooks", Status{Installed: true, Service: true, Enrolled: true, Hooks: "missing"}, 40},
		{"hooks", Status{Installed: true, Service: true, Enrolled: true, Hooks: "unknown"}, 50},
	}
	for _, c := range cases {
		if got := c.state.ExitCode(c.require); got != c.code {
			t.Fatalf("%s %+v: %d want %d", c.require, c.state, got, c.code)
		}
	}
}
