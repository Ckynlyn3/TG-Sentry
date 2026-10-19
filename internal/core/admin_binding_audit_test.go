package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAdminBindingAuditActorAndNoOps(t *testing.T) {
	e := engine(t)
	principal := Principal{Issuer: "https://issuer.example", Subject: "subject"}
	before, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		remove    bool
		name      string
		wantCount int
		action    string
	}{
		{false, "display-token-sentinel", 1, "admin.bind"},
		{false, "display-token-sentinel", 1, "admin.bind"},
		{false, "renamed", 2, "admin.bind"},
		{true, "", 3, "admin.unbind"},
		{true, "", 3, "admin.unbind"},
	}
	for _, step := range steps {
		if step.remove {
			err = e.UnbindAdmin(principal)
		} else {
			err = e.BindAdmin(principal, step.name)
		}
		if err != nil {
			t.Fatal(err)
		}
		audits, err := e.Audits()
		if err != nil || len(audits) != len(before)+step.wantCount {
			t.Fatalf("audit count=%d want=%d err=%v", len(audits), len(before)+step.wantCount, err)
		}
		seenAction := false
		for _, audit := range audits {
			seenAction = seenAction || audit.Action == step.action
			if audit.Action != "admin.bind" && audit.Action != "admin.unbind" {
				continue
			}
			if audit.Actor != (Actor{Issuer: "local", Subject: "cli", Name: "cli", Kind: "cli"}) {
				t.Fatalf("wrong recovery actor: %+v", audit.Actor)
			}
			var got Principal
			if err := json.Unmarshal([]byte(audit.Detail), &got); err != nil || got != principal {
				t.Fatalf("audit detail=%q err=%v", audit.Detail, err)
			}
			if bytes.Contains([]byte(audit.Detail), []byte("display-token-sentinel")) {
				t.Fatal("display data leaked into audit detail")
			}
		}
		if !seenAction {
			t.Fatalf("missing audit action %s", step.action)
		}
	}
}

func TestAdminBindingAuditFailureRestoresFile(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new file", true: "existing file"}[existing], func(t *testing.T) {
			e := engine(t)
			principal := Principal{Issuer: "https://issuer.example", Subject: "subject"}
			path := filepath.Join(e.Dir, "admin-bindings.json")
			if existing {
				if err := e.BindAdmin(principal, "before"); err != nil {
					t.Fatal(err)
				}
			}
			before, readErr := os.ReadFile(path)
			audits, err := e.Audits()
			if err != nil {
				t.Fatal(err)
			}
			rejectAudit(t, e)
			if existing {
				err = e.UnbindAdmin(principal)
			} else {
				err = e.BindAdmin(principal, "new")
			}
			if err == nil {
				t.Fatal("audit failure allowed binding update")
			}
			after, err := os.ReadFile(path)
			if existing && (err != nil || !bytes.Equal(before, after)) {
				t.Fatalf("original binding file not restored: %v", err)
			}
			if !existing && (!os.IsNotExist(readErr) || !os.IsNotExist(err)) {
				t.Fatal("failed bind left a new binding file")
			}
			nextAudits, err := e.Audits()
			if err != nil || len(nextAudits) != len(audits) {
				t.Fatal("failed transaction changed audit")
			}
		})
	}
}
