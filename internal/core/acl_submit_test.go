package core

import (
	"reflect"
	"testing"
)

func TestACLSubmitDenyOverrides(t *testing.T) {
	for _, mode := range []string{"human", "model"} {
		t.Run(mode, func(t *testing.T) {
			e := engine(t)
			e.Settings.Mode = mode
			aclPublish(t, e, ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "deny read", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "tools", Tools: []string{"read"}}}})
			r, err := e.Submit(input("acl-denied", "read", map[string]any{"path": "README.md"}))
			if err != nil || r.Decision != "reject" || r.ReviewPath != "acl" || r.RuleID == "" || r.Execution != "not_executed" || r.NeedsHuman || r.DecidedAt == nil || r.ModelVerdict != nil || r.ModelInput != nil || r.ModelContext != nil {
				t.Fatalf("ACL deny did not terminate safety chain: %+v err=%v", r, err)
			}
			if usage, err := e.Usage(); err != nil || len(usage) != 0 {
				t.Fatal("ACL denial used model", usage, err)
			}
			if _, err := e.Decide(testActorContext(), r.ID, r.Digest, "approve", ""); err == nil {
				t.Fatal("ACL denial entered human approval")
			}
			if err := e.Result(r.ID, "instance", "succeeded", ""); err == nil {
				t.Fatal("ACL denial accepted execution")
			}
		})
	}
}

func TestACLSubmitAllowNonTerminalAndDefaultCompatibility(t *testing.T) {
	e := engine(t)
	fixtures := []ReviewInput{
		input("r1", "bash", map[string]any{"command": "passwd alice"}),
		input("read", "read", map[string]any{"path": "README.md"}),
		input("human", "bash", map[string]any{"command": "echo hello"}),
		input("incomplete", "read", map[string]any{"path": "README.md"}),
	}
	fixtures[3].ScriptCaptureStatus = "incomplete"
	before := []Review{}
	for _, in := range fixtures {
		r, err := e.Submit(in)
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, r)
	}
	s := aclState(t, e)
	s.ACL = ACLState{Initialized: true, Rules: s.EffectiveACLRules()}
	if err := e.put("protection", "current", s); err != nil {
		t.Fatal(err)
	}
	for j, in := range fixtures {
		in.CallID += "-initialized"
		r, err := e.Submit(in)
		old := before[j]
		if err != nil || r.Decision != old.Decision || r.ReviewPath != old.ReviewPath || r.RuleID != old.RuleID || r.Execution != old.Execution || r.NeedsHuman != old.NeedsHuman {
			t.Fatalf("compatibility lost: before=%+v after=%+v err=%v", old, r, err)
		}
	}
	if before[0].Decision != "reject" || before[0].RuleID != "R1" || before[2].Decision != "pending" || !before[3].NeedsHuman {
		t.Fatal("allow bypassed safety evaluation", before)
	}
}

func TestACLSubmitNoMatchDenies(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-match", true: "empty"}[empty], func(t *testing.T) {
			e := engine(t)
			s := aclState(t, e)
			s.ACL = ACLState{Initialized: true, Rules: []ACLRule{}}
			if !empty {
				s.ACL.Rules = []ACLRule{{ID: "allow-other", Enabled: true, Effect: "allow", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "tools", Tools: []string{"other"}}}}
			}
			if err := e.put("protection", "current", s); err != nil {
				t.Fatal(err)
			}
			r, err := e.Submit(input("implicit-deny", "read", map[string]any{"path": "README.md"}))
			if err != nil || r.Decision != "reject" || r.ReviewPath != "acl" || r.RuleID != "" || r.Execution != "not_executed" || r.NeedsHuman {
				t.Fatalf("no permit authorized a call: %+v err=%v", r, err)
			}
		})
	}
}

func TestACLSubmitResolvesNodeTagsAndExactTool(t *testing.T) {
	e, a, b := protectionFixture(t)
	publishProtection(t, e, ProtectionChange{Kind: "tags", ID: a, Tags: []string{"restricted"}})
	aclPublish(t, e, ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "tag deny", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "tags", Tags: []string{"restricted"}}, Target: ACLTarget{Kind: "tools", Tools: []string{"Read"}}}})
	aclPublish(t, e, ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "agent deny", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "agents", AgentIDs: []string{b}}, Target: ACLTarget{Kind: "tools", Tools: []string{"read"}}}})
	for _, node := range []string{a, b} {
		if err := e.Register(Instance{ID: node, NodeID: node, Platform: "linux", SessionID: node, Cwd: "/project", HookVersion: Version}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ node, tool, path string }{{a, "Read", "acl"}, {b, "read", "acl"}, {a, "read", "rule"}, {b, "Read", "rule"}} {
		r, err := e.Submit(ReviewInput{InstanceID: tc.node, CallID: ID(), ToolName: tc.tool, Arguments: map[string]any{"path": "README.md", "file_path": "README.md"}})
		if err != nil || r.ReviewPath != tc.path {
			t.Fatalf("node=%s tool=%s path=%s err=%v", tc.node, tc.tool, r.ReviewPath, err)
		}
	}
}

func TestACLSubmitOfflineAndAuditFailureFailClosed(t *testing.T) {
	// LD7: offline bundles never carry ACL permits or authorize cached allows.
	bundle := PolicyBundle{Rules: []Rule{{ID: "allow", Enabled: true, Matcher: "regex", Pattern: ".*", Decision: "approve"}}}
	if got := PolicyBundleDeny(bundle, input("offline", "read", map[string]any{"path": "README.md"}), t.TempDir()); got != nil {
		t.Fatal("offline cached permit became an authorization", got)
	}
	e := engine(t)
	aclPublish(t, e, ProtectionChange{Kind: "acl", ACL: &ACLRule{Name: "deny", Enabled: true, Effect: "deny", Subject: ACLSubject{Kind: "all"}, Target: ACLTarget{Kind: "all"}}})
	before, err := e.Reviews()
	if err != nil {
		t.Fatal(err)
	}
	rejectAudit(t, e)
	r, err := e.Submit(input("failed-audit", "read", map[string]any{"path": "README.md"}))
	if err == nil || r.Decision != "reject" || r.Execution != "not_executed" {
		t.Fatal("audit failure did not fail closed", r, err)
	}
	after, err := e.Reviews()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed ACL audit persisted partial review", err)
	}
}
