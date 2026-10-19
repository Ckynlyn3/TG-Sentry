package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"aegishook/internal/teststore"
)

func TestPolicyBundleEffectiveRulesAndRevision(t *testing.T) {
	e := engine(t)
	key, err := e.CreateEnrollment(testActorContext(), "bundle")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	get := func() PolicyBundle {
		t.Helper()
		signed, err := e.ClientPolicyBundle(conn.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := VerifyPolicyBundle(signed, conn.BundlePublicKey, conn.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		return bundle
	}
	before := get()
	checkChange := func(change func() error) PolicyBundle {
		t.Helper()
		if err := change(); err != nil {
			t.Fatal(err)
		}
		after := get()
		if after.Revision <= before.Revision {
			t.Fatal("policy write did not advance revision")
		}
		before = after
		return after
	}
	rule := Rule{ID: "U_BUNDLE", Name: "bundle fixture", Enabled: true, ScopeOnly: true, Decision: "reject", Matcher: "contains", Target: "arguments", Pattern: "protected.txt"}
	unbound := checkChange(func() error { return e.SaveRule(testActorContext(), rule) })
	for _, r := range unbound.Rules {
		if r.ID == rule.ID {
			t.Fatal("unbound scope-only rule published")
		}
	}
	scope := Scope{ID: "bundle-scope", Name: "bundle binding", NodeID: conn.NodeID, Platform: "linux", Project: "/project", RuleIDs: []string{rule.ID}}
	bound := checkChange(func() error { return e.SaveScope(testActorContext(), scope) })
	rules, _ := e.Rules()
	want, err := boundRules(rules, []Scope{scope})
	if err != nil || !reflect.DeepEqual(bound.Rules, want) {
		t.Fatal("bundle differs from server effective rules")
	}
	// Binding-only updates, including moving a binding away from this node,
	// must advance the same persisted version as rule/settings mutations.
	scope.RuleIDs = nil
	checkChange(func() error { return e.SaveScope(testActorContext(), scope) })
	scope.RuleIDs = []string{rule.ID}
	checkChange(func() error { return e.SaveScope(testActorContext(), scope) })
	scope.NodeID = ""
	scope.RuleIDs = nil
	scope.Project = t.TempDir()
	checkChange(func() error { return e.SaveScope(testActorContext(), scope) })
	checkChange(func() error { return e.DeleteScope(testActorContext(), scope.ID) })
	rule.Pattern = "changed.txt"
	checkChange(func() error { return e.SaveRule(testActorContext(), rule) })
	checkChange(func() error { return e.DeleteRule(testActorContext(), rule.ID) })
	settings := e.Config()
	checkChange(func() error { return e.SaveSettings(testActorContext(), settings, nil) })
	checkProtectionBundleRevisions(t, e, conn)
	first, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil || !bytes.Equal(first.Payload, second.Payload) || !bytes.Equal(first.Signature, second.Signature) {
		t.Fatal("unstable canonical bytes/signature")
	}
	if err = e.RevokeClient(testActorContext(), conn.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ClientPolicyBundle(conn.NodeID); err == nil {
		t.Fatal("revoked node got bundle")
	}
}

func TestPolicyBundleKeyAndRevisionSurviveRestart(t *testing.T) {
	dir := teststore.Dir(t, t.TempDir())
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := e.CreateEnrollment(testActorContext(), "restart")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err = e.SaveRule(testActorContext(), Rule{ID: "U_RESTART", Name: "restart", Enabled: true, Decision: "reject", Matcher: "contains", Pattern: "fixture"}); err != nil {
		t.Fatal(err)
	}
	before, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	after, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil || !bytes.Equal(before.Payload, after.Payload) || !bytes.Equal(before.Signature, after.Signature) {
		t.Fatal("restart changed trusted bundle")
	}
	if _, err = VerifyPolicyBundle(after, conn.BundlePublicKey, conn.NodeID); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "bundle-signing.key"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("signing key is not private")
	}
}

func TestVerifyPolicyBundleAndCacheRollbackProtection(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(revision int, rules []Rule, node string) SignedPolicyBundle {
		payload, err := json.Marshal(PolicyBundle{Revision: revision, NodeID: node, Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		return SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	valid := sign(2, []Rule{}, "node")
	if _, err := ReadPolicyBundle(path, pub, "node"); !os.IsNotExist(err) {
		t.Fatalf("first-start cache error: %v", err)
	}
	if _, err := CachePolicyBundle(path, valid, pub, "node"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		signed SignedPolicyBundle
		key    []byte
		node   string
	}{
		{"tampered", SignedPolicyBundle{Payload: append(append([]byte(nil), valid.Payload...), ' '), Signature: valid.Signature}, pub, "node"},
		{"bad signature", SignedPolicyBundle{Payload: valid.Payload, Signature: []byte("invalid")}, pub, "node"},
		{"invalid key", valid, nil, "node"},
		{"other node", valid, pub, "other"},
		{"rollback", sign(1, []Rule{}, "node"), pub, "node"},
		{"same revision different body", sign(2, []Rule{{ID: "changed"}}, "node"), pub, "node"},
		{"zero revision", sign(0, []Rule{}, "node"), pub, "node"},
		{"null rules", sign(3, nil, "node"), pub, "node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CachePolicyBundle(path, tc.signed, tc.key, tc.node); err == nil {
				t.Fatal("invalid bundle accepted")
			}
			got, err := ReadPolicyBundle(path, pub, "node")
			if err != nil || !bytes.Equal(got.Payload, valid.Payload) {
				t.Fatal("last valid bundle lost")
			}
		})
	}
	if _, err = CachePolicyBundle(path, valid, pub, "node"); err != nil {
		t.Fatal("equal identical revision rejected", err)
	}
	if _, err = CachePolicyBundle(path, sign(3, []Rule{}, "node"), pub, "node"); err != nil {
		t.Fatal("new revision rejected", err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("cache permissions")
	}
}

func TestPolicyBundleLocalRulesNeverAuthorize(t *testing.T) {
	bundle := PolicyBundle{Rules: []Rule{
		{ID: "U_ALLOW", Enabled: true, Decision: "approve", Matcher: "contains", Pattern: "fixture"},
		{ID: "U_ALERT", Enabled: true, Decision: "alert", Matcher: "contains", Pattern: "fixture"},
	}}
	input := ReviewInput{ToolName: "Read", Arguments: map[string]any{"path": "fixture"}}
	if d := PolicyBundleDeny(bundle, input, t.TempDir()); d != nil {
		t.Fatal("offline permit/alert evaluated as authority")
	}
	bundle.Rules = append(bundle.Rules, Rule{ID: "U_DENY", Enabled: true, Decision: "reject", Matcher: "contains", Pattern: "fixture"})
	if d := PolicyBundleDeny(bundle, input, t.TempDir()); d == nil || d.RuleID != "U_DENY" {
		t.Fatal("cached deny not evaluated")
	}
}

func TestPolicyBundleCacheRejectsUnsafeFilesAndConcurrentRollback(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(revision int) SignedPolicyBundle {
		payload := mustJSON(PolicyBundle{Revision: revision, NodeID: "node", Rules: []Rule{}})
		return SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}
	}
	for _, kind := range []string{"directory", "malformed", "trailing JSON", "bad signature", "lock directory", "busy", "missing parent", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.json")
			signed := sign(2)
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "malformed":
				err = os.WriteFile(path, []byte("invalid"), 0600)
			case "trailing JSON":
				err = os.WriteFile(path, append(mustJSON(sign(1)), []byte(` {}`)...), 0600)
			case "bad signature":
				err = os.WriteFile(path, mustJSON(SignedPolicyBundle{Payload: []byte(`{}`)}), 0600)
			case "lock directory":
				err = os.Mkdir(path+".lock", 0700)
			case "busy":
				lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err = lockProcessFile(lock); err != nil {
					t.Fatal(err)
				}
			case "missing parent":
				path = filepath.Join(path, "missing", "bundle.json")
			case "oversize":
				payload := mustJSON(PolicyBundle{Revision: 2, NodeID: "node", Rules: []Rule{{Message: string(bytes.Repeat([]byte("x"), PolicyBundleMaxBytes))}}})
				signed = SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CachePolicyBundle(path, signed, pub, "node"); err == nil {
				t.Fatal("unsafe cache accepted")
			}
		})
	}
	malformed := []byte("signed but not JSON")
	if _, err := VerifyPolicyBundle(SignedPolicyBundle{Payload: malformed, Signature: ed25519.Sign(private, malformed)}, pub, "node"); err == nil {
		t.Fatal("signed malformed JSON accepted")
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if _, err = CachePolicyBundle(path, sign(2), pub, "node"); err != nil {
		t.Fatal(err)
	}
	// Competing processes use the same nonblocking OS lock; a lower candidate
	// either loses the lock or sees the newly committed higher revision.
	results := make(chan error, 2)
	for _, version := range []int{3, 4} {
		signed := sign(version)
		go func() { _, err := CachePolicyBundle(path, signed, pub, "node"); results <- err }()
	}
	<-results
	<-results
	if _, err = CachePolicyBundle(path, sign(4), pub, "node"); err != nil {
		t.Fatal(err)
	}
	if _, err = CachePolicyBundle(path, sign(3), pub, "node"); err == nil {
		t.Fatal("concurrent rollback accepted")
	}
}

func TestPolicyBundleSigningKeyCorruptionFailsClosed(t *testing.T) {
	for _, key := range [][]byte{[]byte("invalid"), make([]byte, ed25519.PrivateKeySize)} {
		dir := teststore.Dir(t, t.TempDir())
		if err := os.WriteFile(filepath.Join(dir, "bundle-signing.key"), key, 0600); err != nil {
			t.Fatal(err)
		}
		if e, err := Open(dir); err == nil {
			e.Close()
			t.Fatal("corrupt key silently regenerated")
		}
	}
}

func TestPolicyBundleMissingBindingAndStoreErrors(t *testing.T) {
	e := engine(t)
	code, err := e.CreateEnrollment(testActorContext(), "bundle failure")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(code.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{ID: "U_MISSING", Name: "missing", Enabled: true, ScopeOnly: true, Decision: "reject", Matcher: "contains", Pattern: "fixture"}
	if err = e.SaveRule(testActorContext(), rule); err != nil {
		t.Fatal(err)
	}
	if err = e.SaveScope(testActorContext(), Scope{ID: "binding", Name: "binding", Project: "/project", Platform: "linux", NodeID: conn.NodeID, RuleIDs: []string{rule.ID}}); err != nil {
		t.Fatal(err)
	}
	if err = e.DeleteRule(testActorContext(), rule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ClientPolicyBundle(conn.NodeID); err == nil {
		t.Fatal("missing bound rule silently omitted")
	}
	if err = e.DeleteScope(testActorContext(), "binding"); err != nil {
		t.Fatal(err)
	}
	if err = e.put("rules", "corrupt", json.RawMessage(`{"enabled":"invalid"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ClientPolicyBundle(conn.NodeID); err == nil {
		t.Fatal("corrupt rule ignored")
	}
	if _, err = teststore.Admin(t, e.DB).Exec("DELETE FROM records WHERE kind='rules' AND id='corrupt'"); err != nil {
		t.Fatal(err)
	}
	if err = e.put("scopes", "corrupt", json.RawMessage(`{"ruleIds":"invalid"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ClientPolicyBundle(conn.NodeID); err == nil {
		t.Fatal("corrupt scope ignored")
	}
}

func TestPolicyBundleCacheReadHonorsResponseBudget(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := mustJSON(PolicyBundle{Revision: 1, NodeID: "node", Rules: []Rule{}})
	signed := SignedPolicyBundle{Payload: payload, Signature: ed25519.Sign(private, payload)}
	path := filepath.Join(t.TempDir(), "bundle.json")
	oversize := append(mustJSON(signed), bytes.Repeat([]byte(" "), PolicyBundleMaxBytes)...)
	if err = os.WriteFile(path, oversize, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPolicyBundle(path, pub, "node"); err == nil {
		t.Fatal("oversize trailing whitespace bypassed response budget")
	}
}

func checkProtectionBundleRevisions(t *testing.T, e *Engine, conn ClientConnection) {
	t.Helper()
	if err := e.SaveRule(testActorContext(), Rule{ID: "U_TEMPLATE", Name: "template source", Enabled: true, ScopeOnly: true, Decision: "reject", Matcher: "contains", Pattern: "template-protected"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Register(Instance{ID: "bundle-runtime", NodeID: conn.NodeID, Platform: "linux", Agent: "claude", SessionID: "bundle-runtime", Cwd: "/project", HookVersion: Version}); err != nil {
		t.Fatal(err)
	}
	get := func() PolicyBundle {
		t.Helper()
		signed, err := e.ClientPolicyBundle(conn.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := VerifyPolicyBundle(signed, conn.BundlePublicKey, conn.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		review, err := e.Submit(ReviewInput{InstanceID: "bundle-runtime", CallID: ID(), ToolName: "Read", Arguments: map[string]any{"path": "template-protected"}})
		if err != nil {
			t.Fatal(err)
		}
		// Signed definitions retain the complete model, including secret rules.
		// Runtime/audit snapshots keep the same effective list, with the existing
		// privacy projection applied to sensitive rule content.
		raw, err := e.Rules()
		if err != nil {
			t.Fatal(err)
		}
		scopes, err := e.Scopes()
		if err != nil {
			t.Fatal(err)
		}
		applicable := []Scope{}
		for _, scope := range scopes {
			if scope.NodeID == conn.NodeID {
				applicable = append(applicable, scope)
			}
		}
		effective, err := e.protectionRules(raw, applicable, conn.NodeID)
		if err != nil || !reflect.DeepEqual(bundle.Rules, effective) {
			t.Fatal("bundle differs from runtime definitions", err)
		}
		// Independent expectation: never reuse the runtime filter under test.
		auditRules := []Rule{}
		hasSecretModel := false
		for _, rule := range bundle.Rules {
			if rule.Matcher == "secret" {
				hasSecretModel = true
			}
			auditRules = append(auditRules, rule)
		}
		if !hasSecretModel {
			t.Fatal("signed model bundle dropped secret definitions")
		}
		if len(auditRules) != len(review.Rules) {
			t.Fatal("audit snapshot dropped a runtime rule")
		}
		contentOmitted := review.SensitiveInfo != nil && (len(review.SensitiveInfo.Findings) > 0 || review.SensitiveInfo.Unavailable || review.SensitiveInfo.Reason != "")
		for i, expected := range auditRules {
			if contentOmitted || hasExact(SensitiveInfoCategory, expected.Categories...) {
				// These are the only permitted audit-only field differences.
				if contentOmitted {
					expected.Tool, expected.Field = sensitiveIdentifier(expected.Tool), sensitiveIdentifier(expected.Field)
				}
				expected.Name, expected.Message = "Sensitive-info rule", ""
				if expected.Matcher != "btpii" {
					expected.Pattern = "[REDACTED]"
				}
			}
			if !reflect.DeepEqual(expected, review.Rules[i]) {
				t.Fatalf("unexpected audit projection difference: %s", expected.ID)
			}
		}
		return bundle
	}
	previous := get()
	publish := func(name string, change ProtectionChange) ProtectionState {
		t.Helper()
		state, err := e.Protection()
		if err != nil {
			t.Fatal(err)
		}
		draft, err := e.ReviewProtection(change, state.Revision)
		if err != nil {
			t.Fatal(name, err)
		}
		if e.Config().Version != previous.Revision {
			t.Fatal("unpublished draft changed bundle revision")
		}
		state, err = e.ConfirmProtection(testActorContext(), draft.ID, state.Revision, true, change.Kind, change.ID, change.Delete)
		if err != nil {
			t.Fatal(name, err)
		}
		next := get()
		if next.Revision <= previous.Revision {
			t.Fatal(name, "did not advance bundle revision")
		}
		previous = next
		t.Log(name, "advances revision and matches runtime rules")
		return state
	}
	state := publish("template create", ProtectionChange{Kind: "templates", Template: &ProtectionTemplate{Name: "bundle template", Rules: []TemplateRule{{RuleID: "U_TEMPLATE", Category: "category::sensitive-info", Action: "block"}}}})
	templateID := state.Templates[0].ID
	state = publish("policy create", ProtectionChange{Kind: "policies", Policy: &ProtectionPolicy{Name: "bundle policy", TemplateIDs: []string{templateID}, Scope: PolicyScope{Type: "agents", AgentIDs: []string{conn.NodeID}}}})
	policyID := state.Policies[0].ID
	publish("template update", ProtectionChange{Kind: "templates", ID: templateID, Template: &ProtectionTemplate{Name: "bundle template", Rules: []TemplateRule{{RuleID: "U_TEMPLATE", Category: "category::sensitive-info", Action: "alert"}}}})
	publish("policy update", ProtectionChange{Kind: "policies", ID: policyID, Policy: &ProtectionPolicy{Name: "bundle policy", TemplateIDs: []string{templateID}, Scope: PolicyScope{Type: "tags", Tags: []string{"bundle"}}}})
	publish("tag PUT add", ProtectionChange{Kind: "tags", ID: conn.NodeID, Tags: []string{"bundle"}})
	publish("tag PUT remove", ProtectionChange{Kind: "tags", ID: conn.NodeID, Tags: []string{}})
	publish("policy delete", ProtectionChange{Kind: "policies", ID: policyID, Delete: true})
	publish("template delete", ProtectionChange{Kind: "templates", ID: templateID, Delete: true})
}

func TestBundleApprovedRequestPinsVerificationKey(t *testing.T) {
	e := engine(t)
	ticket, err := e.CreateClientRequest("bundle request", "linux", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if err = e.DecideClientRequest(testActorContext(), ticket.ID, "approve"); err != nil {
		t.Fatal(err)
	}
	result, err := e.PollClientRequest(ticket.ID, ticket.Secret, "192.0.2.1")
	if err != nil || result.Connection == nil {
		t.Fatal("approved-request enrollment failed", err)
	}
	conn := *result.Connection
	signed, err := e.ClientPolicyBundle(conn.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyPolicyBundle(signed, conn.BundlePublicKey, conn.NodeID); err != nil {
		t.Fatal("approved request did not deliver verification key", err)
	}
}
