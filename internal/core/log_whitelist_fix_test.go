package core

import (
	"aegishook/internal/teststore"
	"testing"
)

// Instance suppression is server-owned admission provenance, not a lookup of
// current configuration at each lifecycle write (plan §3; Review snapshot
// precedent). Zero-call instances still carry it, and it survives restarts.
func TestLogWhitelistInstanceSuppressionProvenance(t *testing.T) {
	for _, initiallySuppressed := range []bool{true, false} {
		for _, restart := range []bool{false, true} {
			t.Run(map[bool]string{true: "registered-suppressed", false: "registered-normal"}[initiallySuppressed]+
				map[bool]string{true: "-restart", false: ""}[restart], func(t *testing.T) {
				dir := teststore.Dir(t, t.TempDir())
				e := aclOpen(t, dir)
				code, err := e.CreateEnrollment(testActorContext(), "instance provenance")
				if err != nil {
					t.Fatal(err)
				}
				conn, err := e.EnrollClient(code.Code, "linux")
				if err != nil {
					t.Fatal(err)
				}
				entry := whitelistEntry(conn.NodeID)
				if initiallySuppressed {
					publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry})
				}
				if err = e.Register(Instance{ID: "zero-call", Agent: "claude", NodeID: conn.NodeID, Platform: "linux", SessionID: "provenance", Cwd: "/workspace", HookVersion: Version}); err != nil {
					t.Fatal(err)
				}
				instances, err := e.Instances()
				if err != nil || len(instances) != 1 {
					t.Fatal(instances, err)
				}
				if (instances[0].LogSuppression != nil) != initiallySuppressed || initiallySuppressed && (instances[0].LogSuppression.Revision == 0 || len(instances[0].LogSuppression.EntryIDs) == 0) {
					t.Fatal("zero-call instance lacks suppression metadata", instances[0].LogSuppression)
				}
				state, err := e.Protection()
				if err != nil {
					t.Fatal(err)
				}
				if initiallySuppressed {
					publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", ID: state.LogWhitelist[0].ID, Delete: true})
				} else {
					publishProtection(t, e, ProtectionChange{Kind: "log-whitelist", LogWhitelist: &entry})
				}
				// Same-session re-registration is a lifecycle retry, not a new admission.
				if err = e.Register(Instance{ID: "zero-call", Agent: "claude", NodeID: conn.NodeID, Platform: "linux", SessionID: "provenance", Cwd: "/workspace", HookVersion: Version}); err != nil {
					t.Fatal(err)
				}
				if restart {
					aclClose(t, e)
					e = aclOpen(t, dir)
					defer e.Close()
				}
				instances, err = e.Instances()
				if err != nil || len(instances) != 1 || (instances[0].LogSuppression != nil) != initiallySuppressed {
					t.Fatal("retry or restart changed admission provenance", instances, err)
				}
				if err = e.Disconnect("zero-call"); err != nil {
					t.Fatal(err)
				}
				audits, err := e.Audits()
				if err != nil {
					t.Fatal(err)
				}
				suppressedAudit := false
				for _, a := range audits {
					if a.Action == "instance.disconnect" {
						suppressedAudit = true
					}
				}
				if suppressedAudit == initiallySuppressed {
					t.Fatal("disconnect audit did not follow admission provenance", initiallySuppressed)
				}
			})
		}
	}
}
