package core

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestACLDenyWinsOverlappingSubjects(t *testing.T) {
	subjects := map[string]ACLSubject{
		"all":   {Kind: "all"},
		"agent": {Kind: "agents", AgentIDs: []string{"node"}},
		"tag":   {Kind: "tags", Tags: []string{"restricted"}},
	}
	for _, pair := range [][2]string{
		{"all", "tag"}, {"tag", "all"},
		{"all", "agent"}, {"agent", "all"},
		{"agent", "tag"}, {"tag", "agent"},
	} {
		allow := ACLRule{ID: "a-allow", Enabled: true, Subject: subjects[pair[0]], Effect: "allow", Target: ACLTarget{Kind: "all"}}
		deny := ACLRule{ID: "z-deny", Enabled: true, Subject: subjects[pair[1]], Effect: "deny", Target: ACLTarget{Kind: "tools", Tools: []string{"Read"}}}
		for _, reverse := range []bool{false, true} {
			name := pair[0] + "-allow/" + pair[1] + "-deny"
			if reverse {
				name += "/reversed"
			}
			t.Run(name, func(t *testing.T) {
				rules := []ACLRule{allow, deny}
				if reverse {
					rules = []ACLRule{deny, allow}
				}
				before, err := json.Marshal(rules)
				if err != nil {
					t.Fatal(err)
				}
				got := EvaluateACL(rules, "node", []string{"restricted"}, "Read")
				if got != (ACLDecision{Effect: "deny", RuleID: "z-deny"}) {
					t.Fatalf("deny must win regardless of specificity/order: %+v", got)
				}
				after, err := json.Marshal(rules)
				if err != nil || string(after) != string(before) {
					t.Fatalf("evaluator mutated rules: %s / %s / %v", before, after, err)
				}
			})
		}
	}
}

func TestACLAllowOverlappingSubjects(t *testing.T) {
	all := ACLRule{ID: "b-all", Enabled: true, Subject: ACLSubject{Kind: "all"}, Effect: "allow", Target: ACLTarget{Kind: "all"}}
	agent := ACLRule{ID: "a-agent", Enabled: true, Subject: ACLSubject{Kind: "agents", AgentIDs: []string{"node"}}, Effect: "allow", Target: ACLTarget{Kind: "all"}}
	tag := ACLRule{ID: "c-tag", Enabled: true, Subject: ACLSubject{Kind: "tags", Tags: []string{"restricted"}}, Effect: "allow", Target: ACLTarget{Kind: "all"}}
	for _, tc := range []struct {
		name  string
		rules []ACLRule
		want  string
	}{
		{"all/tag", []ACLRule{all, tag}, all.ID},
		{"all/agent", []ACLRule{all, agent}, agent.ID},
		{"agent/tag", []ACLRule{agent, tag}, agent.ID},
	} {
		for _, reverse := range []bool{false, true} {
			name := tc.name
			if reverse {
				name += "/reversed"
			}
			t.Run(name, func(t *testing.T) {
				rules := tc.rules
				if reverse {
					rules = []ACLRule{tc.rules[1], tc.rules[0]}
				}
				if got := EvaluateACL(rules, "node", []string{"restricted"}, "Read"); got != (ACLDecision{Effect: "allow", RuleID: tc.want}) {
					t.Fatalf("matching permits should allow with lowest ID: %+v", got)
				}
			})
		}
	}
}

func TestACLDefaultDenyAndMatching(t *testing.T) {
	all := ACLSubject{Kind: "all"}
	allTools := ACLTarget{Kind: "all"}
	for _, tc := range []struct {
		name    string
		subject ACLSubject
		target  ACLTarget
		node    string
		tags    []string
		tool    string
		effect  string
		allowed bool
	}{
		{"all includes future agents", all, allTools, "new-node", nil, "NewTool", "allow", true},
		{"matching agent", ACLSubject{Kind: "agents", AgentIDs: []string{"other", "node"}}, allTools, "node", nil, "Read", "allow", true},
		{"other agent", ACLSubject{Kind: "agents", AgentIDs: []string{"other"}}, allTools, "node", nil, "Read", "allow", false},
		{"empty node cannot match", ACLSubject{Kind: "agents", AgentIDs: []string{""}}, allTools, "", nil, "Read", "allow", false},
		{"any tag matches", ACLSubject{Kind: "tags", Tags: []string{"other", "restricted"}}, allTools, "node", []string{"unrelated", "restricted"}, "Read", "allow", true},
		{"other tag", ACLSubject{Kind: "tags", Tags: []string{"other"}}, allTools, "node", []string{"restricted"}, "Read", "allow", false},
		{"no tags", ACLSubject{Kind: "tags", Tags: []string{"restricted"}}, allTools, "node", nil, "Read", "allow", false},
		{"unknown subject", ACLSubject{Kind: "users"}, allTools, "node", nil, "Read", "allow", false},
		{"exact tool", all, ACLTarget{Kind: "tools", Tools: []string{"Write", "Read"}}, "node", nil, "Read", "allow", true},
		{"tool case differs", all, ACLTarget{Kind: "tools", Tools: []string{"Read"}}, "node", nil, "read", "allow", false},
		{"input whitespace", all, ACLTarget{Kind: "tools", Tools: []string{"Read"}}, "node", nil, " Read ", "allow", false},
		{"target whitespace", all, ACLTarget{Kind: "tools", Tools: []string{" Read "}}, "node", nil, "Read", "allow", false},
		{"whitespace matches literally", all, ACLTarget{Kind: "tools", Tools: []string{" Read "}}, "node", nil, " Read ", "allow", true},
		{"no wildcard syntax", all, ACLTarget{Kind: "tools", Tools: []string{"*"}}, "node", nil, "Read", "allow", false},
		{"empty tools", all, ACLTarget{Kind: "tools"}, "node", nil, "Read", "allow", false},
		{"unknown target", all, ACLTarget{Kind: "unknown", Tools: []string{"Read"}}, "node", nil, "Read", "allow", false},
		{"unknown effect", all, allTools, "node", nil, "Read", "approve", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := ACLRule{ID: "rule", Enabled: true, Subject: tc.subject, Target: tc.target, Effect: tc.effect}
			want := ACLDecision{Effect: "deny"}
			if tc.allowed {
				want = ACLDecision{Effect: "allow", RuleID: rule.ID}
			}
			if got := EvaluateACL([]ACLRule{rule}, tc.node, tc.tags, tc.tool); got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestACLDisabledRulesAndLowestDenyID(t *testing.T) {
	allow := ACLRule{ID: "allow", Enabled: true, Subject: ACLSubject{Kind: "all"}, Effect: "allow", Target: ACLTarget{Kind: "all"}}
	deny := ACLRule{ID: "z-deny", Enabled: true, Subject: ACLSubject{Kind: "all"}, Effect: "deny", Target: ACLTarget{Kind: "all"}}
	disabledAllow, disabledDeny, firstDeny := allow, deny, deny
	disabledAllow.Enabled, disabledDeny.Enabled = false, false
	firstDeny.ID = "a-deny"
	for _, tc := range []struct {
		name  string
		rules []ACLRule
		want  ACLDecision
	}{
		{"nil rules", nil, ACLDecision{Effect: "deny"}},
		{"empty rules", []ACLRule{}, ACLDecision{Effect: "deny"}},
		{"disabled deny ignored", []ACLRule{disabledDeny, allow}, ACLDecision{Effect: "allow", RuleID: allow.ID}},
		{"disabled allow cannot grant", []ACLRule{disabledAllow}, ACLDecision{Effect: "deny"}},
		{"all disabled", []ACLRule{disabledAllow, disabledDeny}, ACLDecision{Effect: "deny"}},
		{"lowest deny ID", []ACLRule{allow, deny, firstDeny}, ACLDecision{Effect: "deny", RuleID: firstDeny.ID}},
		{"lowest deny ID reversed", []ACLRule{firstDeny, deny, allow}, ACLDecision{Effect: "deny", RuleID: firstDeny.ID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EvaluateACL(tc.rules, "node", nil, "Read"); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestACLStateDistinguishesUninitializedFromEmpty(t *testing.T) {
	for _, tc := range []struct {
		name        string
		data        string
		initialized bool
	}{
		{"absent ACL field", `{}`, false},
		{"zero ACL", `{"acl":{}}`, false},
		{"initialized nil rules", `{"acl":{"initialized":true,"rules":null}}`, true},
		{"initialized empty rules", `{"acl":{"initialized":true,"rules":[]}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var aggregate struct {
				ACL ACLState `json:"acl"`
			}
			if err := json.Unmarshal([]byte(tc.data), &aggregate); err != nil {
				t.Fatal(err)
			}
			if aggregate.ACL.Initialized != tc.initialized {
				t.Fatalf("initialization state lost: %+v", aggregate.ACL)
			}
			if got := EvaluateACL(aggregate.ACL.Rules, "node", nil, "Read"); got != (ACLDecision{Effect: "deny"}) {
				t.Fatalf("empty ACL must not authorize: %+v", got)
			}
			encoded, err := json.Marshal(aggregate)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip struct {
				ACL ACLState `json:"acl"`
			}
			if err := json.Unmarshal(encoded, &roundTrip); err != nil || !reflect.DeepEqual(aggregate, roundTrip) {
				t.Fatalf("ACL state round trip: %+v / %v", roundTrip, err)
			}
		})
	}
}
