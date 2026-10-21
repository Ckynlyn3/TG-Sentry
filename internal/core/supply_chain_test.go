package core

import (
	"bytes"
	"strings"
	"testing"
)

// Schema-derived synthetic fixtures (issue #42, slice S1). Field names and
// vocabularies match the pinned serializers cited in supply_chain.go:
//
//   - skill-scanner ScanResult.to_dict / Finding.to_dict (pinned 8554b119)
//   - mcp-scanner report_generator.results_to_json (pinned 10032f98)
//
// These are NOT captured scanner output and contain no real payloads, secrets,
// network destinations or executable content. The pinned tools were not run.
//
// Valid fixtures use real upstream vocabulary: skill categories are members of
// the pinned ThreatCategory enum (prompt_injection, data_exfiltration,
// policy_violation, obfuscation, ...). Rows and fixtures carrying invented or
// invalid vocabulary (severity "SEVERE", severity "SAFE" on a finding, a
// duplicate or case-aliased member) are negative cases and are named as such.

// schemaDerivedSkillReport renders a skill-scanner object from the members this
// contract reads; scan_duration_seconds, duration_ms, timestamp and scan_metadata
// are included because the serializer always emits them.
func schemaDerivedSkillReport(analyzers, findingsCount, maxSeverity string, isSafe bool, findings, extra string) string {
	return `{"skill_name":"demo","skill_path":"skills/demo","is_safe":` + boolJSON(isSafe) +
		`,"max_severity":"` + maxSeverity + `","findings_count":` + findingsCount +
		`,"findings":` + findings +
		`,"scan_duration_seconds":0.1,"duration_ms":100,"analyzers_used":` + analyzers +
		`,"timestamp":"2026-01-01T00:00:00+00:00","scan_metadata":{}` + extra + `}`
}

func boolJSON(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

const (
	schemaDerivedNoFindings  = "[]"
	schemaDerivedHighFinding = `[{"id":"a:1","rule_id":"PROMPT_INJECTION_IGNORE_INSTRUCTIONS",` +
		`"category":"prompt_injection","severity":"HIGH","title":"t","description":"d",` +
		`"file_path":"SKILL.md","line_number":3,"snippet":"","remediation":null,` +
		`"analyzer":"static","metadata":{}}]`
	schemaDerivedMediumFinding = `[{"id":"a:2","rule_id":"SUSPICIOUS_DOWNLOAD","category":"data_exfiltration",` +
		`"severity":"MEDIUM","title":"t","description":"d","file_path":"SKILL.md","line_number":7,` +
		`"snippet":"","remediation":null,"analyzer":"static","metadata":{}}]`
	schemaDerivedLowFinding = `[{"id":"a:3","rule_id":"MINOR_HYGIENE","category":"policy_violation","severity":"LOW",` +
		`"title":"t","description":"d","file_path":"SKILL.md","line_number":9,"snippet":"",` +
		`"remediation":null,"analyzer":"static","metadata":{}}]`
	schemaDerivedInfoFinding = `[{"id":"a:4","rule_id":"INFO_NOTICE","category":"obfuscation","severity":"INFO",` +
		`"title":"t","description":"d","file_path":"SKILL.md","line_number":11,"snippet":"",` +
		`"remediation":null,"analyzer":"static","metadata":{}}]`
	schemaDerivedSafeFinding = `[{"id":"a:5","rule_id":"REPORTED_SAFE","category":"policy_violation","severity":"SAFE",` +
		`"title":"t","description":"d","file_path":"SKILL.md","line_number":12,"snippet":"",` +
		`"remediation":null,"analyzer":"static","metadata":{}}]`
	schemaDerivedUnknownSeverityFinding = `[{"id":"a:6","rule_id":"NEW_RULE","category":"policy_violation","severity":"SEVERE",` +
		`"title":"t","description":"d","file_path":"SKILL.md","line_number":13,"snippet":"",` +
		`"remediation":null,"analyzer":"static","metadata":{}}]`
	// Negative fixtures: a verdict-bearing finding object that upstream cannot
	// emit, used only to prove the duplicate/alias rejection.
	schemaDerivedDuplicateMemberFinding = `[{"id":"a:8","rule_id":"DUP_MEMBER","category":"policy_violation",` +
		`"severity":"HIGH","severity":"SAFE","analyzer":"static"}]`
	schemaDerivedCaseAliasFinding = `[{"id":"a:9","rule_id":"CASE_ALIAS","category":"policy_violation",` +
		`"severity":"HIGH","Severity":"SAFE","analyzer":"static"}]`
	schemaDerivedNoAnalyzerFinding = `[{"id":"a:7","rule_id":"NO_ANALYZER","category":"policy_violation","severity":"LOW",` +
		`"title":"t","description":"d","file_path":"SKILL.md","line_number":14,"snippet":"",` +
		`"remediation":null,"analyzer":null,"metadata":{}}]`
)

func schemaDerivedMCPReport(item string) string { return "[" + item + "]" }

func schemaDerivedMCPItem(status, isSafe, findings, extra string) string {
	return `{"status":"` + status + `","is_safe":` + isSafe + `,"findings":` + findings +
		`,"tool_name":"demo","tool_description":"d","item_type":"tool"` + extra + `}`
}

const (
	schemaDerivedMCPCleanGroup = `{"yara_analyzer":{"severity":"SAFE","threat_names":[],` +
		`"threat_summary":"No threats detected","total_findings":0}}`
	schemaDerivedMCPHighGroup = `{"yara_analyzer":{"severity":"HIGH","threat_names":["PROMPT_INJECTION"],` +
		`"threat_summary":"Detected 1 threat: PROMPT_INJECTION","total_findings":1}}`
	schemaDerivedMCPSafeWithCountGroup = `{"yara_analyzer":{"severity":"SAFE","threat_names":["PROMPT_INJECTION"],` +
		`"threat_summary":"Detected 1 threat: PROMPT_INJECTION","total_findings":1}}`
	schemaDerivedMCPUnknownGroup = `{"yara_analyzer":{"severity":"UNKNOWN","threat_names":[],` +
		`"threat_summary":"Analysis failed","total_findings":0,"status":"error","errors":[]}}`
	// Negative fixtures: analyzer groups upstream cannot emit, used only to
	// prove the count, name and duplicate/alias rejections.
	schemaDerivedMCPDuplicateKeyGroup = `{"yara_analyzer":{"severity":"SAFE","threat_names":[],` +
		`"total_findings":0},"yara_analyzer":{"severity":"HIGH","threat_names":["PROMPT_INJECTION"],` +
		`"total_findings":1}}`
	schemaDerivedMCPCaseAliasGroup = `{"yara_analyzer":{"severity":"HIGH","Severity":"SAFE",` +
		`"threat_names":["PROMPT_INJECTION"],"total_findings":1}}`
	schemaDerivedMCPMissingCountGroup = `{"yara_analyzer":{"severity":"HIGH","threat_names":["PROMPT_INJECTION"]}}`
	schemaDerivedMCPNullCountGroup    = `{"yara_analyzer":{"severity":"HIGH","threat_names":["PROMPT_INJECTION"],` +
		`"total_findings":null}}`
	schemaDerivedMCPNegativeCountGroup = `{"yara_analyzer":{"severity":"HIGH","threat_names":["PROMPT_INJECTION"],` +
		`"total_findings":-1}}`
	schemaDerivedMCPZeroCountHighGroup = `{"yara_analyzer":{"severity":"HIGH","threat_names":[],` +
		`"total_findings":0}}`
	schemaDerivedMCPZeroCountNamedGroup = `{"yara_analyzer":{"severity":"SAFE","threat_names":["PROMPT_INJECTION"],` +
		`"threat_summary":"Detected 1 threat: PROMPT_INJECTION","total_findings":0}}`
	schemaDerivedMCPNoNamesHighGroup = `{"yara_analyzer":{"severity":"HIGH","threat_names":[],` +
		`"total_findings":2}}`
	schemaDerivedMCPBlankAnalyzerGroup = `{"_analyzer":{"severity":"SAFE","threat_names":[],` +
		`"total_findings":0}}`
	schemaDerivedMCPTaxonomyGroup = `{"yara_analyzer":{"severity":"HIGH","threat_names":["PROMPT_INJECTION"],` +
		`"threat_summary":"Detected 1 threat: PROMPT_INJECTION","total_findings":1,` +
		`"mcp_taxonomies":[{"aitech":"01","aisubtech":"01.01"}]}}`
	schemaDerivedMCPDedupedNamesGroup = `{"yara_analyzer":{"severity":"HIGH","threat_names":["PROMPT_INJECTION"],` +
		`"threat_summary":"Detected 1 threat: PROMPT_INJECTION","total_findings":3}}`
	schemaDerivedMCPErrorGroup = `{"yara_analyzer":{"severity":"SAFE","threat_names":[],` +
		`"threat_summary":"No threats detected","total_findings":0,"status":"partial","errors":[{"analyzer":"yara"}]}}`
)

func mustSubject(t *testing.T, files map[string]string) SupplyChainSubject {
	t.Helper()
	subject, err := NewSupplyChainSubject(files)
	if err != nil {
		t.Fatalf("NewSupplyChainSubject(%v) = %v", files, err)
	}
	return subject
}

func TestSupplyChainContractSubjectBindsMembership(t *testing.T) {
	base := mustSubject(t, map[string]string{
		"SKILL.md":     strings.Repeat("a", 64),
		"scripts/x.py": strings.Repeat("b", 64),
	})
	// Same content, independently constructed: sorted membership is canonical.
	same := mustSubject(t, map[string]string{
		"scripts/x.py": strings.Repeat("b", 64),
		"SKILL.md":     strings.Repeat("a", 64),
	})
	// A changed sibling script must invalidate the subject even though SKILL.md
	// is byte-identical.
	siblingChanged := mustSubject(t, map[string]string{
		"SKILL.md":     strings.Repeat("a", 64),
		"scripts/x.py": strings.Repeat("c", 64),
	})
	// An added member changes membership with every retained hash unchanged.
	memberAdded := mustSubject(t, map[string]string{
		"SKILL.md":     strings.Repeat("a", 64),
		"scripts/x.py": strings.Repeat("b", 64),
		"scripts/y.py": strings.Repeat("d", 64),
	})

	if len(base.Digest) != 64 || !isSupplyChainHash(base.Digest) {
		t.Fatalf("subject digest %q is not a lowercase SHA-256", base.Digest)
	}
	for name, other := range map[string]SupplyChainSubject{
		"sibling content change": siblingChanged,
		"membership change":      memberAdded,
	} {
		if other.Digest == base.Digest {
			t.Fatalf("%s produced the unchanged digest %q", name, base.Digest)
		}
	}
	if same.Digest != base.Digest {
		t.Fatalf("equal membership produced different digests: %q != %q", same.Digest, base.Digest)
	}
	// The subject owns its membership: later caller mutation cannot rebind it.
	files := map[string]string{"SKILL.md": strings.Repeat("a", 64)}
	owned := mustSubject(t, files)
	files["SKILL.md"] = strings.Repeat("f", 64)
	if owned.Files["SKILL.md"] != strings.Repeat("a", 64) {
		t.Fatal("subject retained the caller's map")
	}
}

func TestSupplyChainContractSubjectRejectsInvalid(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for name, files := range map[string]map[string]string{
		"empty":                   {},
		"absolute path":           {"/etc/passwd": hash},
		"parent traversal":        {"../escape": hash},
		"dot segment":             {"scripts/./x.py": hash},
		"empty segment":           {"scripts//x.py": hash},
		"backslash separator":     {`scripts\x.py`: hash},
		"newline in path":         {"scripts/x\n.py": hash},
		"short digest":            {"SKILL.md": strings.Repeat("a", 63)},
		"non-hex digest":          {"SKILL.md": strings.Repeat("z", 64)},
		"uppercase digest":        {"SKILL.md": strings.ToUpper(strings.Repeat("a", 64))},
		"digest with path prefix": {"SKILL.md": "sha256:" + hash},
	} {
		if _, err := NewSupplyChainSubject(files); err == nil {
			t.Errorf("%s: NewSupplyChainSubject accepted %v", name, files)
		}
	}
}

func TestSupplyChainContractDefaultAction(t *testing.T) {
	// docs/PROTECTION-CATEGORIES.md:78-80 records the four-grade default; line 79
	// keeps plugins and coding-agent built-in tools scan-only.
	for _, tc := range []struct {
		grade  string
		family SupplyChainFamily
		want   string
	}{
		{"CRITICAL", SupplyChainFamilySkill, "block"},
		{"HIGH", SupplyChainFamilySkill, "block"},
		{"HIGH", SupplyChainFamilyMCP, "block"},
		{"MEDIUM", SupplyChainFamilySkill, "log-only"},
		{"LOW", SupplyChainFamilyMCP, "log-only"},
		{"INFO", SupplyChainFamilySkill, "none"},
		{"SAFE", SupplyChainFamilySkill, "none"},
		{"UNKNOWN", SupplyChainFamilySkill, "none"},
		{"", SupplyChainFamilySkill, "none"},
		{"HIGH", SupplyChainFamilyPlugin, "alert"},
		{"CRITICAL", SupplyChainFamilyPlugin, "alert"},
		{"MEDIUM", SupplyChainFamilyPlugin, "log-only"},
		{"HIGH", SupplyChainFamilyBuiltinTool, "alert"},
		{"HIGH", SupplyChainFamilyMemoryFile, "block"},
	} {
		if got := SupplyChainDefaultAction(tc.grade, tc.family); got != tc.want {
			t.Errorf("SupplyChainDefaultAction(%q, %q) = %q, want %q", tc.grade, tc.family, got, tc.want)
		}
	}
}

func TestSupplyChainContractProjectSkillScan(t *testing.T) {
	single := `["static"]`
	for _, tc := range []struct {
		name           string
		report         string
		wantState      SupplyChainState
		wantReason     string
		wantGrade      string
		wantFindingIDs []string
	}{
		{
			name:      "clean scan completes with no findings",
			report:    schemaDerivedSkillReport(single, "0", "SAFE", true, schemaDerivedNoFindings, ""),
			wantState: SupplyChainCompleted, wantGrade: "SAFE",
		},
		{
			name:      "HIGH finding blocks and stays HIGH",
			report:    schemaDerivedSkillReport(single, "1", "HIGH", false, schemaDerivedHighFinding, ""),
			wantState: SupplyChainCompleted, wantGrade: "HIGH",
			wantFindingIDs: []string{"PROMPT_INJECTION_IGNORE_INSTRUCTIONS"},
		},
		{
			name:      "MEDIUM finding logs",
			report:    schemaDerivedSkillReport(single, "1", "MEDIUM", true, schemaDerivedMediumFinding, ""),
			wantState: SupplyChainCompleted, wantGrade: "MEDIUM",
			wantFindingIDs: []string{"SUSPICIOUS_DOWNLOAD"},
		},
		{
			name:      "LOW finding logs",
			report:    schemaDerivedSkillReport(single, "1", "LOW", true, schemaDerivedLowFinding, ""),
			wantState: SupplyChainCompleted, wantGrade: "LOW",
			wantFindingIDs: []string{"MINOR_HYGIENE"},
		},
		{
			name:      "INFO is preserved but is not a risk grade",
			report:    schemaDerivedSkillReport(single, "1", "INFO", true, schemaDerivedInfoFinding, ""),
			wantState: SupplyChainCompleted, wantGrade: "INFO",
			wantFindingIDs: []string{"INFO_NOTICE"},
		},
		{
			name:      "null analyzer is attributed to the only analyzer that ran",
			report:    schemaDerivedSkillReport(single, "1", "LOW", true, schemaDerivedNoAnalyzerFinding, ""),
			wantState: SupplyChainCompleted, wantGrade: "LOW",
			wantFindingIDs: []string{"NO_ANALYZER"},
		},
		{
			name:      "SAFE-marked finding is never clean",
			report:    schemaDerivedSkillReport(single, "1", "SAFE", true, schemaDerivedSafeFinding, ""),
			wantState: SupplyChainIncomplete, wantReason: "safe_with_findings",
		},
		{
			name:      "contradictory findings_count",
			report:    schemaDerivedSkillReport(single, "2", "HIGH", false, schemaDerivedHighFinding, ""),
			wantState: SupplyChainIncomplete, wantReason: "findings_count_mismatch",
		},
		{
			name:      "unknown severity",
			report:    schemaDerivedSkillReport(single, "1", "LOW", true, schemaDerivedUnknownSeverityFinding, ""),
			wantState: SupplyChainIncomplete, wantReason: "unknown_severity",
		},
		{
			name:      "unknown max_severity",
			report:    schemaDerivedSkillReport(single, "1", "SEVERE", false, schemaDerivedHighFinding, ""),
			wantState: SupplyChainIncomplete, wantReason: "unknown_severity",
		},
		{
			name:      "max_severity contradicts findings",
			report:    schemaDerivedSkillReport(single, "1", "LOW", false, schemaDerivedHighFinding, ""),
			wantState: SupplyChainIncomplete, wantReason: "max_severity_mismatch",
		},
		{
			name:      "is_safe contradicts a HIGH finding",
			report:    schemaDerivedSkillReport(single, "1", "HIGH", true, schemaDerivedHighFinding, ""),
			wantState: SupplyChainIncomplete, wantReason: "is_safe_mismatch",
		},
		{
			name:      "missing analyzers",
			report:    schemaDerivedSkillReport(`[]`, "0", "SAFE", true, schemaDerivedNoFindings, ""),
			wantState: SupplyChainIncomplete, wantReason: "missing_analyzers",
		},
		{
			name:      "failed analyzer makes coverage incomplete",
			report:    schemaDerivedSkillReport(single, "0", "SAFE", true, schemaDerivedNoFindings, `,"analyzers_failed":[{"analyzer":"llm","error":"boom"}]`),
			wantState: SupplyChainIncomplete, wantReason: "analyzer_failed",
		},
		{
			name:      "missing rule id",
			report:    schemaDerivedSkillReport(single, "1", "LOW", true, `[{"rule_id":"","category":"policy_violation","severity":"LOW","analyzer":"static"}]`, ""),
			wantState: SupplyChainIncomplete, wantReason: "missing_rule_id",
		},
		{
			name:      "malformed JSON",
			report:    `{"skill_name":`,
			wantState: SupplyChainError, wantReason: "malformed_report",
		},
		{
			name:      "unknown top-level key",
			report:    schemaDerivedSkillReport(single, "0", "SAFE", true, schemaDerivedNoFindings, `,"Surprise":1`),
			wantState: SupplyChainError, wantReason: "unrecognized_report",
		},
		{
			name:      "missing required member",
			report:    `{"skill_name":"demo","analyzers_used":["static"]}`,
			wantState: SupplyChainError, wantReason: "unrecognized_report",
		},
		{
			name:      "other JSON type",
			report:    `[{"skill_name":"demo"}]`,
			wantState: SupplyChainError, wantReason: "unrecognized_report",
		},
		{
			name:      "findings is not an array",
			report:    schemaDerivedSkillReport(single, "0", "SAFE", true, `{}`, ""),
			wantState: SupplyChainError, wantReason: "unrecognized_report",
		},
		{
			name:      "duplicate top-level key",
			report:    schemaDerivedSkillReport(single, "0", "SAFE", true, schemaDerivedNoFindings, `,"skill_name":"other"`),
			wantState: SupplyChainError, wantReason: "unrecognized_report",
		},
		{
			name: "is_safe is not a boolean",
			report: `{"skill_name":"demo","skill_path":"p","is_safe":"true","max_severity":"SAFE","findings_count":0,` +
				`"findings":[],"scan_duration_seconds":0.1,"duration_ms":100,"analyzers_used":["static"],` +
				`"timestamp":"2026-01-01T00:00:00+00:00","scan_metadata":{}}`,
			wantState: SupplyChainError, wantReason: "unrecognized_report",
		},
		{
			name:      "truncated report",
			report:    `{"skill_name":"demo","findings_count":`,
			wantState: SupplyChainError, wantReason: "malformed_report",
		},
		{
			name:      "duplicate member inside a finding (negative)",
			report:    schemaDerivedSkillReport(single, "1", "HIGH", false, schemaDerivedDuplicateMemberFinding, ""),
			wantState: SupplyChainError, wantReason: "unrecognized_report",
		},
		{
			name:      "case alias inside a finding (negative)",
			report:    schemaDerivedSkillReport(single, "1", "HIGH", false, schemaDerivedCaseAliasFinding, ""),
			wantState: SupplyChainError, wantReason: "unrecognized_report",
		},
		{
			name:      "blank analyzer name is not coverage (negative)",
			report:    schemaDerivedSkillReport(`[""]`, "0", "SAFE", true, schemaDerivedNoFindings, ""),
			wantState: SupplyChainIncomplete, wantReason: "invalid_analyzer",
		},
		{
			name:      "null analyzer name is not coverage (negative)",
			report:    schemaDerivedSkillReport(`[null]`, "0", "SAFE", true, schemaDerivedNoFindings, ""),
			wantState: SupplyChainIncomplete, wantReason: "invalid_analyzer",
		},
		{
			name:      "oversized report",
			report:    `{"skill_name":"` + strings.Repeat("x", supplyChainReportMaxBytes+1) + `"}`,
			wantState: SupplyChainError, wantReason: "report_too_large",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subject := mustSubject(t, map[string]string{"SKILL.md": strings.Repeat("a", 64)})
			result := ProjectSkillScan(subject, []byte(tc.report))
			if result.Scanner != SupplyChainScannerSkill || result.Family != SupplyChainFamilySkill {
				t.Fatalf("projection identity = %q/%q", result.Scanner, result.Family)
			}
			if result.State != tc.wantState || result.Reason != tc.wantReason {
				t.Fatalf("state = %q/%q, want %q/%q", result.State, result.Reason, tc.wantState, tc.wantReason)
			}
			if result.State != SupplyChainCompleted {
				if len(result.Findings) != 0 || len(result.AnalyzersUsed) != 0 {
					t.Fatalf("non-completed result carried findings %v / analyzers %v", result.Findings, result.AnalyzersUsed)
				}
				if result.RawDigest == "" {
					t.Fatal("non-completed result dropped the raw-report digest")
				}
				return
			}
			if tc.wantGrade != "" && SupplyChainGrade(result.Findings) != tc.wantGrade {
				t.Fatalf("grade = %q, want %q", SupplyChainGrade(result.Findings), tc.wantGrade)
			}
			if len(tc.wantFindingIDs) != len(result.Findings) {
				t.Fatalf("findings = %v, want ids %v", result.Findings, tc.wantFindingIDs)
			}
			for i, id := range tc.wantFindingIDs {
				if result.Findings[i].RuleID != id {
					t.Fatalf("finding %d rule id = %q, want %q", i, result.Findings[i].RuleID, id)
				}
			}
			if result.RawDigest != digestBytes([]byte(tc.report)) {
				t.Fatal("raw digest does not bind the parsed bytes")
			}
		})
	}
}

func TestSupplyChainContractProjectMCPScan(t *testing.T) {
	for _, tc := range []struct {
		name          string
		report        string
		wantState     SupplyChainState
		wantReason    string
		wantGrade     string
		wantAnalyzers []string
	}{
		{
			name:          "clean item completes",
			report:        schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPCleanGroup, "")),
			wantState:     SupplyChainCompleted,
			wantGrade:     "SAFE",
			wantAnalyzers: []string{"yara"},
		},
		{
			name:          "HIGH finding stays HIGH, no CRITICAL escalation",
			report:        schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPHighGroup, "")),
			wantState:     SupplyChainCompleted,
			wantGrade:     "HIGH",
			wantAnalyzers: []string{"yara"},
		},
		{
			name:       "SAFE group with a positive count is never clean",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPSafeWithCountGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "safe_with_findings",
		},
		{
			name:       "UNKNOWN severity is coverage, not a grade",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPUnknownGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "unknown_severity",
		},
		{
			name:       "analyzer group partial status",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPErrorGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "analyzer_error",
		},
		{
			name:       "item status not completed",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("partial", "null", schemaDerivedMCPCleanGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "scan_status_partial",
		},
		{
			name: "analyzer_errors make coverage incomplete",
			report: schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "null", schemaDerivedMCPCleanGroup,
				`,"analyzer_errors":[{"analyzer":"yara","error":"boom"}]`)),
			wantState:  SupplyChainIncomplete,
			wantReason: "analyzer_error",
		},
		{
			name:       "no analyzers reported",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", "{}", "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "missing_analyzers",
		},
		{
			name:       "is_safe contradicts a reported finding",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPHighGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "is_safe_mismatch",
		},
		{
			name:       "empty snapshot has no coverage",
			report:     `[]`,
			wantState:  SupplyChainIncomplete,
			wantReason: "no_scan_items",
		},
		{
			name:       "malformed JSON",
			report:     `[{"status":`,
			wantState:  SupplyChainError,
			wantReason: "malformed_report",
		},
		{
			name:       "unknown item key",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPCleanGroup, `,"extra":1`)),
			wantState:  SupplyChainError,
			wantReason: "unrecognized_report",
		},
		{
			name:       "unsupported item_type",
			report:     schemaDerivedMCPReport(`{"status":"completed","is_safe":true,"findings":{},"item_type":"widget"}`),
			wantState:  SupplyChainError,
			wantReason: "unrecognized_report",
		},
		{
			name:       "analyzer group is not an object",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", `{"yara_analyzer":[]}`, "")),
			wantState:  SupplyChainError,
			wantReason: "unrecognized_report",
		},
		{
			name:       "findings is not an analyzer map",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", `[]`, "")),
			wantState:  SupplyChainError,
			wantReason: "unrecognized_report",
		},
		{
			name:       "trailing content after the array",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPCleanGroup, "")) + ` []`,
			wantState:  SupplyChainError,
			wantReason: "malformed_report",
		},
		{
			name:       "duplicate analyzer key (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPDuplicateKeyGroup, "")),
			wantState:  SupplyChainError,
			wantReason: "unrecognized_report",
		},
		{
			name:       "case alias in an analyzer group (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPCaseAliasGroup, "")),
			wantState:  SupplyChainError,
			wantReason: "unrecognized_report",
		},
		{
			name:       "missing total_findings (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPMissingCountGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "missing_findings_count",
		},
		{
			name:       "null total_findings (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPNullCountGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "missing_findings_count",
		},
		{
			name:       "negative total_findings (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPNegativeCountGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "negative_findings_count",
		},
		{
			name:       "graded severity with a zero count (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPZeroCountHighGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "contradictory_counts",
		},
		{
			name:       "zero count with threat names (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPZeroCountNamedGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "contradictory_counts",
		},
		{
			name:       "positive count with no threat name (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPNoNamesHighGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "missing_threat_names",
		},
		{
			name:       "blank analyzer name is not coverage (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "true", schemaDerivedMCPBlankAnalyzerGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "invalid_analyzer",
		},
		{
			name:       "is_safe false with no findings (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPCleanGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "is_safe_mismatch",
		},
		{
			name:       "null is_safe on a completed item (negative)",
			report:     schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "null", schemaDerivedMCPCleanGroup, "")),
			wantState:  SupplyChainIncomplete,
			wantReason: "is_safe_mismatch",
		},
		{
			name:          "mcp_taxonomies is an accepted optional member",
			report:        schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPTaxonomyGroup, "")),
			wantState:     SupplyChainCompleted,
			wantGrade:     "HIGH",
			wantAnalyzers: []string{"yara"},
		},
		{
			name:          "deduped threat names need not equal the count",
			report:        schemaDerivedMCPReport(schemaDerivedMCPItem("completed", "false", schemaDerivedMCPDedupedNamesGroup, "")),
			wantState:     SupplyChainCompleted,
			wantGrade:     "HIGH",
			wantAnalyzers: []string{"yara"},
		},
		{
			name:       "object instead of array",
			report:     `{"status":"completed"}`,
			wantState:  SupplyChainError,
			wantReason: "unrecognized_report",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subject := mustSubject(t, map[string]string{"tools.json": strings.Repeat("a", 64)})
			result := ProjectMCPScan(subject, []byte(tc.report))
			if result.Scanner != SupplyChainScannerMCP || result.Family != SupplyChainFamilyMCP {
				t.Fatalf("projection identity = %q/%q", result.Scanner, result.Family)
			}
			if result.State != tc.wantState || result.Reason != tc.wantReason {
				t.Fatalf("state = %q/%q, want %q/%q", result.State, result.Reason, tc.wantState, tc.wantReason)
			}
			if result.State != SupplyChainCompleted {
				if len(result.Findings) != 0 {
					t.Fatalf("non-completed result carried findings %v", result.Findings)
				}
				return
			}
			if got := SupplyChainGrade(result.Findings); got != tc.wantGrade {
				t.Fatalf("grade = %q, want %q", got, tc.wantGrade)
			}
			if len(result.AnalyzersUsed) != len(tc.wantAnalyzers) {
				t.Fatalf("analyzers = %v, want %v", result.AnalyzersUsed, tc.wantAnalyzers)
			}
			for i, analyzer := range tc.wantAnalyzers {
				if result.AnalyzersUsed[i] != analyzer {
					t.Fatalf("analyzer %d = %q, want %q", i, result.AnalyzersUsed[i], analyzer)
				}
			}
		})
	}
}

func TestSupplyChainContractNotRunIsNeverClean(t *testing.T) {
	subject := mustSubject(t, map[string]string{"SKILL.md": strings.Repeat("a", 64)})
	result := SupplyChainNotRunResult(SupplyChainScannerSkill, SupplyChainFamilySkill, subject, "")
	if result.State != SupplyChainNotRun || result.Reason != "scanner_not_available" {
		t.Fatalf("not-run result = %q/%q", result.State, result.Reason)
	}
	if SupplyChainGrade(result.Findings) != "SAFE" || SupplyChainDefaultAction(SupplyChainGrade(result.Findings), result.Family) != "none" {
		t.Fatal("a not-run result must carry no grade and no action")
	}
	// RawDigest binds to nothing else here, and an empty report is still an error.
	if empty := ProjectSkillScan(subject, nil); empty.State != SupplyChainError || empty.Reason != "malformed_report" {
		t.Fatalf("empty report = %q/%q, want error/malformed_report", empty.State, empty.Reason)
	}
}

func TestSupplyChainContractOversizedReportsUseSharedBudget(t *testing.T) {
	subject := mustSubject(t, map[string]string{"tools.json": strings.Repeat("a", 64)})
	oversized := bytes.Repeat([]byte(" "), supplyChainReportMaxBytes+1)
	if result := ProjectMCPScan(subject, oversized); result.State != SupplyChainError || result.Reason != "report_too_large" {
		t.Fatalf("oversized report = %q/%q, want error/report_too_large", result.State, result.Reason)
	}
}
