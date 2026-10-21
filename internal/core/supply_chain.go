package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// Supply-chain scan-result contract (issue #42, slice S1): small types and pure
// functions only. No persistence, HTTP, worker or policy wiring lives here; no
// scanner is executed. The scanner tools are the pinned Cisco AI Defense
// sources the plan cites, and the projections below read the exact JSON shapes
// their serializers emit:
//
//   - skill-scanner ScanResult.to_dict / Finding.to_dict (pinned 8554b119)
//   - mcp-scanner report_generator.results_to_json (pinned 10032f98)
//
// Result binding follows the in-toto Statement v1 subject/digest model
// (https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md):
// results name immutable subjects by digest, never by path or name alone.
// Client-submitted findings are never authoritative; only a trusted supervisor
// that captured the bytes may construct these values.

// SupplyChainFamily is the protected asset family a result belongs to.
type SupplyChainFamily string

const (
	SupplyChainFamilySkill       SupplyChainFamily = "skill"
	SupplyChainFamilyMCP         SupplyChainFamily = "mcp"
	SupplyChainFamilyPlugin      SupplyChainFamily = "plugin"
	SupplyChainFamilyBuiltinTool SupplyChainFamily = "builtin-tool"
	SupplyChainFamilyMemoryFile  SupplyChainFamily = "memory-file"
)

// Scanner identities: the pinned upstream tool that produced a report.
const (
	SupplyChainScannerSkill = "skill-scanner"
	SupplyChainScannerMCP   = "mcp-scanner"
)

// SupplyChainState is the completion state. Only SupplyChainCompleted describes
// a finished scan; every other state is operational or coverage information and
// is never a risk grade, a clean result or an authorization.
type SupplyChainState string

const (
	SupplyChainCompleted  SupplyChainState = "completed"
	SupplyChainIncomplete SupplyChainState = "incomplete"
	SupplyChainError      SupplyChainState = "error"
	SupplyChainNotRun     SupplyChainState = "not_run"
)

// SupplyChainSubject pins an immutable multi-file subject as relative path ->
// SHA-256 of the captured bytes, plus a digest over the complete sorted
// membership. Adding, removing or changing any member changes Digest, so a
// changed sibling script invalidates a result even when SKILL.md is unchanged.
type SupplyChainSubject struct {
	Digest string
	Files  map[string]string
}

// Named local versioned contract. in-toto defines subject digests over one
// artifact's bytes; a multi-file package needs a canonical membership
// serialization, which this product owns. Domain-separated, path-sorted, one
// "path\0sha256" record per line, so membership and content are both bound.
const supplyChainSubjectDomain = "tg-sentry-supply-chain-subject/v1"

// NewSupplyChainSubject validates and copies the membership and computes its
// digest. Paths are relative to the capture root; absolute, empty, "." or ".."
// segments and backslash separators are rejected, as are non-SHA-256 digests.
func NewSupplyChainSubject(files map[string]string) (SupplyChainSubject, error) {
	if len(files) == 0 {
		return SupplyChainSubject{}, errors.New("empty supply-chain subject")
	}
	validated := make(map[string]string, len(files))
	for path, hash := range files {
		if !validSupplyChainPath(path) || !isSupplyChainHash(hash) {
			return SupplyChainSubject{}, errors.New("invalid supply-chain subject member")
		}
		validated[path] = hash
	}
	return SupplyChainSubject{Digest: supplyChainSubjectDigest(validated), Files: validated}, nil
}

func supplyChainSubjectDigest(files map[string]string) string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	h := sha256.New()
	io.WriteString(h, supplyChainSubjectDomain+"\n")
	for _, path := range paths {
		io.WriteString(h, path)
		h.Write([]byte{0})
		io.WriteString(h, files[path])
		io.WriteString(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validSupplyChainPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00\n\r") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func isSupplyChainHash(hash string) bool {
	if len(hash) != sha256.Size*2 || strings.ToLower(hash) != hash {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

// SupplyChainFinding is a normalized finding. Severity stays exactly as the
// upstream analyzer reported it: this contract never escalates a grade, so
// mcp-scanner HIGH stays HIGH (that scanner has no CRITICAL grade). Category
// keeps the upstream category value; consumers map it to category::supply-chain.
type SupplyChainFinding struct {
	RuleID   string
	Category string
	Severity string
	Analyzer string
}

// SupplyChainResult is the trusted record a supervisor may persist. State and
// Reason, not Findings, carry coverage: a result that is not completed cannot be
// treated as clean. RawDigest binds the exact report bytes that were parsed.
type SupplyChainResult struct {
	Scanner       string
	Family        SupplyChainFamily
	Subject       SupplyChainSubject
	State         SupplyChainState
	Reason        string
	RawDigest     string
	AnalyzersUsed []string
	Findings      []SupplyChainFinding
}

// Named local exception, not a measured scanner-report limit: the plan's
// §3 rule is that resource ceilings need documented precedent or measurements
// before enforcement ships, and no such measurement exists yet. The number
// reuses the existing in-repo config-parse size (client_drift.go:16, 2 MiB) as a
// starting parse cap only. Applicability to whole-package scanning reports is
// pending measurement; this constant is not a derived scanning budget and
// carries no cross-package bridge dependency.
const supplyChainReportMaxBytes = clientDriftMaxBytes

// Severity vocabularies. UNKNOWN is an operational coverage state, not a grade,
// and is deliberately absent from both lists.
var (
	supplyChainSkillSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"}
	supplyChainMCPSeverities   = []string{"HIGH", "MEDIUM", "LOW", "INFO", "SAFE"}
)

// Grade order used for roll-up; SAFE is not a grade a finding can raise.
var supplyChainGradeOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

// SupplyChainGrade returns the worst severity across findings, or "SAFE" when
// there are none. It is a summary of declared coverage only.
func SupplyChainGrade(findings []SupplyChainFinding) string {
	for _, grade := range supplyChainGradeOrder {
		for _, finding := range findings {
			if finding.Severity == grade {
				return grade
			}
		}
	}
	return "SAFE"
}

// SupplyChainDefaultAction maps a grade and asset family to the existing
// protection action vocabulary (protection.go:176). CRITICAL/HIGH block and
// MEDIUM/LOW log are the AgentSentry default recorded at
// docs/PROTECTION-CATEGORIES.md:78-80. Plugins and coding-agent built-in tools
// are scan-only and never block, whatever the grade
// (docs/PROTECTION-CATEGORIES.md:79).
//
// "none" (returned for INFO, SAFE, UNKNOWN and any unknown grade) is a local
// "emit no action" sentinel, NOT a protection action: it is deliberately absent
// from protection.go's action vocabulary (block/alert/log-only/redact).
// Consumers must skip it — never write it as a rule action, and never read it as
// authorization — because actionDecision() would otherwise fall through to
// "approve" (protection.go:483-492).
func SupplyChainDefaultAction(grade string, family SupplyChainFamily) string {
	switch grade {
	case "CRITICAL", "HIGH":
		if family == SupplyChainFamilyPlugin || family == SupplyChainFamilyBuiltinTool {
			return "alert"
		}
		return "block"
	case "MEDIUM", "LOW":
		return "log-only"
	default:
		return "none"
	}
}

// SupplyChainNotRunResult is the explicit NOT RUN record: a missing or
// unusable scanner is never a clean scan.
func SupplyChainNotRunResult(scanner string, family SupplyChainFamily, subject SupplyChainSubject, reason string) SupplyChainResult {
	if reason == "" {
		reason = "scanner_not_available"
	}
	return SupplyChainResult{Scanner: scanner, Family: family, Subject: subject, State: SupplyChainNotRun, Reason: reason}
}

// supplyChainParse is the parser outcome before the raw-report digest is bound.
type supplyChainParse struct {
	State         SupplyChainState
	Reason        string
	AnalyzersUsed []string
	Findings      []SupplyChainFinding
}

// ProjectSkillScan projects one Cisco skill-scanner JSON object.
func ProjectSkillScan(subject SupplyChainSubject, raw []byte) SupplyChainResult {
	return projectSupplyChain(subject, SupplyChainScannerSkill, SupplyChainFamilySkill, raw, parseSkillScanReport)
}

// ProjectMCPScan projects the raw mcp-scanner JSON array (one element per
// scanned item).
func ProjectMCPScan(subject SupplyChainSubject, raw []byte) SupplyChainResult {
	return projectSupplyChain(subject, SupplyChainScannerMCP, SupplyChainFamilyMCP, raw, parseMCPScanReport)
}

func projectSupplyChain(subject SupplyChainSubject, scanner string, family SupplyChainFamily, raw []byte, parse func([]byte) supplyChainParse) SupplyChainResult {
	result := SupplyChainResult{Scanner: scanner, Family: family, Subject: subject, RawDigest: digestBytes(raw)}
	// An oversized report is never truncated and never parsed: it cannot become
	// a completed result.
	if len(raw) > supplyChainReportMaxBytes {
		result.State, result.Reason = SupplyChainError, "report_too_large"
		return result
	}
	// Malformed bytes are reported distinctly from a schema we do not recognize.
	if !json.Valid(raw) {
		result.State, result.Reason = SupplyChainError, "malformed_report"
		return result
	}
	parsed := parse(raw)
	result.State, result.Reason, result.AnalyzersUsed, result.Findings = parsed.State, parsed.Reason, parsed.AnalyzersUsed, parsed.Findings
	if result.Findings == nil {
		result.Findings = []SupplyChainFinding{}
	}
	if result.AnalyzersUsed == nil {
		result.AnalyzersUsed = []string{}
	}
	return result
}

// Decoded shape of the pinned skill-scanner serializer: these members are
// always emitted, so a report missing one is not that schema.
var supplyChainSkillScanKeys = map[string]bool{
	"skill_name": true, "skill_path": true, "is_safe": true, "max_severity": true,
	"findings_count": true, "findings": true, "scan_duration_seconds": true,
	"duration_ms": true, "analyzers_used": true, "timestamp": true,
	"scan_metadata": true, "analyzers_failed": true, "llm_usage": true,
	"suppressed_findings": true,
}

var supplyChainSkillScanRequired = []string{
	"skill_name", "skill_path", "is_safe", "max_severity", "findings_count",
	"findings", "scan_duration_seconds", "duration_ms", "analyzers_used",
	"timestamp", "scan_metadata",
}

func supplyChainParseError(reason string) supplyChainParse {
	return supplyChainParse{State: SupplyChainError, Reason: reason}
}

func supplyChainParseIncomplete(reason string) supplyChainParse {
	return supplyChainParse{State: SupplyChainIncomplete, Reason: reason}
}

func parseSkillScanReport(raw []byte) supplyChainParse {
	fields, ok := decodeExactObject(raw, supplyChainSkillScanKeys)
	if !ok {
		return supplyChainParseError("unrecognized_report")
	}
	for _, key := range supplyChainSkillScanRequired {
		if _, present := fields[key]; !present {
			return supplyChainParseError("unrecognized_report")
		}
	}
	var skillName string
	if json.Unmarshal(fields["skill_name"], &skillName) != nil || strings.TrimSpace(skillName) == "" {
		return supplyChainParseError("unrecognized_report")
	}
	var analyzersUsed []string
	if json.Unmarshal(fields["analyzers_used"], &analyzersUsed) != nil {
		return supplyChainParseError("unrecognized_report")
	}
	var findingsCount int
	if json.Unmarshal(fields["findings_count"], &findingsCount) != nil || findingsCount < 0 {
		return supplyChainParseError("unrecognized_report")
	}
	var maxSeverity string
	if json.Unmarshal(fields["max_severity"], &maxSeverity) != nil {
		return supplyChainParseError("unrecognized_report")
	}
	var isSafe bool
	if json.Unmarshal(fields["is_safe"], &isSafe) != nil {
		return supplyChainParseError("unrecognized_report")
	}
	// Coverage first: a scan whose analyzers did not all run is incomplete,
	// regardless of what its findings say. A blank or null analyzer name is not
	// coverage either: it cannot attribute a finding.
	if len(analyzersUsed) == 0 {
		return supplyChainParseIncomplete("missing_analyzers")
	}
	for _, analyzer := range analyzersUsed {
		if strings.TrimSpace(analyzer) == "" {
			return supplyChainParseIncomplete("invalid_analyzer")
		}
	}
	if raw, present := fields["analyzers_failed"]; present {
		var failed []json.RawMessage
		if json.Unmarshal(raw, &failed) != nil {
			return supplyChainParseError("unrecognized_report")
		}
		if len(failed) > 0 {
			return supplyChainParseIncomplete("analyzer_failed")
		}
	}
	// Findings are verdict-bearing, so each one is decoded under the same
	// exact-key rule as the report: a duplicate member or a case alias (for
	// example "severity":"HIGH" with "Severity":"SAFE") must not downgrade a
	// verdict. The remaining documented Finding members (title, description,
	// file_path, line_number, snippet, remediation, metadata) are accepted but
	// not consumed.
	reported, ok := decodeArrayOfExactObjects(fields["findings"], supplyChainSkillFindingKeys)
	if !ok {
		return supplyChainParseError("unrecognized_report")
	}
	// The pinned serializer checks HIGH/CRITICAL only and does not itself
	// account for analyzer failures, so is_safe is cross-checked, never trusted.
	if findingsCount != len(reported) {
		return supplyChainParseIncomplete("findings_count_mismatch")
	}
	findings := make([]SupplyChainFinding, 0, len(reported))
	for _, finding := range reported {
		ruleID, ok := supplyChainRequiredString(finding, "rule_id")
		if !ok {
			return supplyChainParseError("unrecognized_report")
		}
		severity, ok := supplyChainRequiredString(finding, "severity")
		if !ok {
			return supplyChainParseError("unrecognized_report")
		}
		if strings.TrimSpace(ruleID) == "" {
			return supplyChainParseIncomplete("missing_rule_id")
		}
		if !hasExact(severity, supplyChainSkillSeverities...) {
			return supplyChainParseIncomplete("unknown_severity")
		}
		// A SAFE-marked finding is a reporting inconsistency, never a clean
		// result and never a silent downgrade to LOW.
		if severity == "SAFE" {
			return supplyChainParseIncomplete("safe_with_findings")
		}
		category, ok := supplyChainOptionalString(finding, "category")
		if !ok {
			return supplyChainParseError("unrecognized_report")
		}
		analyzer, ok := supplyChainOptionalString(finding, "analyzer")
		if !ok {
			return supplyChainParseError("unrecognized_report")
		}
		if analyzer == "" {
			// Upstream leaves analyzer null; name the analyzer after the only
			// analyzer that ran so the finding stays attributable.
			if len(analyzersUsed) != 1 {
				return supplyChainParseIncomplete("missing_analyzer")
			}
			analyzer = analyzersUsed[0]
		}
		findings = append(findings, SupplyChainFinding{RuleID: ruleID, Category: category, Severity: severity, Analyzer: analyzer})
	}
	if !hasExact(maxSeverity, supplyChainSkillSeverities...) {
		return supplyChainParseIncomplete("unknown_severity")
	}
	grade := SupplyChainGrade(findings)
	if grade != maxSeverity {
		return supplyChainParseIncomplete("max_severity_mismatch")
	}
	// Upstream is_safe is False only for CRITICAL/HIGH, and it never accounts
	// for analyzer failures; it is cross-checked, never trusted.
	if unsafe := grade == "CRITICAL" || grade == "HIGH"; isSafe == unsafe {
		return supplyChainParseIncomplete("is_safe_mismatch")
	}
	return supplyChainParse{State: SupplyChainCompleted, AnalyzersUsed: analyzersUsed, Findings: findings}
}

// Decoded shape of the pinned mcp-scanner per-item serializer.
var supplyChainMCPScanKeys = map[string]bool{
	"status": true, "is_safe": true, "findings": true, "analyzer_errors": true,
	"meta_analysis": true, "tool_name": true, "tool_description": true,
	"prompt_name": true, "prompt_description": true, "resource_uri": true,
	"resource_name": true, "resource_mime_type": true, "item_type": true,
	"server_source": true, "server_name": true,
}

var supplyChainMCPItemNameKey = map[string]string{
	"tool": "tool_name", "prompt": "prompt_name", "resource": "resource_uri",
}

// Documented Finding.to_dict members. An analyzer's own unknown member or a
// case alias is rejected rather than silently read as the field it resembles.
var supplyChainSkillFindingKeys = map[string]bool{
	"id": true, "rule_id": true, "category": true, "severity": true,
	"title": true, "description": true, "file_path": true, "line_number": true,
	"snippet": true, "remediation": true, "analyzer": true, "metadata": true,
}

// One "<analyzer>_analyzer" group; the analyzer completed with no findings when
// severity is SAFE and total_findings is 0. mcp_taxonomies and the remaining
// documented optional members are accepted without being consumed.
var supplyChainMCPGroupKeys = map[string]bool{
	"severity": true, "threat_names": true, "threat_summary": true,
	"total_findings": true, "status": true, "errors": true,
	"mcp_taxonomies": true,
}

func parseMCPScanReport(raw []byte) supplyChainParse {
	items, ok := decodeArrayOfObjects(raw)
	if !ok {
		return supplyChainParseError("unrecognized_report")
	}
	// An empty snapshot carries no coverage: nothing was scanned.
	if len(items) == 0 {
		return supplyChainParseIncomplete("no_scan_items")
	}
	var findings []SupplyChainFinding
	analyzersUsed := []string{}
	for _, item := range items {
		fields, ok := decodeExactObject(item, supplyChainMCPScanKeys)
		if !ok {
			return supplyChainParseError("unrecognized_report")
		}
		for _, key := range []string{"status", "is_safe", "findings", "item_type"} {
			if _, present := fields[key]; !present {
				return supplyChainParseError("unrecognized_report")
			}
		}
		var itemType string
		if json.Unmarshal(fields["item_type"], &itemType) != nil {
			return supplyChainParseError("unrecognized_report")
		}
		nameKey, supported := supplyChainMCPItemNameKey[itemType]
		if !supported {
			return supplyChainParseError("unrecognized_report")
		}
		if _, present := fields[nameKey]; !present {
			return supplyChainParseError("unrecognized_report")
		}
		var status string
		if json.Unmarshal(fields["status"], &status) != nil {
			return supplyChainParseError("unrecognized_report")
		}
		// Upstream emits completed/partial/failed/skipped; is_safe is null for
		// every status but completed (result.py is_safe).
		if status != "completed" {
			return supplyChainParseIncomplete("scan_status_" + status)
		}
		var isSafe *bool
		if json.Unmarshal(fields["is_safe"], &isSafe) != nil {
			return supplyChainParseError("unrecognized_report")
		}
		if raw, present := fields["analyzer_errors"]; present {
			var errs []json.RawMessage
			if json.Unmarshal(raw, &errs) != nil {
				return supplyChainParseError("unrecognized_report")
			}
			if len(errs) > 0 {
				return supplyChainParseIncomplete("analyzer_error")
			}
		}
		// The analyzer-name map and each group object are verdict-bearing, so
		// they are decoded under the same exact-key rule: a repeated analyzer
		// key or a case alias cannot change a verdict. mcp_taxonomies and the
		// other documented optional group members stay accepted.
		rawGroups, ok := decodeExactKeys(fields["findings"], func(key string) bool {
			return strings.HasSuffix(key, "_analyzer")
		})
		if !ok {
			return supplyChainParseError("unrecognized_report")
		}
		if len(rawGroups) == 0 {
			return supplyChainParseIncomplete("missing_analyzers")
		}
		groupKeys := make([]string, 0, len(rawGroups))
		for key := range rawGroups {
			groupKeys = append(groupKeys, key)
		}
		// Sorted so the reported reason is deterministic across map iteration.
		sort.Strings(groupKeys)
		itemFindings := []SupplyChainFinding{}
		itemTotal := 0
		for _, key := range groupKeys {
			analyzer := strings.TrimSuffix(key, "_analyzer")
			// A blank analyzer name is not coverage: it cannot attribute a
			// finding.
			if strings.TrimSpace(analyzer) == "" {
				return supplyChainParseIncomplete("invalid_analyzer")
			}
			group, ok := decodeExactObject(rawGroups[key], supplyChainMCPGroupKeys)
			if !ok {
				return supplyChainParseError("unrecognized_report")
			}
			severity, ok := supplyChainRequiredString(group, "severity")
			if !ok {
				return supplyChainParseError("unrecognized_report")
			}
			if !hasExact(severity, supplyChainMCPSeverities...) {
				return supplyChainParseIncomplete("unknown_severity")
			}
			// The count must be present and non-negative: a missing or null
			// count must never default to 0 and read as clean.
			count, ok := supplyChainOptionalInt(group, "total_findings")
			if !ok {
				return supplyChainParseIncomplete("missing_findings_count")
			}
			if count < 0 {
				return supplyChainParseIncomplete("negative_findings_count")
			}
			// The pinned serializer can retain SAFE for other severities
			// despite a positive count; a graded severity with a zero count is
			// the mirror inconsistency. Neither is clean.
			if severity == "SAFE" && count > 0 {
				return supplyChainParseIncomplete("safe_with_findings")
			}
			if severity != "SAFE" && count == 0 {
				return supplyChainParseIncomplete("contradictory_counts")
			}
			groupStatus, ok := supplyChainOptionalString(group, "status")
			if !ok {
				return supplyChainParseError("unrecognized_report")
			}
			var groupErrors []json.RawMessage
			if rawErrors, present := group["errors"]; present && string(rawErrors) != "null" {
				if json.Unmarshal(rawErrors, &groupErrors) != nil {
					return supplyChainParseError("unrecognized_report")
				}
			}
			// The generator writes status/errors only when an analyzer failed
			// or was partially filtered.
			if groupStatus != "" || len(groupErrors) > 0 {
				return supplyChainParseIncomplete("analyzer_error")
			}
			var names []string
			if rawNames, present := group["threat_names"]; present && string(rawNames) != "null" {
				if json.Unmarshal(rawNames, &names) != nil {
					return supplyChainParseError("unrecognized_report")
				}
			}
			// Upstream dedupes threat names, so names need not equal the count;
			// a positive count with no name at all is still unattributable, and
			// a zero count that still names threats is the mirror
			// contradiction: it would project a finding from a clean group.
			if count > 0 && len(names) == 0 {
				return supplyChainParseIncomplete("missing_threat_names")
			}
			if count == 0 && len(names) > 0 {
				return supplyChainParseIncomplete("contradictory_counts")
			}
			itemTotal += count
			for _, name := range names {
				itemFindings = append(itemFindings, SupplyChainFinding{RuleID: name, Severity: severity, Analyzer: analyzer})
			}
			analyzersUsed = append(analyzersUsed, analyzer)
		}
		// result.py:87-99: is_safe is False when findings exist, True when a
		// completed scan found none, and null when coverage is incomplete. Both
		// directions are cross-checked; null is never accepted here.
		expectedSafe := itemTotal == 0
		if isSafe == nil || *isSafe != expectedSafe {
			return supplyChainParseIncomplete("is_safe_mismatch")
		}
		findings = append(findings, itemFindings...)
	}
	sort.Strings(analyzersUsed)
	return supplyChainParse{State: SupplyChainCompleted, AnalyzersUsed: analyzersUsed, Findings: findings}
}

// decodeExactObject reads one JSON object, rejecting unknown keys, duplicate
// keys and trailing content, using the same exact-key approach as
// prompt_attack_classifier.go:95-142: the standard decoder otherwise accepts
// case variants and duplicate fields, and neither may change a security verdict.
func decodeExactObject(raw []byte, allowed map[string]bool) (map[string]json.RawMessage, bool) {
	return decodeExactKeys(raw, func(key string) bool { return allowed[key] })
}

// decodeExactKeys is decodeExactObject with a dynamic key rule, for maps such as
// mcp-scanner's analyzer-name-keyed findings, where the member names are not a
// fixed set but must still be unique and unambiguous.
func decodeExactKeys(raw []byte, allowed func(string) bool) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, ok := token.(string)
		if !ok || !allowed(name) {
			return nil, false
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		fields[name] = value
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return nil, false
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, false
	}
	return fields, true
}

// decodeArrayOfExactObjects applies the same exact-key rule to every element.
func decodeArrayOfExactObjects(raw []byte, allowed map[string]bool) ([]map[string]json.RawMessage, bool) {
	items, ok := decodeArrayOfObjects(raw)
	if !ok {
		return nil, false
	}
	objects := make([]map[string]json.RawMessage, 0, len(items))
	for _, item := range items {
		fields, ok := decodeExactObject(item, allowed)
		if !ok {
			return nil, false
		}
		objects = append(objects, fields)
	}
	return objects, true
}

// supplyChainOptionalString reads a member that may be absent, null or a string.
func supplyChainOptionalString(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, present := fields[key]
	if !present || string(raw) == "null" {
		return "", true
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

// supplyChainRequiredString reads a member that must be present and a string.
func supplyChainRequiredString(fields map[string]json.RawMessage, key string) (string, bool) {
	value, ok := supplyChainOptionalString(fields, key)
	_, present := fields[key]
	return value, ok && present
}

// supplyChainOptionalInt reads a member that must be present, non-null and an
// integer; a missing member is reported rather than defaulted to zero.
func supplyChainOptionalInt(fields map[string]json.RawMessage, key string) (int, bool) {
	raw, present := fields[key]
	if !present || string(raw) == "null" {
		return 0, false
	}
	var value int
	if json.Unmarshal(raw, &value) != nil {
		return 0, false
	}
	return value, true
}

func decodeArrayOfObjects(raw []byte) ([]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('[') {
		return nil, false
	}
	var items []json.RawMessage
	for dec.More() {
		var item json.RawMessage
		if err := dec.Decode(&item); err != nil {
			return nil, false
		}
		items = append(items, item)
	}
	if end, err := dec.Token(); err != nil || end != json.Delim(']') {
		return nil, false
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, false
	}
	return items, true
}
