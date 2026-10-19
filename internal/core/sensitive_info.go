package core

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const SensitiveInfoCategory = "category::sensitive-info"

// Separate names avoid importing the in-progress #26 harness. Its Detector
// adapter only translates these equivalent fields; offsets are UTF-16 exclusive.
type SensitiveInput struct{ Text, Language, Surface, Tenant string }
type SensitiveSpan struct {
	StartUTF16 int `json:"startUTF16"`
	EndUTF16   int `json:"endUTF16"`
}
type SensitiveFinding struct {
	Category   string         `json:"category"`
	Tag        string         `json:"tag"`
	EntityType string         `json:"entityType"`
	Span       *SensitiveSpan `json:"span,omitempty"`
	Score      float64        `json:"score"`
	RuleID     string         `json:"ruleId,omitempty"`
}
type SensitiveResult struct {
	Findings    []SensitiveFinding `json:"findings"`
	Decision    string             `json:"decision"`
	Unavailable bool               `json:"unavailable"`
	Reason      string             `json:"reason,omitempty"`
	RuleID      string             `json:"ruleId,omitempty"`
}
type SensitiveDetector struct {
	BTPII BTPIIConfig
	// nil uses all built-in types for a standalone detector; an explicit empty
	// slice disables detection. Engine callers pass their resolved tenant rules.
	Rules []Rule
}

func sensitiveInfoRules() []Rule {
	rules := []Rule{}
	for _, item := range []struct{ id, name, tag string }{
		{"R_PII_CARD", "Bank card number", "bank-card"},
		{"R_PII_ID", "ID number", "id-number"},
		{"R_PII_EMAIL", "E-mail address", "email"},
		{"R_PII_PHONE", "Mobile phone number", "mobile"},
		{"R_PII_OTHER", "Other private data (compat labels only)", "other"},
	} {
		// Opt-in until a workload endpoint is provisioned, like R_NET_PIPE. Binding
		// a template enables its selected detector without changing the baseline.
		rules = append(rules, Rule{ID: item.id, Name: item.name, Matcher: "btpii", Target: "arguments", Pattern: item.tag, Decision: "reject", Builtin: true, Categories: []string{SensitiveInfoCategory}})
	}
	return rules
}
func (d SensitiveDetector) Detect(ctx context.Context, in SensitiveInput) (SensitiveResult, error) {
	result := SensitiveResult{Findings: []SensitiveFinding{}, Decision: "approve"}
	if in.Tenant != "" && in.Tenant != eventTenant() {
		return unavailableSensitive()
	}
	if in.Surface != "" && !hasExact(in.Surface, "prompt", "tool_input", "tool_result", "file", "final_response") {
		return unavailableSensitive()
	}
	if !utf8.ValidString(in.Text) {
		return unavailableSensitive()
	}
	rules := append([]Rule{}, d.Rules...)
	if d.Rules == nil {
		rules = sensitiveInfoRules()
		for i := range rules {
			rules[i].Enabled = true
		}
	}
	sortRules(rules)
	ctx, cancel := context.WithTimeout(ctx, btpiiBudget)
	defer cancel()
	remote := false
	for _, r := range rules {
		if r.Enabled && r.Matcher == "btpii" {
			remote = true
		}
	}
	if remote && in.Text != "" {
		if in.Language == "" {
			in.Language = d.BTPII.resolved().Language
		}
		findings, err := d.BTPII.analyze(ctx, in.Text, in.Language)
		if err != nil {
			return unavailableSensitive()
		}
		for _, f := range findings {
			for _, r := range rules {
				if !r.Enabled || r.Matcher != "btpii" || r.Pattern != f.Tag {
					continue
				}
				f.RuleID = r.ID
				selectSensitiveDecision(&result, r)
				break
			}
			// Labels remain visible even if no selected rule handles their type.
			result.Findings = append(result.Findings, f)
		}
	}
	for _, r := range rules {
		if !r.Enabled || r.Matcher == "btpii" || !hasExact(SensitiveInfoCategory, r.Categories...) {
			continue
		}
		spans, err := customSensitiveSpans(r, in.Text)
		if err != nil {
			return unavailableSensitive()
		}
		for _, span := range spans {
			result.Findings = append(result.Findings, SensitiveFinding{Category: SensitiveInfoCategory, Tag: "custom", EntityType: "CUSTOM", Span: &SensitiveSpan{utf16Length(in.Text[:span[0]]), utf16Length(in.Text[:span[1]])}, Score: 1, RuleID: r.ID})
			selectSensitiveDecision(&result, r)
		}
	}
	if ctx.Err() != nil {
		return unavailableSensitive()
	}
	return result, nil
}
func unavailableSensitive() (SensitiveResult, error) {
	return SensitiveResult{Findings: []SensitiveFinding{}, Decision: "reject", Unavailable: true, Reason: btpiiUnavailable.Error()}, btpiiUnavailable
}
func selectSensitiveDecision(result *SensitiveResult, r Rule) {
	if result.RuleID == "" || decisionStrength(r.Decision) > decisionStrength(result.Decision) {
		result.Decision, result.RuleID = r.Decision, r.ID
	}
}
func customSensitiveSpans(r Rule, text string) ([][2]int, error) {
	spans := [][2]int{}
	if r.Matcher == "regex" {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, btpiiUnavailable
		}
		for _, span := range re.FindAllStringIndex(text, -1) {
			if span[0] < span[1] {
				spans = append(spans, [2]int{span[0], span[1]})
			}
		}
		return spans, nil
	}
	if !hasExact(r.Matcher, "contains", "keywords") || r.Pattern == "" {
		return nil, btpiiUnavailable
	}
	patterns := []string{r.Pattern}
	if r.Matcher == "keywords" {
		patterns = strings.Split(r.Pattern, "\n")
	}
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		for start := 0; start < len(text); {
			i := strings.Index(text[start:], pattern)
			if i < 0 {
				break
			}
			i += start
			spans = append(spans, [2]int{i, i + len(pattern)})
			start = i + len(pattern)
		}
	}
	return spans, nil
}
func utf16Length(text string) int { return len(utf16.Encode([]rune(text))) }
func utf16ByteOffsets(text string) []int {
	offsets := []int{0}
	for index, r := range text {
		if r > 0xFFFF {
			offsets = append(offsets, -1)
		}
		offsets = append(offsets, index+utf8.RuneLen(r))
	}
	return offsets
}
func validSensitiveSpan(offsets []int, start, end int) bool {
	return start >= 0 && start < end && end < len(offsets) && offsets[start] >= 0 && offsets[end] >= 0
}

// RedactSensitive is a pure MARKER-style rewrite, following BTPII replace.py.
// Only a synchronous client rewrite hook may use the returned text as output.
// Cross-label overlaps are unioned to avoid leaking part of either finding;
// mixed labels use the existing generic REDACTED marker, not a guessed type.
func RedactSensitive(text string, findings []SensitiveFinding) (string, error) {
	if !utf8.ValidString(text) {
		return "", errors.New("invalid redaction input")
	}
	offsets := utf16ByteOffsets(text)
	type replacement struct {
		start, end int
		label      string
	}
	spans := []replacement{}
	for _, f := range findings {
		if f.Span == nil || !validSensitiveSpan(offsets, f.Span.StartUTF16, f.Span.EndUTF16) || !btpiiLabel.MatchString(f.EntityType) {
			return "", errors.New("invalid redaction finding")
		}
		spans = append(spans, replacement{offsets[f.Span.StartUTF16], offsets[f.Span.EndUTF16], f.EntityType})
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end < spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	merged := []replacement{}
	for _, span := range spans {
		if len(merged) > 0 && span.start < merged[len(merged)-1].end {
			last := &merged[len(merged)-1]
			last.end = max(last.end, span.end)
			if last.label != span.label {
				last.label = "REDACTED"
			}
		} else {
			merged = append(merged, span)
		}
	}
	var out strings.Builder
	start := 0
	for _, span := range merged {
		out.WriteString(text[start:span.start])
		out.WriteString("[" + span.label + "]")
		start = span.end
	}
	out.WriteString(text[start:])
	return out.String(), nil
}
