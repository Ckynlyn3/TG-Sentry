package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Scan returns UTF-16 locations in the original text, never candidate material.
// Gitleaks b58d3f10 detect/detect.go:321–348: case-insensitive keyword OR,
// keyword-less rules always run. Inline gitleaks:allow is deliberately ignored
// (plan §3.1). Cancellation discards all findings (plan §3.2).
func Scan(ctx context.Context, text string) ([]Finding, Status) {
	if ctx.Err() != nil || !utf8.ValidString(text) {
		return nil, Interrupted
	}
	lower := strings.ToLower(text)
	var findings []Finding
	for _, r := range rules {
		if ctx.Err() != nil {
			return nil, Interrupted
		}
		if hasKeyword(lower, r.keywords) {
			findings = append(findings, scanRule(text, r)...)
		}
	}
	if ctx.Err() != nil {
		return nil, Interrupted
	}
	return findings, Complete
}

func hasKeyword(lower string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func scanRule(text string, r rule) []Finding {
	var findings []Finding
	byteCursor, unitCursor := 0, 0
	for _, indices := range r.regex.FindAllStringSubmatchIndex(text, -1) {
		start, end := secretBounds(indices, r.secretGroup)
		if start < 0 || start == end {
			continue
		}
		secret := text[start:end]
		// Gitleaks b58d3f10 detect/detect.go:547–565: reject <= threshold,
		// on the extracted secret, then global AND per-rule allowlist checks.
		if r.entropy != 0 && shannonEntropy(secret) <= r.entropy {
			continue
		}
		if allowed(globalAllowlists, text, indices[0], indices[1], secret) || allowed(r.allowlists, text, indices[0], indices[1], secret) {
			continue
		}
		// Regexp results are ordered/non-overlapping: count each prefix once,
		// not once per finding (which would be quadratic for repeated tokens).
		unitCursor += utf16Length(text[byteCursor:start])
		startUTF16 := unitCursor
		unitCursor += utf16Length(text[start:end])
		byteCursor = end
		findings = append(findings, Finding{RuleID: r.id, EntityType: r.id, Span: Span{startUTF16, unitCursor}})
	}
	return findings
}

func utf16Length(text string) int {
	n := 0
	for _, r := range text {
		n += utf16.RuneLen(r)
	}
	return n
}

// Gitleaks b58d3f10 detect/detect.go:524–545: explicit secretGroup, else
// first nonempty capture, else full match. Spans use that extracted capture
// rather than the upstream line/column full-match position (lead disposition).
func secretBounds(indices []int, group int) (int, int) {
	if group > 0 {
		if 2*group+1 >= len(indices) {
			return -1, -1
		}
		return indices[2*group], indices[2*group+1]
	}
	for i := 2; i < len(indices); i += 2 {
		if indices[i] >= 0 && indices[i] < indices[i+1] {
			return indices[i], indices[i+1]
		}
	}
	return indices[0], indices[1]
}

// ScanTree follows core.Redact's map/array/string traversal, scanning both keys
// and values before masking. A caller-owned surface and hashed dotted leaf path
// describe each finding; the cleartext path is in-memory only (plan §3.6).
func ScanTree(ctx context.Context, v any, surface string) ([]Leaf, Status) {
	var leaves []Leaf
	if !walkTree(ctx, v, "", surface, &leaves) || ctx.Err() != nil {
		return nil, Interrupted
	}
	return leaves, Complete
}

func walkTree(ctx context.Context, v any, path, surface string, leaves *[]Leaf) bool {
	if ctx.Err() != nil {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			child := key
			if path != "" {
				child = path + "." + key
			}
			if !scanLeaf(ctx, key, child, surface, "key", leaves) || !walkTree(ctx, value, child, surface, leaves) {
				return false
			}
		}
	case []any:
		for i, value := range x {
			child := strconv.Itoa(i)
			if path != "" {
				child = path + "." + child
			}
			if !walkTree(ctx, value, child, surface, leaves) {
				return false
			}
		}
	case string:
		return scanLeaf(ctx, x, path, surface, "value", leaves)
	}
	return true
}

func scanLeaf(ctx context.Context, text, path, surface, kind string, leaves *[]Leaf) bool {
	findings, status := Scan(ctx, text)
	if status != Complete {
		return false
	}
	sum := sha256.Sum256([]byte(path))
	for _, finding := range findings {
		*leaves = append(*leaves, Leaf{Finding: finding, Surface: surface, Kind: kind,
			FieldDigest: hex.EncodeToString(sum[:]), Path: path})
	}
	return true
}
