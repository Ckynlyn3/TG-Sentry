package core

import (
	"context"
	"encoding/json"
	"strings"
)

// Pinned native /ner/text contract (PII services/pii-redaction
// app/schemas.py:138-163). Each submitted chunk yields exactly one response item
// in input order. location.stt_idx/end_idx are original-text CODE-POINT offsets
// (exclusive end) and likelihood is the detector score rounded to four decimals,
// not a calibrated probability. entities[].text and the item metadata
// (entities_present, characters_processed, languages_detected) are ignored, not
// copied into any durable DTO.
type btpiiNativeRequest struct {
	Text            []string                    `json:"text"`
	EntityDetection *btpiiNativeEntityDetection `json:"entity_detection,omitempty"`
}
type btpiiNativeEntityDetection struct {
	EntityTypes []btpiiNativeSelector `json:"entity_types"`
}
type btpiiNativeSelector struct {
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

// analyzeNativeChunk sends one chunk as a single-element text array and returns
// findings whose spans are chunk-local UTF-16 offsets, ready for the shared
// chunk rebasing in analyze. The chunk's raw text is never retained.
func (c BTPIIConfig) analyzeNativeChunk(ctx context.Context, text, token string) ([]SensitiveFinding, error) {
	payload := btpiiNativeRequest{Text: []string{text}}
	// Selectors are omitted by default so the service applies its documented
	// default label set. An explicit list becomes one ENABLE selector.
	if len(c.Entities) > 0 {
		payload.EntityDetection = &btpiiNativeEntityDetection{EntityTypes: []btpiiNativeSelector{{Type: "ENABLE", Value: c.Entities}}}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, btpiiUnavailable
	}
	data, err := btpiiPost(ctx, btpiiEndpoint(c.Endpoint, "/ner/text"), body, token)
	if err != nil {
		return nil, btpiiUnavailable
	}
	// Reject duplicate member names and trailing JSON before decoding, so
	// encoding/json cannot silently merge a hostile response.
	if !validExactJSON(data) {
		return nil, btpiiUnavailable
	}
	// Consumed members are then read by EXACT member name: encoding/json matches
	// struct fields case-insensitively, so a case-variant alias could otherwise
	// satisfy a required member, override its value or erase findings
	// (Go src/encoding/json, Unmarshal). Unconsumed members stay ignored.
	var items []map[string]json.RawMessage
	if json.Unmarshal(data, &items) != nil || len(items) != 1 {
		return nil, btpiiUnavailable
	}
	var entities []map[string]json.RawMessage
	if json.Unmarshal(items[0]["entities"], &entities) != nil || entities == nil || len(entities) > btpiiMaxFindings {
		return nil, btpiiUnavailable
	}
	// Code-point boundary -> UTF-16 boundary for this chunk; the existing span
	// validation, deduplication and redaction then apply unchanged.
	points := codePointUTF16Offsets(text)
	positions := utf16ByteOffsets(text)
	findings := []SensitiveFinding{}
	for _, entity := range entities {
		label, from, to, score, ok := readNativeEntity(entity)
		if !ok || !btpiiLabel.MatchString(label) || !(score >= 0 && score <= 1) || !validSensitiveSpan(points, from, to) {
			return nil, btpiiUnavailable
		}
		start, end := points[from], points[to]
		// Existing checksum behaviour, applied where the native label carries one.
		// Native SSN stays distinct from compat US_SSN: no China-specific rule.
		if label == "CREDIT_CARD" && !ValidLuhn(strings.NewReplacer(" ", "", "-", "").Replace(text[positions[start]:positions[end]])) {
			continue
		}
		if label == "CN_ID_CARD" && !ValidCNID(text[positions[start]:positions[end]]) {
			continue
		}
		// No global likelihood cutoff: the service filters. An explicitly
		// configured threshold stays a client-side filter.
		if c.ScoreThreshold != nil && score < *c.ScoreThreshold {
			continue
		}
		findings = append(findings, SensitiveFinding{Category: SensitiveInfoCategory, Tag: sensitiveTag(label), EntityType: label, Span: &SensitiveSpan{start, end}, Score: score})
	}
	return findings, nil
}

// readNativeEntity reads the consumed members of one entity object by exact member
// name. It reports false when a consumed member is absent, null, or not of the
// declared JSON type; an absent member fails exactly like a null one, because
// Unmarshal rejects a nil RawMessage.
func readNativeEntity(raw map[string]json.RawMessage) (label string, from, to int, score float64, ok bool) {
	var start, end *int
	var likelihood *float64
	if json.Unmarshal(raw["label"], &label) != nil || json.Unmarshal(raw["likelihood"], &likelihood) != nil || likelihood == nil {
		return "", 0, 0, 0, false
	}
	var location map[string]json.RawMessage
	if json.Unmarshal(raw["location"], &location) != nil || location == nil ||
		json.Unmarshal(location["stt_idx"], &start) != nil || start == nil ||
		json.Unmarshal(location["end_idx"], &end) != nil || end == nil {
		return "", 0, 0, 0, false
	}
	return label, *start, *end, *likelihood, true
}

// codePointUTF16Offsets maps each code-point boundary of text to its UTF-16
// boundary. Index i is the unit offset of the i-th rune and the final entry is
// the total unit count; BMP runes add one unit, supplementary runes two.
func codePointUTF16Offsets(text string) []int {
	offsets := []int{0}
	for _, r := range text {
		step := 1
		if r > 0xFFFF {
			step = 2
		}
		offsets = append(offsets, offsets[len(offsets)-1]+step)
	}
	return offsets
}
