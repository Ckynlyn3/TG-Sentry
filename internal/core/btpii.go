package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// TG-Java PresidioClient.java:64-69,148-175: NLE-1 measured 2000 UTF-16
// chunk units, RFC 5321 §4.5.3.1 254-address overlap; not arbitrary tuning.
const btpiiChunkUnits = 2000
const btpiiChunkOverlap = 254

// BTPII app/presidio_compat.py MAX_RESPONSE_BYTES and MAX_FINDINGS.
const btpiiResponseBytes = 2 * 1024 * 1024
const btpiiMaxFindings = 3000

// Named local exception btpii-hook-budget: reserve 500 ms from bridge.go's
// 2500 ms HTTP deadline. This bounds the WHOLE detection, not each chunk.
const btpiiBudget = 2 * time.Second

var btpiiUnavailable = errors.New("sensitive-info detector unavailable")
var btpiiBearer = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`) // RFC 6750 §2.1.
// Metadata identifier bound reuses policy.go's 64-byte custom-rule suffix.
var btpiiLabel = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// BTPIIConfig contains paths, never the workload bearer itself. Credentials are
// read at call time to allow rotation and never enter settings/audits/bundles.
type BTPIIConfig struct {
	Endpoint       string   `json:"endpoint,omitempty"`
	TokenFile      string   `json:"tokenFile,omitempty"`
	Language       string   `json:"language,omitempty"`
	Entities       []string `json:"entities,omitempty"`
	ScoreThreshold *float64 `json:"scoreThreshold,omitempty"`
}

func (c BTPIIConfig) resolved() BTPIIConfig {
	if c.Endpoint == "" {
		c.Endpoint = os.Getenv("TG_SENTRY_BTPII_ENDPOINT")
	}
	if c.TokenFile == "" {
		c.TokenFile = os.Getenv("TG_SENTRY_BTPII_TOKEN_FILE")
	}
	if c.Language == "" {
		c.Language = "en"
	}
	if c.Entities == nil {
		c.Entities = []string{"CREDIT_CARD", "EMAIL_ADDRESS", "IP_ADDRESS", "PHONE_NUMBER", "US_SSN"}
	}
	return c
}
func (c BTPIIConfig) validate() error {
	if c.Endpoint != "" {
		if ValidateModelURL(c.Endpoint) != nil {
			return btpiiUnavailable
		}
	}
	if !hasExact(c.Language, "", "en", "zh") {
		return btpiiUnavailable
	}
	if c.ScoreThreshold != nil && !(*c.ScoreThreshold >= 0 && *c.ScoreThreshold <= 1) {
		return btpiiUnavailable
	}
	for _, label := range c.Entities {
		if !btpiiLabel.MatchString(label) {
			return btpiiUnavailable
		}
	}
	return nil
}

type btpiiFinding struct {
	EntityType string   `json:"entity_type"`
	Start      *int     `json:"start"`
	End        *int     `json:"end"`
	Score      *float64 `json:"score"`
}

func (c BTPIIConfig) analyze(ctx context.Context, text, language string) ([]SensitiveFinding, error) {
	if ctx.Err() != nil {
		return nil, btpiiUnavailable
	}
	c = c.resolved()
	if c.validate() != nil || c.Endpoint == "" || c.TokenFile == "" || !hasExact(language, "en", "zh") || !utf8.ValidString(text) {
		return nil, btpiiUnavailable
	}
	file, err := os.Open(c.TokenFile)
	if err != nil {
		return nil, btpiiUnavailable
	}
	// Bound secret-file reads by the existing response-byte ceiling, not a new cap.
	secret, err := io.ReadAll(io.LimitReader(file, btpiiResponseBytes+1))
	closeErr := file.Close()
	token := strings.TrimSpace(string(secret))
	if err != nil || closeErr != nil || len(secret) > btpiiResponseBytes || !btpiiBearer.MatchString(token) {
		return nil, btpiiUnavailable
	}
	units := utf16.Encode([]rune(text))
	findings := []SensitiveFinding{}
	seen := map[struct {
		label      string
		start, end int
	}]int{}
	for start := 0; start < len(units); {
		end := min(start+btpiiChunkUnits, len(units))
		if end < len(units) && utf16.IsSurrogate(rune(units[end-1])) && units[end-1] >= 0xD800 && units[end-1] <= 0xDBFF {
			end--
		}
		chunk := string(utf16.Decode(units[start:end]))
		local, err := c.analyzeChunk(ctx, chunk, language, token)
		if err != nil {
			return nil, btpiiUnavailable
		}
		for _, f := range local {
			f.Span = &SensitiveSpan{StartUTF16: start + f.Span.StartUTF16, EndUTF16: start + f.Span.EndUTF16}
			key := struct {
				label      string
				start, end int
			}{f.EntityType, f.Span.StartUTF16, f.Span.EndUTF16}
			if i, ok := seen[key]; ok {
				if f.Score > findings[i].Score {
					findings[i] = f
				}
			} else {
				seen[key] = len(findings)
				findings = append(findings, f)
			}
		}
		if end == len(units) {
			break
		}
		start = end - btpiiChunkOverlap
		if units[start] >= 0xDC00 && units[start] <= 0xDFFF {
			start--
		}
	}
	if ctx.Err() != nil {
		return nil, btpiiUnavailable
	}
	return findings, nil
}
func (c BTPIIConfig) analyzeChunk(ctx context.Context, text, language, token string) ([]SensitiveFinding, error) {
	payload := struct {
		Text           string   `json:"text"`
		Language       string   `json:"language"`
		Entities       []string `json:"entities"`
		ScoreThreshold *float64 `json:"score_threshold,omitempty"`
	}{text, language, c.Entities, c.ScoreThreshold}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, btpiiUnavailable
	}
	endpoint := strings.TrimRight(c.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/analyze") {
		endpoint += "/analyze"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, btpiiUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return btpiiUnavailable }}
	response, err := client.Do(req)
	if err != nil {
		return nil, btpiiUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, btpiiUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, btpiiResponseBytes+1))
	if err != nil || len(data) > btpiiResponseBytes || !utf8.Valid(data) {
		return nil, btpiiUnavailable
	}
	var wire []btpiiFinding
	if json.Unmarshal(data, &wire) != nil || wire == nil || len(wire) > btpiiMaxFindings {
		return nil, btpiiUnavailable
	}
	findings := []SensitiveFinding{}
	offsets := utf16ByteOffsets(text)
	for _, f := range wire {
		if !btpiiLabel.MatchString(f.EntityType) || f.Start == nil || f.End == nil || f.Score == nil || !(*f.Score >= 0 && *f.Score <= 1) || !validSensitiveSpan(offsets, *f.Start, *f.End) {
			return nil, btpiiUnavailable
		}
		value := text[offsets[*f.Start]:offsets[*f.End]]
		tag := sensitiveTag(f.EntityType)
		requested := hasExact(f.EntityType, c.Entities...)
		if !requested {
			tag = "other"
		} // Retain upgrade labels; never silently lose a detection.
		if requested && f.EntityType == "CREDIT_CARD" && !ValidLuhn(strings.NewReplacer(" ", "", "-", "").Replace(value)) {
			continue
		}
		if requested && (f.EntityType == "CN_ID_CARD" || f.EntityType == "US_SSN" && len(value) == 18) && !ValidCNID(value) {
			continue
		}
		if c.ScoreThreshold != nil && *f.Score < *c.ScoreThreshold {
			continue
		}
		findings = append(findings, SensitiveFinding{Category: SensitiveInfoCategory, Tag: tag, EntityType: f.EntityType, Span: &SensitiveSpan{*f.Start, *f.End}, Score: *f.Score})
	}
	return findings, nil
}
func sensitiveTag(entity string) string {
	switch entity {
	case "CREDIT_CARD":
		return "bank-card"
	case "CN_ID_CARD", "US_SSN":
		return "id-number"
	case "EMAIL_ADDRESS":
		return "email"
	case "PHONE_NUMBER":
		return "mobile"
	default:
		return "other"
	}
}
