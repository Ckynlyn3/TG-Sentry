package secrets

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

// Fixture shapes/expectations follow Gitleaks at b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b,
// config/gitleaks.toml and cmd/generate/config/utils/validate.go. No upstream
// positive samples are used. Only recipes, not generated candidates, are stored.
type ruleFixture struct {
	RuleID    string   `json:"rule_id"`
	Regex     string   `json:"regex"`
	Entropy   float64  `json:"entropy"`
	Keywords  []string `json:"keywords"`
	Positives []string `json:"positives"`
	Negatives []string `json:"negatives"`
}

func loadFixtures(t *testing.T) []ruleFixture {
	t.Helper()
	paths, err := filepath.Glob("../../testdata/secrets/*.json")
	if err != nil || len(paths) != 9 { // Approved secret-rule-subset, plan §3.1.
		t.Fatal("expected the frozen nine-rule fixture corpus")
	}
	var fixtures []ruleFixture
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var fixture ruleFixture
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, fixture)
	}
	return fixtures
}

func syntheticText(alphabet string, n int) string {
	// Named local fixture seed: issue number 22; reproducible, never provisioned.
	rng := mathrand.New(mathrand.NewSource(22))
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(out)
}

func syntheticCandidate(t *testing.T, id, variant string) string {
	t.Helper()
	const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	const urlsafe = alnum + "_-"
	switch id {
	case "aws-access-token":
		prefix := "AKIA"
		if variant != "bare" && variant != "delimited" {
			prefix = variant
		}
		return prefix + syntheticText("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
	case "github-pat":
		return "ghp_" + syntheticText(alnum, 36)
	case "github-fine-grained-pat":
		return "github_pat_" + syntheticText(urlsafe[:len(urlsafe)-1], 82)
	case "gitlab-pat":
		return "glpat-" + syntheticText(urlsafe, 20)
	case "anthropic-api-key":
		return "sk-ant-api03-" + syntheticText(urlsafe, 93) + "AA"
	case "anthropic-admin-api-key":
		return "sk-ant-admin01-" + syntheticText(urlsafe, 93) + "AA"
	case "openai-api-key":
		if variant == "bare" || variant == "delimited" {
			return "sk-" + syntheticText(alnum, 20) + "T3BlbkFJ" + syntheticText(alnum, 20)
		}
		n := 58
		if strings.HasSuffix(variant, "74") {
			n = 74
		}
		prefix := strings.TrimSuffix(strings.TrimSuffix(variant, "58"), "74")
		return "sk-" + prefix + "-" + syntheticText(urlsafe, n) + "T3BlbkFJ" + syntheticText(urlsafe, n)
	case "jwt":
		return "ey" + syntheticText(alnum, 17) + ".ey" + syntheticText(alnum, 17) + "." + syntheticText(urlsafe, 10)
	case "private-key":
		// crypto/rsa's documented example uses 2048 bits. Disposable in-memory
		// material only: never written, provisioned, or used for authentication.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal("generate disposable RSA fixture")
		}
		return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	default:
		t.Fatal("unknown fixture rule ID")
		return ""
	}
}

func fixtureEntropy(s string) float64 {
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	for _, n := range counts {
		p := float64(n) / float64(len(s)) // All entropy fixtures use ASCII.
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func utf16Units(s string) int { return len(utf16.Encode([]rune(s))) }

func assertScan(t *testing.T, text string, want []Finding) {
	t.Helper()
	got, status := Scan(context.Background(), text)
	if status != Complete {
		t.Fatal("scan interrupted on an active context")
	}
	if len(got) != len(want) {
		t.Fatalf("finding count: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal("rule, entity type or UTF-16 span mismatch")
		}
	}
}

func TestFrozenRuleFixtures(t *testing.T) {
	wantIDs := strings.Fields("aws-access-token github-pat github-fine-grained-pat gitlab-pat openai-api-key anthropic-api-key anthropic-admin-api-key private-key jwt")
	seen := map[string]bool{}
	for _, f := range loadFixtures(t) {
		if seen[f.RuleID] || !slices.Contains(wantIDs, f.RuleID) {
			t.Fatal("fixture corpus changed the frozen rule IDs")
		}
		seen[f.RuleID] = true
		for _, variant := range f.Positives {
			t.Run(f.RuleID+"/"+variant, func(t *testing.T) {
				candidate := syntheticCandidate(t, f.RuleID, variant)
				re := regexp.MustCompile(f.Regex)
				if !re.MatchString(candidate) || f.Entropy != 0 && fixtureEntropy(candidate) <= f.Entropy {
					t.Fatal("synthetic recipe does not satisfy pinned regex/entropy")
				}
				keyword := false
				for _, k := range f.Keywords {
					keyword = keyword || strings.Contains(strings.ToLower(candidate), k)
				}
				if !keyword && len(f.Keywords) != 0 {
					t.Fatal("synthetic recipe does not satisfy pinned keyword OR")
				}
				prefix, suffix := "", ""
				if variant == "delimited" {
					prefix, suffix = "😀 source='", "'; done"
				}
				assertScan(t, prefix+candidate+suffix, []Finding{{RuleID: f.RuleID, EntityType: f.RuleID, Span: Span{Start: utf16Units(prefix), End: utf16Units(prefix + candidate)}}})
			})
		}
		for _, variant := range f.Negatives {
			t.Run(f.RuleID+"/"+variant, func(t *testing.T) {
				assertScan(t, negativeCandidate(t, f.RuleID, variant), nil)
			})
		}
	}
}

func TestSyntheticFixtureRecipes(t *testing.T) {
	for _, f := range loadFixtures(t) {
		re := regexp.MustCompile(f.Regex)
		for _, variant := range f.Positives {
			candidate := syntheticCandidate(t, f.RuleID, variant)
			if !re.MatchString(candidate) || f.Entropy != 0 && fixtureEntropy(candidate) <= f.Entropy {
				t.Fatalf("invalid positive recipe: %s/%s", f.RuleID, variant)
			}
		}
		for _, variant := range f.Negatives {
			candidate := negativeCandidate(t, f.RuleID, variant)
			if variant == "malformed" {
				if re.MatchString(candidate) {
					t.Fatalf("malformed recipe still matches: %s", f.RuleID)
				}
				continue
			}
			if !re.MatchString(candidate) || variant == "low-entropy" && fixtureEntropy(candidate) > f.Entropy {
				t.Fatalf("invalid rejection recipe: %s/%s", f.RuleID, variant)
			}
		}
	}
}

func negativeCandidate(t *testing.T, id, variant string) string {
	t.Helper()
	candidate := syntheticCandidate(t, id, "bare")
	switch variant {
	case "malformed":
		return "!" + candidate[1:]
	case "low-entropy":
		switch id {
		case "aws-access-token":
			return "AKIA" + strings.Repeat("Z", 16)
		case "github-pat":
			return "ghp_" + strings.Repeat("Z", 36)
		case "github-fine-grained-pat":
			return "github_pat_" + strings.Repeat("Z", 82)
		case "gitlab-pat":
			return "glpat-" + strings.Repeat("Z", 20)
		case "openai-api-key":
			return "sk-" + strings.Repeat("Z", 20) + "T3BlbkFJ" + strings.Repeat("Z", 20)
		case "jwt":
			return "ey" + strings.Repeat("Z", 17) + ".ey" + strings.Repeat("Z", 17) + "." + strings.Repeat("Z", 10)
		}
	case "global-stopword":
		return "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ" + syntheticText("0123456789", 10)
	case "global-uuid-stopword", "global-regex":
		word := "014DF517-39D1-4453-B7B3-9930C563627C"
		if variant == "global-regex" {
			word = "fAlSe"
		}
		return "sk-ant-api03-" + word + syntheticText("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 93-len(word)) + "AA"
	}
	t.Fatal("unsupported negative fixture recipe")
	return ""
}
