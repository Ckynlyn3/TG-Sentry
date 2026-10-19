package secrets

import (
	"regexp"
	"strings"
)

// Gitleaks b58d3f10 config/allowlist.go:33–57,148–177 and
// detect/detect.go:823–906: regex targets secret by default; stopwords always
// target the extracted secret; content criteria combine using OR or AND.
// Paths/commits are omitted under secret-allowlist-no-path (plan §9).
type allowlist struct {
	regexTarget string
	condition   string
	regexes     []*regexp.Regexp
	stopwords   []string
}

func allowed(lists []allowlist, text string, start, end int, secret string) bool {
	for _, a := range lists {
		target := secret
		switch a.regexTarget {
		case "match":
			target = text[start:end]
		case "line":
			first := strings.LastIndexByte(text[:start], '\n') + 1
			last := len(text)
			if i := strings.IndexByte(text[end:], '\n'); i >= 0 {
				last = end + i
			}
			target = text[first:last]
		}
		regexOK := false
		for _, re := range a.regexes {
			regexOK = regexOK || target != "" && re.MatchString(target)
		}
		wordOK := false
		for _, word := range a.stopwords {
			wordOK = wordOK || secret != "" && strings.Contains(strings.ToLower(secret), strings.ToLower(word))
		}
		if a.condition == "AND" {
			if (len(a.regexes) > 0 || len(a.stopwords) > 0) && (len(a.regexes) == 0 || regexOK) && (len(a.stopwords) == 0 || wordOK) {
				return true
			}
		} else if regexOK || wordOK {
			return true
		}
	}
	return false
}

// Exact global content allowlist: config/gitleaks.toml:51–71 at b58d3f10.
// RegexTarget and condition are absent upstream, hence default secret / OR.
var globalAllowlists = []allowlist{{
	regexes: []*regexp.Regexp{
		regexp.MustCompile(`(?i)^true|false|null$`),
		regexp.MustCompile(`^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\*+|\.+)$`),
		regexp.MustCompile(`^\$(?:\d+|{\d+})$`),
		regexp.MustCompile(`^\$(?:[A-Z_]+|[a-z_]+)$`),
		regexp.MustCompile(`^\${(?:[A-Z_]+|[a-z_]+)}$`),
		regexp.MustCompile(`^\{\{[ \t]*[\w ().|]+[ \t]*}}$`),
		regexp.MustCompile(`^\$\{\{[ \t]*(?:(?:env|github|secrets|vars)(?:\.[A-Za-z]\w+)+[\w "'&./=|]*)[ \t]*}}$`),
		regexp.MustCompile(`^%(?:[A-Z_]+|[a-z_]+)%$`),
		regexp.MustCompile(`^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$`),
		regexp.MustCompile(`^\{\d{0,2}}$`),
		regexp.MustCompile(`^@(?:[A-Z_]+|[a-z_]+)@$`),
		regexp.MustCompile(`^/Users/(?i)[a-z0-9]+/[\w .-/]+$`),
		regexp.MustCompile(`^/(?:bin|etc|home|opt|tmp|usr|var)/[\w ./-]+$`),
	},
	stopwords: []string{"014df517-39d1-4453-b7b3-9930c563627c", "abcdefghijklmnopqrstuvwxyz"},
}}
