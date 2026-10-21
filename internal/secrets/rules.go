package secrets

import "regexp"

// Frozen Gitleaks b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b (MIT).
// Pattern sources: https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml
// Each pattern cites its exact source line below; capture, widths, entropy and
// allowlists are unchanged. Detection is not credential validity verification.
// config/gitleaks.toml SHA-256 e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf.
// Only the approved nine IDs. Path/commit allowlists have no runtime-text target
// (plan exception secret-allowlist-no-path); all content checks are retained.
type rule struct {
	id          string
	regex       *regexp.Regexp
	secretGroup int
	entropy     float64
	keywords    []string
	allowlists  []allowlist
}

var rules = []rule{
	// config/gitleaks.toml:144
	{id: "anthropic-admin-api-key", regex: regexp.MustCompile(`\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy: 0, keywords: []string{"sk-ant-admin01"},
	},
	// config/gitleaks.toml:150
	{id: "anthropic-api-key", regex: regexp.MustCompile(`\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy: 0, keywords: []string{"sk-ant-api03"},
	},
	// config/gitleaks.toml:206
	{id: "aws-access-token", regex: regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`),
		entropy: 3.0, keywords: []string{"a3t", "akia", "asia", "abia", "acca"},
		allowlists: []allowlist{{regexes: []*regexp.Regexp{regexp.MustCompile(`.+EXAMPLE$`)}}},
	},
	// config/gitleaks.toml:2145
	{id: "github-fine-grained-pat", regex: regexp.MustCompile(`github_pat_\w{82}`),
		entropy: 3.0, keywords: []string{"github_pat_"},
	},
	// config/gitleaks.toml:2159
	{id: "github-pat", regex: regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		entropy: 3.0, keywords: []string{"ghp_"},
	},
	// config/gitleaks.toml:2226
	{id: "gitlab-pat", regex: regexp.MustCompile(`glpat-[\w-]{20}`),
		entropy: 3.0, keywords: []string{"glpat-"},
	},
	// config/gitleaks.toml:2424
	{id: "jwt", regex: regexp.MustCompile(`\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy: 3.0, keywords: []string{"ey"},
	},
	// config/gitleaks.toml:2704
	{id: "openai-api-key", regex: regexp.MustCompile(`\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy: 3.0, keywords: []string{"t3blbkfj"},
	},
	// config/gitleaks.toml:2785
	{id: "private-key", regex: regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`),
		entropy: 0, keywords: []string{"-----begin"},
	},
}
