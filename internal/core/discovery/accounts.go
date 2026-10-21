package discovery

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
)

// AccountHome is a local intermediate observation, not a wire schema.
// Only OpenHome establishes whether the enumerated home can be accessed.
type AccountHome struct {
	ObservedLocalAccount string
	AccountID            string
	HomePath             string
}

var ErrUnsupportedPlatform = errors.New("discovery: account enumeration unsupported on this platform")

// EnumerateLocalAccounts returns validated, distinct accounts in AccountID order.
func EnumerateLocalAccounts(ctx context.Context) ([]AccountHome, error) {
	raw, err := enumerateLocalAccounts(ctx)
	if err != nil {
		return nil, err
	}
	return normalizeAccounts(raw)
}

func normalizeAccounts(raw []AccountHome) ([]AccountHome, error) {
	byID := make(map[string]AccountHome, len(raw))
	accounts := make([]AccountHome, 0, len(raw))
	for _, account := range raw {
		if !validAccountField(account.AccountID) || !validAccountField(account.HomePath) || !validAccountHome(account.HomePath) {
			return nil, errors.New("discovery: invalid local account")
		}
		if previous, exists := byID[account.AccountID]; exists {
			if previous != account {
				return nil, errors.New("discovery: conflicting local account records")
			}
			continue
		}
		byID[account.AccountID] = account
		accounts = append(accounts, account)
	}
	// Go string comparison is lexicographic byte order (go.dev/ref/spec).
	slices.SortFunc(accounts, func(a, b AccountHome) int { return strings.Compare(a.AccountID, b.AccountID) })
	return accounts, nil
}

func validAccountField(value string) bool {
	// Reject ASCII controls, not UTF-8 continuation bytes (RFC 20 §2).
	return value != "" && validStrings(value) && !strings.ContainsFunc(value, func(r rune) bool {
		return r < ' ' || r == '\x7f'
	})
}

func validAccountHome(home string) bool {
	if !filepath.IsAbs(home) {
		return false
	}
	// Native lexical rules only: pkg.go.dev/path/filepath#Clean and #VolumeName.
	// Clean is used to detect roots, never to rewrite the observed path or stat it.
	clean := filepath.Clean(home)
	rest := clean[len(filepath.VolumeName(clean)):]
	return rest != "" && rest != string(filepath.Separator)
}
