//go:build !darwin && !windows && !linux

package discovery

import (
	"context"
	"errors"
	"testing"
)

// On platforms with no account-enumeration implementation, EnumerateLocalAccounts
// reports ErrUnsupportedPlatform through the accounts_other.go fallback. The
// implemented platforms (darwin/linux/windows) assert real behaviour in their own
// build-tagged tests, so this stub assertion is scoped away from them.
func TestEnumerateLocalAccountsStubUnsupported(t *testing.T) {
	got, err := EnumerateLocalAccounts(context.Background())
	if !errors.Is(err, ErrUnsupportedPlatform) || got != nil {
		t.Fatalf("fallback returned accounts=%#v, error=%v", got, err)
	}
}
