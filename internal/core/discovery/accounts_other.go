//go:build !darwin && !linux && !windows

package discovery

import "context"

// S2a/S2b/S2c replace the supported-OS stubs; other platforms stay unsupported.
func enumerateLocalAccounts(ctx context.Context) ([]AccountHome, error) {
	return nil, ErrUnsupportedPlatform
}
