//go:build windows

package discovery

import (
	"context"
	"errors"
	"testing"
)

func TestIsEnumerableProfileSID(t *testing.T) {
	tests := []struct {
		name string
		sid  string
		want bool
	}{
		{"LocalSystem", "S-1-5-18", false},
		{"LocalService", "S-1-5-19", false},
		{"NetworkService", "S-1-5-20", false},
		{"service SID", "S-1-5-80-123-456-789-123-456", false},
		{"all services", "S-1-5-80-0", false},
		{"user", "S-1-5-21-123-456-789-1001", true},
		{"no RID floor", "S-1-5-21-123-456-789-500", true},
		{"backup", "S-1-5-21-123-456-789-1001.bak", false},
		{"uppercase backup", "S-1-5-21-123-456-789-1001.BAK", false},
		{"lowercase service", "s-1-5-18", false},
		{"lowercase service prefix", "s-1-5-80-123", false},
		{"lowercase user", "s-1-5-21-123-456-789-1001", true},
		{"service prefix boundary", "S-1-5-800-123", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEnumerableProfileSID(tt.sid); got != tt.want {
				t.Fatalf("enumerable = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccountHomeFromProfile(t *testing.T) {
	const sid = "s-1-5-21-123-456-789-1001"
	tests := []struct {
		home  string
		label string
	}{
		{`C:\Users\Élodie 東京`, "Élodie 東京"},
		{`D:\Profiles\old-name`, "old-name"},
		{`C:\Users\person\`, "person"},
	}
	for _, tt := range tests {
		want := AccountHome{ObservedLocalAccount: tt.label, AccountID: sid, HomePath: tt.home}
		if got := accountHomeFromProfile(sid, tt.home); got != want {
			t.Fatalf("account = %#v, want %#v", got, want)
		}
	}
}

func TestWindowsAccountEnumerationCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := enumerateLocalAccounts(ctx)
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled enumeration returned accounts=%#v, error=%v", got, err)
	}
}
