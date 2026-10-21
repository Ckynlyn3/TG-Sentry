package discovery

import (
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeAccounts(t *testing.T) {
	first := AccountHome{"person-one", "10", accountTestHome("Person One")}
	second := AccountHome{"person-two", "2", accountTestHome("Élodie 東京")}
	upper := AccountHome{"person-upper", "A", accountTestHome("Upper")}
	lower := AccountHome{"person-lower", "a", accountTestHome("Lower")}
	tests := []struct {
		name string
		raw  []AccountHome
		want []AccountHome
	}{
		{"nil input", nil, nil},
		{"empty input", []AccountHome{}, nil},
		{"spaces and Unicode preserved", []AccountHome{second, first}, []AccountHome{first, second}},
		{"exact duplicates collapse", []AccountHome{second, first, second, first}, []AccountHome{first, second}},
		{"byte order not numeric or case folded", []AccountHome{lower, second, upper, first}, []AccountHome{first, second, upper, lower}},
		{"already sorted", []AccountHome{first, second}, []AccountHome{first, second}},
		{"observed label is not required", []AccountHome{{"", "501", accountTestHome("Unlabelled")}}, []AccountHome{{"", "501", accountTestHome("Unlabelled")}}},
		{"path spelling is not cleaned", []AccountHome{{"person", "501", accountTestHome("Person") + string(filepath.Separator) + "."}}, []AccountHome{{"person", "501", accountTestHome("Person") + string(filepath.Separator) + "."}}},
	}
	if runtime.GOOS != "windows" {
		literal := AccountHome{"person", "501", `/Users/private\name`}
		tests = append(tests, struct {
			name string
			raw  []AccountHome
			want []AccountHome
		}{"POSIX literal backslash preserved", []AccountHome{literal}, []AccountHome{literal}})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := slices.Clone(tt.raw)
			got, err := normalizeAccounts(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("accounts = %#v, want %#v", got, tt.want)
			}
			if !slices.Equal(tt.raw, before) {
				t.Fatal("normalization modified input")
			}
			if len(got) > 0 {
				got[0].HomePath = "changed-output"
				if !slices.Equal(tt.raw, before) {
					t.Fatal("output aliases input")
				}
			}
		})
	}
}

func TestNormalizeAccountsRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name string
		id   string
		home string
	}{
		{"empty ID", "", accountTestHome("private-home")},
		{"empty home", "private-id", ""},
		{"NUL ID", "private-id\x00", accountTestHome("private-home")},
		{"NUL home", "private-id", accountTestHome("private-home") + "\x00"},
		{"invalid UTF-8 ID", "private-id\xff", accountTestHome("private-home")},
		{"invalid UTF-8 home", "private-id", accountTestHome("private-home") + "\xff"},
		{"control ID", "private-id\t", accountTestHome("private-home")},
		{"control home", "private-id", accountTestHome("private-home") + "\n"},
		{"DEL ID", "private-id\x7f", accountTestHome("private-home")},
		{"DEL home", "private-id", accountTestHome("private-home") + "\x7f"},
		{"relative home", "private-id", "private-relative-home"},
		{"dot relative home", "private-id", "./private-home"},
		{"parent relative home", "private-id", "../private-home"},
		{"Unix root", "private-id", "/"},
		{"Windows root", "private-id", `C:\`},
		{"bare drive", "private-id", "C:"},
		{"drive relative home", "private-id", `C:private-home`},
		{"current drive root", "private-id", `\`},
		{"native root", "private-id", filepath.VolumeName(accountTestHome("private-home")) + string(filepath.Separator)},
		{"cleaned native root", "private-id", accountTestHome("private-home") + string(filepath.Separator) + ".."},
	}
	if runtime.GOOS == "windows" {
		tests = append(tests,
			struct{ name, id, home string }{"UNC volume", "private-id", `\\server\share`},
			struct{ name, id, home string }{"UNC root", "private-id", `\\server\share\`},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A valid preceding account must never escape as partial success.
			raw := []AccountHome{{"safe-label", "safe-id", accountTestHome("safe-home")}, {"private-label", tt.id, tt.home}}
			got, err := normalizeAccounts(raw)
			if err == nil || got != nil {
				t.Fatalf("invalid input returned accounts=%#v, error=%v", got, err)
			}
			assertAccountError(t, err, "discovery: invalid local account", raw)
		})
	}
}

func TestNormalizeAccountsRejectsConflictingIDs(t *testing.T) {
	original := AccountHome{"private-label", "private-id", accountTestHome("private-home")}
	tests := []struct {
		name  string
		other AccountHome
	}{
		{"label differs", AccountHome{"other-private-label", original.AccountID, original.HomePath}},
		{"home differs", AccountHome{original.ObservedLocalAccount, original.AccountID, accountTestHome("other-private-home")}},
		{"both differ", AccountHome{"other-private-label", original.AccountID, accountTestHome("other-private-home")}},
		{"lexically equivalent home differs", AccountHome{original.ObservedLocalAccount, original.AccountID, original.HomePath + string(filepath.Separator) + "."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, raw := range [][]AccountHome{{original, tt.other}, {tt.other, original}} {
				got, err := normalizeAccounts(raw)
				if err == nil || got != nil {
					t.Fatalf("conflict returned accounts=%#v, error=%v", got, err)
				}
				assertAccountError(t, err, "discovery: conflicting local account records", raw)
			}
		})
	}
}

func accountTestHome(name string) string {
	// Native absolute fixtures only; no candidate directories are created/opened.
	if runtime.GOOS == "windows" {
		return `C:\` + name
	}
	return "/" + name
}

func assertAccountError(t *testing.T, err error, want string, raw []AccountHome) {
	t.Helper()
	if err.Error() != want {
		t.Fatalf("error is not the static message %q", want)
	}
	for _, account := range raw {
		for _, value := range []string{account.ObservedLocalAccount, account.AccountID, account.HomePath} {
			if value != "" && strings.Contains(err.Error(), value) {
				t.Fatal("error contains an injected field")
			}
		}
	}
}
