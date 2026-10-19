package server

import "testing"

func TestNextRejectsTabNewlineBackslashDoubleSlash(t *testing.T) {
	for _, target := range []string{"/\t/attacker.invalid", "/\n/attacker.invalid", `/\attacker`, "//attacker.invalid", "https://attacker.invalid/", "http://console.example/", "relative", "", "/\x00evil", "/\x1fevil", "/\x7fevil", "///attacker.invalid", "//user@console.example/"} {
		t.Run(target, func(t *testing.T) {
			if got := safeNext(target, "https://console.example"); got != "/" {
				t.Fatalf("unsafe next accepted: %q", got)
			}
		})
	}
}

func TestNextAcceptsSameOriginPath(t *testing.T) {
	for _, target := range []string{"/", "/calls", "/calls?page=2#review", "/settings/profile", "/%E4%B8%AD"} {
		if got := safeNext(target, "https://console.example"); got != target {
			t.Fatalf("next %q became %q", target, got)
		}
	}
	if got := safeNext("/calls", ":bad"); got != "/" {
		t.Fatal("invalid base accepted")
	}
}
