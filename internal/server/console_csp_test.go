package server

import (
	"aegishook/internal/assets"
	"aegishook/internal/core"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestConsoleCSPHashMatchesServedInlineScript(t *testing.T) {
	ui := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<script id="theme-init">
  document.documentElement.dataset.theme = "dark";
</script><script type="module" crossorigin src="/assets/app.js"></script>`)}}
	h := New(&core.Engine{}, ui, "", "", "").Handler()
	for _, path := range []string{"/", "/login", "/index.html"} {
		t.Run(path, func(t *testing.T) { assertConsoleCSP(t, h, path) })
	}
	// A filesystem-backed console may change after Handler construction. The hash must
	// still describe the response bytes, not a stale startup snapshot.
	ui["index.html"] = &fstest.MapFile{Data: []byte(`<script id="theme-init">document.documentElement.dataset.theme = "light";</script>`)}
	assertConsoleCSP(t, h, "/login")
}

func assertConsoleCSP(t *testing.T, h http.Handler, path string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18790"+path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("console status=%d body=%s", w.Code, w.Body.String())
	}
	// Independently extract the served element; CSP3 hashes only its exact text,
	// including leading/trailing whitespace, never the script tags (MDN script-src).
	matches := regexp.MustCompile(`(?s)<script id="theme-init">(.*?)</script>`).FindAllStringSubmatch(w.Body.String(), -1)
	if len(matches) != 1 {
		t.Fatalf("expected one inline theme initializer, found %d", len(matches))
	}
	digest := sha256.Sum256([]byte(matches[0][1]))
	want := "script-src 'self' 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	var got string
	for _, directive := range strings.Split(w.Header().Get("Content-Security-Policy"), ";") {
		if strings.HasPrefix(strings.TrimSpace(directive), "script-src ") {
			got = strings.TrimSpace(directive)
		}
	}
	if got != want {
		t.Fatalf("served script CSP=%q, exact served bytes require %q", got, want)
	}
	if strings.Contains(w.Body.String(), `src="/theme-init.js"`) {
		t.Fatal("console still requests the render-blocking theme asset")
	}
}

func TestEmbeddedConsoleCSPHashMatchesServedInlineScript(t *testing.T) {
	ui, err := fs.Sub(assets.Files, "ui")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(ui, "index.html"); err != nil {
		// Native Go-only jobs embed a placeholder. Console-enabled builds must run
		// prepare-assets before this test, as build:console:linux does in CI.
		t.Skip("console not built; fixture CSP consistency test still runs")
	}
	assertConsoleCSP(t, New(&core.Engine{}, ui, "", "", "").Handler(), "/login")
}

func TestConsoleCSPDoesNotAuthorizeOtherInlineScripts(t *testing.T) {
	for _, tc := range []struct{ name, html string }{
		{"no scripts", "app"},
		{"unnamed initializer", `<script>window.unapproved = true;</script>`},
		{"external initializer", `<script id="theme-init" src="/theme-init.js"></script>`},
		{"missing closing tag", `<script id="theme-init">missing closing tag`},
		{"extra unnamed inline", `<script id="theme-init">theme();</script><script>other();</script>`},
		{"duplicate initializers", `<script id="theme-init">theme();</script><script id="theme-init">theme();</script>`},
		{"uppercase extra inline", `<script id="theme-init">theme();</script><SCRIPT>other();</SCRIPT>`},
		{"non-normalized line endings", "<script id=\"theme-init\">\r\ntheme();\r</script>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ui := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(tc.html)}}
			w := httptest.NewRecorder()
			New(&core.Engine{}, ui, "", "", "").Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18790/", nil))
			var got string
			for _, directive := range strings.Split(w.Header().Get("Content-Security-Policy"), ";") {
				if strings.HasPrefix(strings.TrimSpace(directive), "script-src ") {
					got = strings.TrimSpace(directive)
				}
			}
			if got != "script-src 'self'" {
				t.Fatalf("unauthorized inline script source: %q", got)
			}
		})
	}
}
