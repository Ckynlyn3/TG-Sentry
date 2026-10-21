package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
)

const consoleCSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; script-src 'self'"

// Only discount the external module elements Vite emits. Other script markup
// conservatively counts as inline, so unexpected layouts receive no hash.
var consoleModuleScripts = regexp.MustCompile(`<script type="module" crossorigin src="[^"<>]+"></script>`)

// consoleContentSecurityPolicy authorizes only Vite's single theme initializer.
// ponytail: exact generated layout, not a general HTML parser; change this together
// with console/vite.config.ts if the emitter changes. CSP3 §2.3.1 hash-source:
// https://www.w3.org/TR/CSP3/#grammardef-hash-source
func consoleContentSecurityPolicy(index []byte) string {
	inline := bytes.ToLower(consoleModuleScripts.ReplaceAll(index, nil))
	if bytes.Count(inline, []byte("<script")) != 1 || bytes.Count(inline, []byte("</script>")) != 1 {
		return consoleCSP
	}
	_, tail, found := bytes.Cut(index, []byte(`<script id="theme-init">`))
	if !found {
		return consoleCSP
	}
	script, _, closed := bytes.Cut(tail, []byte(`</script>`))
	if !closed || bytes.ContainsRune(script, '\r') {
		// Build emission is LF-only. Reject a non-normalized asset rather than grant
		// a raw-byte hash that the browser's HTML preprocessing cannot match.
		return consoleCSP
	}
	// Hash the actual response bytes, including whitespace, never the tags.
	digest := sha256.Sum256(script)
	return consoleCSP + " 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
}
