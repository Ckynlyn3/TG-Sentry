package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Port of the independent review's subprocess probe: exercise the actual matrix
// gate against isolated source, not a second inventory implementation.
func TestRouteMatrixGateRejectsUnlistedRegistrations(t *testing.T) {
	for _, tc := range []struct {
		name, registration, want string
	}{
		{"literal_control", `mux.HandleFunc("GET /api/v1/reviewer-unlisted", nil)`, "registered route absent from matrix: GET /api/v1/reviewer-unlisted"},
		{"computed_variable", `base := "/api/v1/reviewer-unlisted"; mux.HandleFunc("GET " + base, nil)`, "registered route absent from matrix: GET /api/v1/reviewer-unlisted"},
		{"constant_concatenation", `const base = "/api/v1/reviewer-unlisted"; mux.HandleFunc("GET " + base, nil)`, "registered route absent from matrix: GET /api/v1/reviewer-unlisted"},
		{"handle", `mux.Handle("GET /api/v1/reviewer-unlisted", nil)`, "registered route absent from matrix: GET /api/v1/reviewer-unlisted"},
		{"nested_ranges", `for _, base := range []string{"/api/v1/me", "/api/v1/reviewer-unlisted"} { for _, method := range []string{"GET"} { mux.HandleFunc(method + " " + base, nil) } }`, "registered route absent from matrix: GET /api/v1/reviewer-unlisted"},
		{"unresolvable", `mux.HandleFunc(pattern(), nil)`, "probe.go:6: unresolvable mux registration pattern"},
		{"unresolvable_handle", `mux.Handle(pattern(), nil)`, "probe.go:6: unresolvable mux registration pattern"},
		{"unresolvable_range", `for _, base := range paths() { mux.HandleFunc("GET " + base, nil) }`, "probe.go:6: unresolvable mux registration pattern"},
		{"address_taken", `base := "/api/v1/me"; ptr := &base; *ptr = "/api/v1/reviewer-unlisted"; mux.HandleFunc("GET " + base, nil)`, "probe.go:6: unresolvable mux registration pattern"},
		{"parenthesized_address_taken", `base := "/api/v1/me"; ptr := &(base); *ptr = "/api/v1/reviewer-unlisted"; mux.HandleFunc("GET " + base, nil)`, "probe.go:6: unresolvable mux registration pattern"},
		{"reassigned_variable", `base := "/api/v1/me"; base = pattern(); mux.HandleFunc("GET " + base, nil)`, "probe.go:6: unresolvable mux registration pattern"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runRouteMatrixFixture(t, tc.registration)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("matrix gate did not reject registration as expected: %v\n%s", err, out)
			}
		})
	}
}

func TestRouteMatrixGateResolvesListedRegistrations(t *testing.T) {
	out, err := runRouteMatrixFixture(t, `
	const prefix = "/api/v1/"
	base := prefix + "client-nodes/{id}/tags"
	mux.Handle("GET " + base, nil)
	for _, kind := range []string{"templates", "policies"} {
		base := prefix + kind
		mux.HandleFunc("GET " + base, nil)
		for _, suffix := range []string{"/review", "/{id}/review"} {
			mux.HandleFunc("POST " + base + suffix, nil)
		}
		for _, method := range []string{"PUT", "DELETE"} {
			mux.Handle(method + " " + base + "/{id}", nil)
		}
	}`)
	if err != nil {
		t.Fatalf("listed constant and loop registrations rejected: %v\n%s", err, out)
	}
}

func runRouteMatrixFixture(t *testing.T, registration string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	fixture := "package server\nimport \"net/http\"\nfunc pattern() string { return \"/runtime\" }\nfunc paths() []string { return nil }\nfunc routes(mux *http.ServeMux) { mux.HandleFunc(\"GET /api/v1/me\", nil)\n" + registration + "\n}\n"
	for name, content := range map[string]string{"go.mod": "module fixture\n\ngo 1.26.0\n", "probe.go": fixture} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestRouteMatrixCoversEveryRegisteredRoute$", "-test.v")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
