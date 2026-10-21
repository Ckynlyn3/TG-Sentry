package testoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFixtureRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{":0", "0.0.0.0:0", "localhost:0", "invalid"} {
		if p, err := Start(addr); err == nil {
			p.Close()
			t.Fatalf("accepted non-IP-loopback listen address %q", addr)
		}
	}
	p, err := Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/authorize?redirect_uri=https%3A%2F%2Foutside.example%2Fcallback", nil))
	if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatal("fixture redirected to an external origin")
	}
}
