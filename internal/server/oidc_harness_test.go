package server

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"aegishook/internal/core"
	"aegishook/internal/teststore"
)

// The external fixtures use this same redirect chain, without POST /api/v1/login.
func TestOIDCHeadlessBoundAdminSession(t *testing.T) {
	s, p, _ := oidcFixture(t)
	p.Claims["roles"] = []string{"unknown"} // Admission must come from the local binding.
	e, err := core.Open(teststore.Dir(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	s.Engine = e
	host := httptest.NewUnstartedServer(nil)
	s.ListenAddr = host.Listener.Addr().String()
	t.Setenv("TG_SENTRY_OIDC_REDIRECT_URL", "http://"+s.ListenAddr+"/api/v1/auth/callback")
	host.Config.Handler = s.Handler()
	host.Start()
	t.Cleanup(host.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	login := func(want int) {
		t.Helper()
		res, err := client.Get(host.URL + "/api/v1/auth/login?next=%2Fapi%2Fv1%2Fme")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("headless code flow: status=%d want=%d url=%s", res.StatusCode, want, res.Request.URL)
		}
		if want != http.StatusOK {
			return
		}
		var me struct{ Kind, Role, Subject, Name string }
		if err := json.NewDecoder(res.Body).Decode(&me); err != nil {
			t.Fatal(err)
		}
		if me.Kind != "human" || me.Role != "admin" || me.Subject != "subject" || me.Name != "Display Name" {
			t.Fatalf("not a bound human admin: %+v", me)
		}
	}
	login(http.StatusForbidden)
	if err := e.BindAdmin(core.Principal{Issuer: p.URL, Subject: "subject"}, "fixture"); err != nil {
		t.Fatal(err)
	}
	login(http.StatusOK)
	res, err := client.Get(host.URL + "/api/v1/client-enrollments")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("management cookie rejected: %d", res.StatusCode)
	}
}
