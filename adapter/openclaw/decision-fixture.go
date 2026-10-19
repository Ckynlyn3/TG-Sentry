// Local integration fixture: real TG-Sentry HTTP handler and decision engine,
// synthetic bearer values only. Started by gateway.test.mjs; never production.
package main

import (
	"aegishook/internal/core"
	"aegishook/internal/server"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"testing/fstest"
)

func main() {
	e, err := core.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()
	for _, r := range []core.Rule{
		{ID: "U_openclaw_deny", Name: "fixture deny marker", Enabled: true, Decision: "reject", Target: "arguments", Field: "command", Matcher: "contains", Pattern: "DENIED_MARKER", Message: "fixture denies exec", Priority: 100},
		{ID: "U_openclaw_allow", Name: "fixture benign marker", Enabled: true, Decision: "approve", Target: "arguments", Field: "command", Matcher: "contains", Pattern: "BENIGN_MARKER", Message: "fixture permits benign exec", Priority: 100},
	} {
		if err := e.SaveRule(core.WithActor(context.Background(), core.SystemActor("openclaw-fixture")), r); err != nil {
			log.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{"endpoint": "http://" + listener.Addr().String()})
	log.Fatal(http.Serve(listener, server.New(e, fstest.MapFS{}, "fixture-admin-not-secret", "fixture-hook-not-secret", os.Args[1]).Handler()))
}
