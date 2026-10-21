// test-oidc is a test fixture — not shipped. It auto-approves synthetic loopback
// logins for CI only. Release builds target ./cmd/aegishook, never this command.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"aegishook/internal/testoidc"
)

func main() {
	port := flag.Int("port", 0, "loopback port (0 selects an available port)")
	subject := flag.String("subject", "subject", "synthetic subject")
	name := flag.String("name", "Display Name", "synthetic display name")
	email := flag.String("email", "fixture@example.test", "synthetic email")
	flag.Parse()
	p, err := testoidc.Start(net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()
	p.Claims["sub"], p.Claims["name"], p.Claims["email"] = *subject, *name, *email
	// External tests must exercise admin bind, not get admin from a role claim.
	delete(p.Claims, "roles")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	fmt.Printf("test OIDC ready %s\n", p.URL)
	<-stop
}
