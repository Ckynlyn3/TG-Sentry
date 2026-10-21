package server

import (
	"context"
	"io"
	"net/http"
	"time"
)

// Kubernetes API health endpoints separate process liveness from traffic readiness:
// https://kubernetes.io/docs/reference/using-api/health-checks/#api-endpoints-for-health
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	status, body := http.StatusOK, "ok"
	if r.URL.Path == "/readyz" {
		// Reuse the store connectivity budget in core/store_connection_test.go
		// (itself the SQLite busy_timeout in core/store_database.go).
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if s.Engine.DB.PingContext(ctx) != nil {
			status, body = http.StatusServiceUnavailable, "not ready"
		}
	}
	// OWASP Error Handling Cheat Sheet: expose no dependency or error details.
	// https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		io.WriteString(w, body)
	}
}
