package server

import (
	"errors"
	"net/http"
	"os"
	"strconv"
)

// Issue #65 plan §3.6: one public record per request, behind client middleware.
func (s *Server) clientKeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/client/keys/{version}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requestClient(r); !ok {
			fail(w, http.StatusForbidden, errors.New("trust record requires enrolled device credentials"))
			return
		}
		version, err := strconv.Atoi(r.PathValue("version"))
		if err != nil || version < 1 {
			fail(w, http.StatusBadRequest, errors.New("trust version must be a positive integer"))
			return
		}
		record, err := s.Engine.BundleTrustRecord(version)
		if errors.Is(err, os.ErrNotExist) {
			fail(w, http.StatusNotFound, errors.New("trust record not found"))
			return
		}
		if err != nil {
			fail(w, http.StatusServiceUnavailable, errors.New("trust record unavailable"))
			return
		}
		write(w, record)
	})
}
