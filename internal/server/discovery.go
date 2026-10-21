package server

import (
	"aegishook/internal/core"
	"aegishook/internal/core/discovery"
	"errors"
	"net/http"
)

func (s *Server) ingestDiscoveryReport(w http.ResponseWriter, r *http.Request) {
	node, ok := requestClient(r)
	if !ok || node.ID == "" || node.Revoked {
		fail(w, http.StatusForbidden, core.ErrDiscoveryClient)
		return
	}
	// Same report-body limit as read in server.go:65 (plan §9.2), independent
	// of the endpoint's config-file parsing resource budget.
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	report, err := discovery.DecodeReport(r.Body)
	if err != nil {
		var overflow *http.MaxBytesError
		switch {
		case errors.As(err, &overflow):
			fail(w, http.StatusRequestEntityTooLarge, errors.New("discovery report exceeds body limit"))
		case errors.Is(err, discovery.ErrDuplicateAsset):
			fail(w, http.StatusBadRequest, discovery.ErrDuplicateAsset)
		default:
			fail(w, http.StatusBadRequest, discovery.ErrInvalidReport)
		}
		return
	}
	err = s.Engine.IngestDiscoveryReport(r.Context(), node.ID, report)
	switch {
	case err == nil:
		write(w, map[string]bool{"ok": true})
	case errors.Is(err, core.ErrDiscoveryClient), errors.Is(err, core.ErrDiscoveryNodeMismatch):
		fail(w, http.StatusForbidden, err)
	case errors.Is(err, core.ErrStaleDiscoveryReport):
		fail(w, http.StatusConflict, err)
	case errors.Is(err, discovery.ErrInvalidReport), errors.Is(err, discovery.ErrDuplicateAsset):
		fail(w, http.StatusBadRequest, err)
	default:
		fail(w, http.StatusInternalServerError, errors.New("discovery report unavailable"))
	}
}
