package server

import (
	"aegishook/internal/core"
	"errors"
	"net/http"
)

func (s *Server) riskStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	window := q.Get("window")
	if window == "" {
		window = "7d"
	}
	stats, err := s.Engine.RiskStats(r.Context(), core.RiskEventFilter{Severity: q.Get("severity"), Category: q.Get("category"), Agent: q.Get("agent")}, window)
	if errors.Is(err, core.ErrRiskEventQuery) {
		fail(w, 400, core.ErrRiskEventQuery)
		return
	}
	if err != nil {
		fail(w, 500, errors.New("risk stats unavailable"))
		return
	}
	write(w, stats)
}
