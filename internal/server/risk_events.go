package server

import (
	"aegishook/internal/core"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
)

// Risk reads are deliberately not in hookAllowed: the existing admin session
// authenticates every page and detail request, independently of its cursor.
func (s *Server) riskEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size := int64(0)
	if q.Get("page_size") != "" {
		var err error
		size, err = strconv.ParseInt(q.Get("page_size"), 10, 32)
		if err != nil {
			fail(w, 400, core.ErrRiskEventQuery)
			return
		}
	}
	filter := core.RiskEventFilter{Severity: q.Get("severity"), Category: q.Get("category"), Agent: q.Get("agent")}
	for name, bound := range map[string]**int64{"from": &filter.From, "to": &filter.To} {
		if q.Has(name) {
			value, err := strconv.ParseInt(q.Get(name), 10, 64)
			if err != nil {
				fail(w, 400, core.ErrRiskEventQuery)
				return
			}
			*bound = &value
		}
	}
	page, err := s.Engine.RiskEvents(int(size), q.Get("page_token"), filter)
	if errors.Is(err, core.ErrRiskEventQuery) {
		fail(w, 400, err)
		return
	}
	if err != nil {
		fail(w, 500, errors.New("risk events unavailable"))
		return
	}
	write(w, page)
}
func (s *Server) riskEvent(w http.ResponseWriter, r *http.Request) {
	event, err := s.Engine.RiskEvent(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, errors.New("risk event not found"))
		return
	}
	if err != nil {
		fail(w, 500, errors.New("risk event unavailable"))
		return
	}
	write(w, event)
}
