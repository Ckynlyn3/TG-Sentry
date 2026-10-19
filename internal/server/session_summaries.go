package server

import (
	"aegishook/internal/core"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

func sessionSummaryParams(q url.Values) (int, int, core.SessionSummaryFilter, error) {
	page, size := 1, 20 // Plan LD9: existing /calls defaults and ceiling.
	for key, target := range map[string]*int{"page": &page, "size": &size} {
		if q.Has(key) {
			value, err := strconv.Atoi(q.Get(key))
			if err != nil || value < 1 {
				return 0, 0, core.SessionSummaryFilter{}, core.ErrSessionSummaryQuery
			}
			*target = value
		}
	}
	if size > 100 {
		return 0, 0, core.SessionSummaryFilter{}, core.ErrSessionSummaryQuery
	}
	return page, size, core.SessionSummaryFilter{Agent: q.Get("agent"), NodeID: q.Get("nodeId"), SessionKey: q.Get("sessionKey"), From: q.Get("from"), To: q.Get("to")}, nil
}

func (s *Server) sessionSummaries(w http.ResponseWriter, r *http.Request) {
	page, size, filter, err := sessionSummaryParams(r.URL.Query())
	if err != nil {
		fail(w, 400, err)
		return
	}
	result, err := s.Engine.SessionSummaries(page, size, filter)
	if errors.Is(err, core.ErrSessionSummaryQuery) {
		fail(w, 400, err)
		return
	}
	if err != nil {
		fail(w, 500, errors.New("session summaries unavailable"))
		return
	}
	// This fixed projection contains no content for either capability value.
	// /calls owns the per-request contentAllowed projection (plan A2 / LD4).
	write(w, result)
}
