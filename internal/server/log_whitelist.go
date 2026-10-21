package server

import (
	"aegishook/internal/core"
	"database/sql"
	"net/http"
)

// Log whitelist routes mirror the ACL resource: the same strict decoder, global revision,
// review binding, downgrade acknowledgement and audited core transaction apply.
func (s *Server) logWhitelistRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/log-whitelist", s.logWhitelistGet)
	mux.HandleFunc("GET /api/v1/log-whitelist/{id}", s.logWhitelistGet)
	mux.HandleFunc("POST /api/v1/log-whitelist/review", s.logWhitelistReview)
	mux.HandleFunc("POST /api/v1/log-whitelist/{id}/review", s.logWhitelistReview)
	mux.HandleFunc("POST /api/v1/log-whitelist", s.logWhitelistPublish)
	mux.HandleFunc("PUT /api/v1/log-whitelist/{id}", s.logWhitelistPublish)
	mux.HandleFunc("DELETE /api/v1/log-whitelist/{id}", s.logWhitelistPublish)
}

func (s *Server) logWhitelistGet(w http.ResponseWriter, r *http.Request) {
	state, err := s.Engine.Protection()
	if err != nil {
		protectionError(w, err)
		return
	}
	w.Header().Set("ETag", protectionETag(state.Revision))
	if id := r.PathValue("id"); id != "" {
		writeLogWhitelistItem(w, state, id)
		return
	}
	rules := state.LogWhitelist
	page, size, start, end, err := protectionPage(r, len(rules))
	if err != nil {
		protectionError(w, err)
		return
	}
	write(w, map[string]any{"revision": state.Revision, "items": append([]core.LogWhitelistEntry{}, rules[start:end]...), "total": len(rules), "page": page, "pageSize": size})
}

func writeLogWhitelistItem(w http.ResponseWriter, state core.ProtectionState, id string) {
	for _, rule := range state.LogWhitelist {
		if rule.ID == id {
			write(w, map[string]any{"revision": state.Revision, "item": rule})
			return
		}
	}
	protectionError(w, sql.ErrNoRows)
}

func (s *Server) logWhitelistReview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string                   `json:"name"`
		Description string                   `json:"description"`
		Enabled     bool                     `json:"enabled"`
		Subject     core.LogWhitelistSubject `json:"subject"`
		Delete      bool                     `json:"delete"`
	}
	if !readProtection(w, r, &in) {
		return
	}
	base, ok := s.protectionBase(w, r)
	if !ok {
		return
	}
	review, err := s.Engine.ReviewProtection(core.ProtectionChange{Kind: "log-whitelist", ID: r.PathValue("id"), Delete: in.Delete, LogWhitelist: &core.LogWhitelistEntry{Name: in.Name, Description: in.Description, Enabled: in.Enabled, Subject: in.Subject}}, base)
	if err != nil {
		protectionError(w, err)
		return
	}
	w.Header().Set("ETag", protectionETag(review.BaseRevision))
	write(w, review)
}

func (s *Server) logWhitelistPublish(w http.ResponseWriter, r *http.Request) {
	var in protectionConfirm
	if !readProtection(w, r, &in) {
		return
	}
	if in.ReviewID == "" {
		protectionError(w, core.ErrProtectionConflict)
		return
	}
	base, ok := s.protectionBase(w, r)
	if !ok {
		return
	}
	state, err := s.Engine.ConfirmProtection(r.Context(), in.ReviewID, base, in.ConfirmDowngrade, "log-whitelist", r.PathValue("id"), r.Method == "DELETE")
	if err != nil {
		protectionError(w, err)
		return
	}
	w.Header().Set("ETag", protectionETag(state.Revision))
	if r.Method == "DELETE" {
		write(w, map[string]any{"ok": true, "revision": state.Revision})
		return
	}
	id := r.PathValue("id")
	if id == "" {
		id = state.LogWhitelist[len(state.LogWhitelist)-1].ID
	}
	writeLogWhitelistItem(w, state, id)
}
