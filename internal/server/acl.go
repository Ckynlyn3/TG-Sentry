package server

import (
	"aegishook/internal/core"
	"database/sql"
	"net/http"
)

// ACL routes mirror protection.go: the same strict decoder, global revision,
// review binding, downgrade acknowledgement and audited core transaction apply.
func (s *Server) aclRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/acl", s.aclGet)
	mux.HandleFunc("GET /api/v1/acl/{id}", s.aclGet)
	mux.HandleFunc("POST /api/v1/acl/review", s.aclReview)
	mux.HandleFunc("POST /api/v1/acl/{id}/review", s.aclReview)
	mux.HandleFunc("POST /api/v1/acl", s.aclPublish)
	mux.HandleFunc("PUT /api/v1/acl/{id}", s.aclPublish)
	mux.HandleFunc("DELETE /api/v1/acl/{id}", s.aclPublish)
}

func (s *Server) aclGet(w http.ResponseWriter, r *http.Request) {
	state, err := s.Engine.Protection()
	if err != nil {
		protectionError(w, err)
		return
	}
	w.Header().Set("ETag", protectionETag(state.Revision))
	if id := r.PathValue("id"); id != "" {
		writeACLItem(w, state, id)
		return
	}
	rules := state.EffectiveACLRules()
	page, size, start, end, err := protectionPage(r, len(rules))
	if err != nil {
		protectionError(w, err)
		return
	}
	write(w, map[string]any{"revision": state.Revision, "virtualDefault": !state.ACL.Initialized, "items": append([]core.ACLRule{}, rules[start:end]...), "total": len(rules), "page": page, "pageSize": size})
}

func writeACLItem(w http.ResponseWriter, state core.ProtectionState, id string) {
	for _, rule := range state.EffectiveACLRules() {
		if rule.ID == id {
			write(w, map[string]any{"revision": state.Revision, "virtualDefault": !state.ACL.Initialized, "item": rule})
			return
		}
	}
	protectionError(w, sql.ErrNoRows)
}

func (s *Server) aclReview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Enabled     bool            `json:"enabled"`
		Subject     core.ACLSubject `json:"subject"`
		Effect      string          `json:"effect"`
		Target      core.ACLTarget  `json:"target"`
		Delete      bool            `json:"delete"`
	}
	if !readProtection(w, r, &in) {
		return
	}
	base, ok := s.protectionBase(w, r)
	if !ok {
		return
	}
	review, err := s.Engine.ReviewProtection(core.ProtectionChange{Kind: "acl", ID: r.PathValue("id"), Delete: in.Delete, ACL: &core.ACLRule{Name: in.Name, Description: in.Description, Enabled: in.Enabled, Subject: in.Subject, Effect: in.Effect, Target: in.Target}}, base)
	if err != nil {
		protectionError(w, err)
		return
	}
	w.Header().Set("ETag", protectionETag(review.BaseRevision))
	write(w, review)
}

func (s *Server) aclPublish(w http.ResponseWriter, r *http.Request) {
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
	state, err := s.Engine.ConfirmProtection(r.Context(), in.ReviewID, base, in.ConfirmDowngrade, "acl", r.PathValue("id"), r.Method == "DELETE")
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
		id = state.ACL.Rules[len(state.ACL.Rules)-1].ID
	}
	writeACLItem(w, state, id)
}
