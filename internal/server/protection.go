package server

import (
	"aegishook/internal/core"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type protectionConfirm struct {
	ReviewID         string `json:"reviewId"`
	ConfirmDowngrade bool   `json:"confirmDowngrade"`
}

func readProtection(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // Existing server body ceiling.
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		fail(w, 400, errors.New("invalid protection JSON"))
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		fail(w, 400, errors.New("one JSON object required"))
		return false
	}
	return true
}
func protectionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrProtectionPrecondition):
		fail(w, 412, err)
	case errors.Is(err, core.ErrProtectionConflict):
		fail(w, 409, err)
	case errors.Is(err, core.ErrProtectionInvalid):
		fail(w, 400, err)
	case errors.Is(err, sql.ErrNoRows):
		fail(w, 404, errors.New("protection resource not found"))
	default:
		fail(w, 500, errors.New("protection store unavailable"))
	}
}
func protectionETag(revision int) string { return fmt.Sprintf(`"%d"`, revision) }

// RFC 9110 §8.8.3: entity-tag = [ "W/" ] DQUOTE *etagc DQUOTE.
// etagc is %x21 / %x23-7E / obs-text; backslash is literal, not an escape.
// See also Go's net/http/fs.go scanETag/checkIfMatch implementation.
func protectionEntityTag(value string) (string, string) {
	start := 0
	if strings.HasPrefix(value, "W/") {
		start = len("W/")
	}
	if len(value) <= start || value[start] != '"' {
		return "", value
	}
	end := strings.IndexByte(value[start+1:], '"')
	if end < 0 {
		return "", value
	}
	end += start + 1
	for i := start + 1; i < end; i++ {
		if value[i] < 0x21 || value[i] == 0x7f {
			return "", value
		}
	}
	return value[:end+1], value[end+1:]
}
func (s *Server) protectionBase(w http.ResponseWriter, r *http.Request) (int, bool) {
	// RFC 9110 §5.2 combines repeated field lines; §5.6.1 ignores empty list
	// members. Only SP/HTAB are optional whitespace, not arbitrary Unicode.
	value := strings.Trim(strings.Join(r.Header.Values("If-Match"), ","), " \t")
	if value == "" {
		fail(w, 428, errors.New("If-Match base revision required"))
		return 0, false
	}
	state, err := s.Engine.Protection()
	if err != nil {
		protectionError(w, err)
		return 0, false
	}
	matched := false
	for value != "" {
		value = strings.TrimLeft(value, " \t,")
		if value == "" {
			break
		}
		tag, rest := protectionEntityTag(value)
		if tag == "" {
			fail(w, 400, errors.New("an explicit entity-tag list is required; wildcard is unsupported"))
			return 0, false
		}
		// RFC 9110 §13.1.1 requires strong comparison: W/ tags never match.
		matched = matched || tag == protectionETag(state.Revision)
		value = strings.TrimLeft(rest, " \t")
		if value != "" && value[0] != ',' {
			fail(w, 400, errors.New("invalid entity-tag list separator"))
			return 0, false
		}
	}
	if !matched {
		protectionError(w, core.ErrProtectionPrecondition)
		return 0, false
	}
	// The engine rechecks this revision under its writer lock before mutation.
	return state.Revision, true
}
func (s *Server) protectionRoutes(mux *http.ServeMux) {
	for _, kind := range []string{"templates", "policies"} {
		base := "/api/v1/" + kind
		mux.HandleFunc("GET "+base, func(w http.ResponseWriter, r *http.Request) { s.protectionGet(w, r, kind, false) })
		mux.HandleFunc("GET "+base+"/{id}", func(w http.ResponseWriter, r *http.Request) { s.protectionGet(w, r, kind, true) })
		for _, suffix := range []string{"/review", "/{id}/review"} {
			mux.HandleFunc("POST "+base+suffix, func(w http.ResponseWriter, r *http.Request) { s.protectionReview(w, r, kind) })
		}
		mux.HandleFunc("POST "+base, func(w http.ResponseWriter, r *http.Request) { s.protectionPublish(w, r, kind) })
		for _, method := range []string{"PUT", "DELETE"} {
			mux.HandleFunc(method+" "+base+"/{id}", func(w http.ResponseWriter, r *http.Request) { s.protectionPublish(w, r, kind) })
		}
	}
	base := "/api/v1/client-nodes/{id}/tags"
	mux.HandleFunc("POST "+base+"/review", func(w http.ResponseWriter, r *http.Request) { s.protectionReview(w, r, "tags") })
	mux.HandleFunc("PUT "+base, func(w http.ResponseWriter, r *http.Request) { s.protectionPublish(w, r, "tags") })
	mux.HandleFunc("GET "+base, func(w http.ResponseWriter, r *http.Request) { s.protectionGet(w, r, "tags", true) })
}
func (s *Server) protectionReview(w http.ResponseWriter, r *http.Request, kind string) {
	c := core.ProtectionChange{Kind: kind, ID: r.PathValue("id")}
	switch kind {
	case "templates":
		var in struct {
			Name   string              `json:"name"`
			Rules  []core.TemplateRule `json:"rules"`
			Delete bool                `json:"delete"`
		}
		if !readProtection(w, r, &in) {
			return
		}
		c.Template = &core.ProtectionTemplate{Name: in.Name, Rules: in.Rules}
		c.Delete = in.Delete
	case "policies":
		var in struct {
			Name        string           `json:"name"`
			TemplateIDs []string         `json:"templateIds"`
			Scope       core.PolicyScope `json:"scope"`
			Delete      bool             `json:"delete"`
		}
		if !readProtection(w, r, &in) {
			return
		}
		c.Policy = &core.ProtectionPolicy{Name: in.Name, TemplateIDs: in.TemplateIDs, Scope: in.Scope}
		c.Delete = in.Delete
	case "tags":
		var in struct {
			Tags []string `json:"tags"`
		}
		if !readProtection(w, r, &in) {
			return
		}
		c.Tags = in.Tags
	}
	base, ok := s.protectionBase(w, r)
	if !ok {
		return
	}
	review, err := s.Engine.ReviewProtection(c, base)
	if err != nil {
		protectionError(w, err)
		return
	}
	w.Header().Set("ETag", protectionETag(review.BaseRevision))
	write(w, review)
}
func (s *Server) protectionPublish(w http.ResponseWriter, r *http.Request, kind string) {
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
	state, err := s.Engine.ConfirmProtection(r.Context(), in.ReviewID, base, in.ConfirmDowngrade, kind, r.PathValue("id"), r.Method == "DELETE")
	if err != nil {
		protectionError(w, err)
		return
	}
	w.Header().Set("ETag", protectionETag(state.Revision))
	if r.Method == "DELETE" {
		write(w, map[string]any{"ok": true, "revision": state.Revision})
		return
	}
	var reviewID string
	if id := r.PathValue("id"); id != "" {
		reviewID = id
	} else {
		// Creation appends exactly one resource to the reviewed aggregate.
		if kind == "templates" {
			reviewID = state.Templates[len(state.Templates)-1].ID
		} else {
			reviewID = state.Policies[len(state.Policies)-1].ID
		}
	}
	writeProtectionItem(w, state, kind, reviewID)
}
func writeProtectionItem(w http.ResponseWriter, state core.ProtectionState, kind, id string) {
	if kind == "tags" {
		write(w, map[string]any{"revision": state.Revision, "tags": append([]string{}, state.Tags[id]...)})
		return
	}
	var item any
	if kind == "templates" {
		for _, t := range state.Templates {
			if t.ID == id {
				item = t
				break
			}
		}
	} else {
		for _, p := range state.Policies {
			if p.ID == id {
				item = p
				break
			}
		}
	}
	if item == nil {
		protectionError(w, sql.ErrNoRows)
		return
	}
	write(w, map[string]any{"revision": state.Revision, "item": item})
}
func protectionPage(r *http.Request, total int) (int, int, int, int, error) {
	page, size := 1, 20 // Existing calls-page defaults and size ceiling.
	var err error
	if q := r.URL.Query().Get("page"); q != "" {
		page, err = strconv.Atoi(q)
		if err != nil || page < 1 {
			return 0, 0, 0, 0, core.ErrProtectionInvalid
		}
	}
	if q := r.URL.Query().Get("pageSize"); q != "" {
		size, err = strconv.Atoi(q)
		if err != nil || size < 1 || size > 100 {
			return 0, 0, 0, 0, core.ErrProtectionInvalid
		}
	}
	start := total
	if page <= total/size+1 {
		start = min((page-1)*size, total)
	}
	return page, size, start, min(start+size, total), nil
}
func (s *Server) protectionGet(w http.ResponseWriter, r *http.Request, kind string, detail bool) {
	state, err := s.Engine.Protection()
	if err != nil {
		protectionError(w, err)
		return
	}
	w.Header().Set("ETag", protectionETag(state.Revision))
	if detail {
		if kind == "tags" {
			nodes, err := s.Engine.ClientNodes()
			if err != nil {
				protectionError(w, err)
				return
			}
			found := false
			for _, node := range nodes {
				if node.ID == r.PathValue("id") {
					found = true
					break
				}
			}
			if !found {
				protectionError(w, sql.ErrNoRows)
				return
			}
		}
		writeProtectionItem(w, state, kind, r.PathValue("id"))
		return
	}
	total := len(state.Templates)
	if kind == "policies" {
		total = len(state.Policies)
	}
	page, size, start, end, err := protectionPage(r, total)
	if err != nil {
		protectionError(w, err)
		return
	}
	var items any
	if kind == "policies" {
		items = state.Policies[start:end]
	} else {
		items = state.Templates[start:end]
	}
	write(w, map[string]any{"revision": state.Revision, "items": items, "total": total, "page": page, "pageSize": size})
}
