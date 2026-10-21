package server

import (
	"aegishook/internal/core"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// #45: GitHub Actions metadata-only reads and writes; plaintext is available
// solely through the authenticated enrolled-device route, never a cookie.
func (s *Server) credentialRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.Engine.Credentials()
		if err != nil {
			credentialFailure(w, err)
			return
		}
		write(w, items)
	})
	mux.HandleFunc("GET /api/v1/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		c, err := s.Engine.Credential(r.PathValue("id"))
		if err != nil {
			credentialFailure(w, err)
			return
		}
		write(w, c)
	})
	mux.HandleFunc("POST /api/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name        string                   `json:"name"`
			Type        string                   `json:"type"`
			Env         string                   `json:"env"`
			Description string                   `json:"description"`
			Bindings    []core.CredentialBinding `json:"bindings"`
			Value       string                   `json:"value"`
		}
		if !readCredential(w, r, &input) {
			return
		}
		c, err := s.Engine.CreateCredential(r.Context(), core.Credential{Name: input.Name, Type: input.Type, Env: input.Env, Description: input.Description, Bindings: input.Bindings}, input.Value)
		if err != nil {
			credentialFailure(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		write(w, c)
	})
	mux.HandleFunc("PUT /api/v1/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Value string `json:"value"`
		}
		if !readCredential(w, r, &input) {
			return
		}
		c, err := s.Engine.RotateCredential(r.Context(), r.PathValue("id"), input.Value)
		if err != nil {
			credentialFailure(w, err)
			return
		}
		write(w, c)
	})
	mux.HandleFunc("DELETE /api/v1/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Engine.DeleteCredential(r.Context(), r.PathValue("id")); err != nil {
			credentialFailure(w, err)
			return
		}
		write(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/v1/client/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		node, ok := requestClient(r)
		if !ok {
			fail(w, http.StatusForbidden, core.ErrCredentialDenied)
			return
		}
		c, err := s.Engine.ResolveCredential(r.PathValue("id"), node.ID, r.URL.Query().Get("agent"))
		if err != nil {
			fail(w, http.StatusForbidden, core.ErrCredentialDenied)
			return
		}
		write(w, c)
	})
}
func credentialFailure(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, sql.ErrNoRows) {
		status = http.StatusNotFound
	}
	// Do not echo persistence, decoding or validation errors: arbitrary values
	// are not covered by RedactText's known-key patterns (#45 E6).
	fail(w, status, errors.New("credential request failed"))
}
func readCredential(w http.ResponseWriter, r *http.Request, out any) bool {
	// Reuse server.go's existing request-size ceiling, but reject unknown fields
	// and trailing JSON without reflecting any input in the error response.
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		credentialFailure(w, err)
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		credentialFailure(w, errors.New("trailing JSON"))
		return false
	}
	return true
}
func credentialHookAllowed(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	id, ok := strings.CutPrefix(r.URL.EscapedPath(), "/api/v1/client/credentials/")
	return ok && id != "" && !strings.ContainsAny(id, "/%")
}
