package server

import (
	"errors"
	"log"
	"net/http"
)

func (s *Server) transformToolOutput(w http.ResponseWriter, r *http.Request) {
	review, err := s.Engine.Review(r.PathValue("id"))
	node, _ := requestClient(r)
	// Same credential/node binding as /result, with a common 404 for absence
	// and wrong ownership. Engine's store/tenant layer owns tenant selection.
	if err != nil || r.Header.Get("Authorization") != "" && !s.Engine.ClientOwnsInstance(node.ID, review.InstanceID) {
		fail(w, http.StatusNotFound, errors.New("Tool output review not found"))
		return
	}
	response, err := s.Engine.TransformToolOutput(r.Context(), review.ID, r.Body)
	// A metadata-audit failure must not discard a computed replacement or
	// strengthen an alert. Engine returns its outcome alongside that error.
	if err != nil && response.Outcome == "" {
		fail(w, http.StatusServiceUnavailable, errors.New("Tool output transformation unavailable"))
		return
	}
	if err != nil {
		log.Print("Tool output metadata audit unavailable")
	}
	write(w, response)
}
