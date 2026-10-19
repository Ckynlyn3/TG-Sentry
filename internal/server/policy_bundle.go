package server

import (
	"aegishook/internal/core"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) clientBundleRoutes(mux *http.ServeMux) {
	s.clientKeyRoutes(mux)
	mux.HandleFunc("GET /api/v1/client/bundle", func(w http.ResponseWriter, r *http.Request) {
		node, ok := requestClient(r)
		if !ok {
			fail(w, http.StatusForbidden, errors.New("bundle requires enrolled device credentials"))
			return
		}
		bundle, err := s.Engine.ClientPolicyBundle(node.ID)
		if err != nil {
			fail(w, http.StatusServiceUnavailable, errors.New("policy bundle unavailable"))
			return
		}
		etag := core.PolicyBundleETag(bundle)
		w.Header().Set("ETag", etag)
		// Issue #65 plan §3.6/§9.3: expose key-only changes even on 304.
		w.Header().Set("TG-Trust-Version", strconv.Itoa(s.Engine.BundleTrustVersion()))
		// RFC 9110 §§13.1.2,15.4.5: GET uses weak comparison, accepts a list
		// or '*', and returns an empty 304. Authentication always ran first.
		for _, header := range r.Header.Values("If-None-Match") {
			for _, candidate := range strings.Split(header, ",") {
				candidate = strings.TrimSpace(candidate)
				if candidate == "*" || strings.TrimPrefix(candidate, "W/") == etag {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
		write(w, bundle)
	})
}
