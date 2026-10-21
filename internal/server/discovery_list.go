package server

import (
	"aegishook/internal/core"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
)

// Copy RiskEvents' AIP-158 parsing exactly (including empty/zero default, signed
// 32-bit input, core rejection of negatives, and core coercion above 100).
func discoveryQuery(r *http.Request) (int, string, core.DiscoveryFilter, error) {
	q := r.URL.Query()
	size := int64(0)
	if q.Get("page_size") != "" {
		var err error
		size, err = strconv.ParseInt(q.Get("page_size"), 10, 32)
		if err != nil {
			return 0, "", core.DiscoveryFilter{}, core.ErrDiscoveryQuery
		}
	}
	return int(size), q.Get("page_token"), core.DiscoveryFilter{Node: q.Get("node"), Account: q.Get("account"), Agent: q.Get("agent"), Category: q.Get("category"), State: q.Get("state")}, nil
}

func projectDiscoveredAgent(v core.DiscoveredAgentView, pathsAllowed bool) core.DiscoveredAgentView {
	if !pathsAllowed {
		v.ObservedLocalAccount = nil
		v.HomePath = nil
		v.Evidence.RelPath = nil
	}
	return v
}
func projectAgentAsset(v core.AgentAssetView, pathsAllowed bool) core.AgentAssetView {
	if !pathsAllowed {
		v.SourceRelPath = nil
	}
	return v
}
func discoveryReadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrDiscoveryQuery):
		fail(w, 400, err)
	case errors.Is(err, sql.ErrNoRows):
		fail(w, 404, errors.New("discovery asset not found"))
	default:
		fail(w, 500, errors.New("discovery inventory unavailable"))
	}
}

// Inventory GETs deliberately stay out of hookAllowed and cliRoutes. Every
// request, including cursor continuation and detail, needs its own human session.
func (s *Server) discoveredAgents(w http.ResponseWriter, r *http.Request) {
	size, token, filter, err := discoveryQuery(r)
	if err != nil {
		discoveryReadError(w, err)
		return
	}
	page, err := s.Engine.DiscoveredAgents(size, token, filter)
	if err != nil {
		discoveryReadError(w, err)
		return
	}
	pathsAllowed := s.contentAllowed(r)
	items := make([]core.DiscoveredAgentView, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, projectDiscoveredAgent(item, pathsAllowed))
	}
	write(w, core.DiscoveryPage[core.DiscoveredAgentView]{Items: items, NextPageToken: page.NextPageToken})
}
func (s *Server) agentAssets(w http.ResponseWriter, r *http.Request) {
	size, token, filter, err := discoveryQuery(r)
	if err != nil {
		discoveryReadError(w, err)
		return
	}
	page, err := s.Engine.AgentAssets(size, token, filter)
	if err != nil {
		discoveryReadError(w, err)
		return
	}
	pathsAllowed := s.contentAllowed(r)
	items := make([]core.AgentAssetView, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, projectAgentAsset(item, pathsAllowed))
	}
	write(w, core.DiscoveryPage[core.AgentAssetView]{Items: items, NextPageToken: page.NextPageToken})
}
func (s *Server) agentAsset(w http.ResponseWriter, r *http.Request) {
	asset, err := s.Engine.AgentAsset(r.PathValue("id"))
	if err != nil {
		discoveryReadError(w, err)
		return
	}
	write(w, projectAgentAsset(asset, s.contentAllowed(r)))
}
