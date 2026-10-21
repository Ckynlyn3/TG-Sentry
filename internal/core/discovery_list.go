package core

import (
	"aegishook/internal/core/discovery"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

var ErrDiscoveryQuery = errors.New("invalid discovery query or page token")

// Plan §3.9: agent is the stable discoveredAgentId; state is category scanState,
// not freshness. Category/state filters select the returned categories as well.
type DiscoveryFilter struct{ Node, Account, Agent, Category, State string }

type DiscoveryEvidenceView struct {
	Kind    string     `json:"kind"`
	RelPath *string    `json:"relPath,omitempty"`
	Mtime   *time.Time `json:"mtime,omitempty"`
}
type DiscoveredCategoryView struct {
	Category            string              `json:"category"`
	Scope               discovery.Scope     `json:"scope"`
	ScanState           discovery.ScanState `json:"scanState"`
	Reason              discovery.Reason    `json:"reason,omitempty"`
	LastScanCompletedAt time.Time           `json:"lastScanCompletedAt"`
	Freshness           string              `json:"freshness"`
}

// Explicit wire allowlists, like ReviewMetaView: never embed stored payloads or
// Category.Assets, so future storage/content fields cannot leak into reads.
type DiscoveredAgentView struct {
	ID                   string                   `json:"id"`
	NodeID               string                   `json:"nodeId"`
	AccountID            string                   `json:"accountId"`
	ObservedLocalAccount *string                  `json:"observedLocalAccount,omitempty"`
	HomePath             *string                  `json:"homePath,omitempty"`
	Family               string                   `json:"family"`
	Found                discovery.FoundState     `json:"found"`
	Evidence             DiscoveryEvidenceView    `json:"evidence"`
	Version              string                   `json:"version"`
	State                string                   `json:"state"`
	Categories           []DiscoveredCategoryView `json:"categories"`
	ScanCompletedAt      time.Time                `json:"scanCompletedAt"`
	Freshness            string                   `json:"freshness"`
}
type AgentAssetView struct {
	AssetID           string                   `json:"assetId"`
	Name              string                   `json:"name"`
	Category          string                   `json:"category"`
	SourceRelPath     *string                  `json:"sourceRelPath,omitempty"`
	Size              *int64                   `json:"size,omitempty"`
	Mtime             *time.Time               `json:"mtime,omitempty"`
	Hash              string                   `json:"hash"`
	HashKind          discovery.HashKind       `json:"hashKind"`
	Descriptor        *discovery.MCPDescriptor `json:"descriptor,omitempty"`
	DiscoveredAgentID string                   `json:"discoveredAgentId"`
	NodeID            string                   `json:"nodeId"`
	AccountID         string                   `json:"accountId"`
	Family            string                   `json:"family"`
	Scope             discovery.Scope          `json:"scope"`
	ScanCompletedAt   time.Time                `json:"scanCompletedAt"`
	ScanState         discovery.ScanState      `json:"scanState"`
	Reason            discovery.Reason         `json:"reason,omitempty"`
	Freshness         string                   `json:"freshness"`
}
type DiscoveryPage[T any] struct {
	Items         []T    `json:"items"`
	NextPageToken string `json:"next_page_token"`
}

func validDiscoveryFilter(f DiscoveryFilter) bool {
	return (f.Category == "" || hasExact(f.Category, "skills", "mcp", "plugins", "builtin_tools", "memory")) &&
		(f.State == "" || hasExact(f.State, "not_supported", "not_scanned", "scanned", "error", "unknown"))
}

func discoveryFreshness(now, effective time.Time, policy *DiscoveryPolicy) string {
	if policy == nil || !policy.Enabled || policy.IntervalSeconds <= 0 || effective.IsZero() {
		return "not_scanned"
	}
	// Named local exception §9.1: strict age > interval, no grace multiplier.
	// Protection policy validates the duration conversion before publication.
	if now.Sub(effective) > time.Duration(policy.IntervalSeconds)*time.Second {
		return "stale"
	}
	return "fresh"
}

// One tenant transaction reads policy, category state and retained assets together.
// ponytail: scan existing records like RiskEvents; index the projection if the
// inventory outgrows the existing small-set pagination precedent (AIP-158).
func (e *Engine) discoveryInventory() ([]DiscoveredAgent, []AgentAsset, *DiscoveryPolicy, error) {
	tx, err := e.beginTenant()
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT kind,payload FROM records WHERE tenant_id=$1 AND (kind IN ('discovered_agents','agent_assets') OR (kind='protection' AND id='current')) ORDER BY id", eventTenant())
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	agents, assets := []DiscoveredAgent{}, []AgentAsset{}
	var policy *DiscoveryPolicy
	for rows.Next() {
		var kind string
		var payload []byte
		if err := rows.Scan(&kind, &payload); err != nil {
			return nil, nil, nil, err
		}
		switch kind {
		case "discovered_agents":
			var v DiscoveredAgent
			if err := json.Unmarshal(payload, &v); err != nil {
				return nil, nil, nil, err
			}
			agents = append(agents, v)
		case "agent_assets":
			var v AgentAsset
			if err := json.Unmarshal(payload, &v); err != nil {
				return nil, nil, nil, err
			}
			assets = append(assets, v)
		case "protection":
			var v ProtectionState
			if err := json.Unmarshal(payload, &v); err != nil {
				return nil, nil, nil, err
			}
			policy = v.Discovery
		}
	}
	return agents, assets, policy, rows.Err()
}

func discoveryCategoryMatches(c DiscoveredCategory, f DiscoveryFilter) bool {
	return (f.Category == "" || c.Category.Category == f.Category) && (f.State == "" || string(c.ScanState) == f.State)
}
func discoveryMatches(node, account, agent string, f DiscoveryFilter) bool {
	return (f.Node == "" || f.Node == node) && (f.Account == "" || f.Account == account) && (f.Agent == "" || f.Agent == agent)
}
func discoveredAgentView(a DiscoveredAgent, f DiscoveryFilter, now time.Time, policy *DiscoveryPolicy) DiscoveredAgentView {
	categories := []DiscoveredCategoryView{}
	for _, c := range a.Categories {
		if discoveryCategoryMatches(c, f) {
			categories = append(categories, DiscoveredCategoryView{Category: c.Category.Category, Scope: c.Scope, ScanState: c.ScanState, Reason: c.Reason, LastScanCompletedAt: c.LastScanCompletedAt, Freshness: discoveryFreshness(now, c.LastScanCompletedAt, policy)})
		}
	}
	return DiscoveredAgentView{ID: a.ID, NodeID: a.NodeID, AccountID: a.AccountID, ObservedLocalAccount: &a.ObservedLocalAccount, HomePath: &a.HomePath, Family: a.Family, Found: a.Found, Evidence: DiscoveryEvidenceView{Kind: a.Evidence.Kind, RelPath: &a.Evidence.RelPath, Mtime: a.Evidence.Mtime}, Version: a.Version, State: a.State, Categories: categories, ScanCompletedAt: a.ScanCompletedAt, Freshness: discoveryFreshness(now, a.ScanCompletedAt, policy)}
}
func agentAssetView(a AgentAsset, c DiscoveredCategory, now time.Time, policy *DiscoveryPolicy) AgentAssetView {
	return AgentAssetView{AssetID: a.AssetID, Name: a.Name, Category: a.Category, SourceRelPath: &a.SourceRelPath, Size: a.Size, Mtime: a.Mtime, Hash: a.Hash, HashKind: a.HashKind, Descriptor: a.Descriptor, DiscoveredAgentID: a.DiscoveredAgentID, NodeID: a.NodeID, AccountID: a.AccountID, Family: a.Family, Scope: a.Scope, ScanCompletedAt: a.ScanCompletedAt, ScanState: c.ScanState, Reason: c.Reason, Freshness: discoveryFreshness(now, a.ScanCompletedAt, policy)}
}

func discoveryToken(kind, id string, filter DiscoveryFilter) string {
	// RiskEvents convention: opaque SHA-256 cursor bound to resource and filters;
	// page_size can change. Membership, never the cursor, authorizes a read.
	payload, _ := json.Marshal(struct {
		Kind, ID string
		Filter   DiscoveryFilter
	}{kind, id, filter})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
func discoveryPage[T any](items []T, size int, token, kind string, f DiscoveryFilter, id func(T) string) (DiscoveryPage[T], error) {
	if size < 0 || !validDiscoveryFilter(f) {
		return DiscoveryPage[T]{}, ErrDiscoveryQuery
	}
	if size == 0 {
		size = 20
	}
	if size > 100 {
		size = 100
	} // RiskEvents / AIP-158 defaults.
	page := DiscoveryPage[T]{Items: []T{}}
	found := token == ""
	last := ""
	for _, item := range items {
		if !found {
			if discoveryToken(kind, id(item), f) == token {
				found = true
			}
			continue
		}
		if len(page.Items) == size {
			page.NextPageToken = last
			break
		}
		page.Items = append(page.Items, item)
		last = discoveryToken(kind, id(item), f)
	}
	if !found {
		return DiscoveryPage[T]{}, ErrDiscoveryQuery
	}
	return page, nil
}

func (e *Engine) DiscoveredAgents(size int, token string, f DiscoveryFilter) (DiscoveryPage[DiscoveredAgentView], error) {
	if size < 0 || !validDiscoveryFilter(f) {
		return DiscoveryPage[DiscoveredAgentView]{}, ErrDiscoveryQuery
	}
	agents, _, policy, err := e.discoveryInventory()
	if err != nil {
		return DiscoveryPage[DiscoveredAgentView]{}, err
	}
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].ScanCompletedAt.Equal(agents[j].ScanCompletedAt) {
			return agents[i].ID > agents[j].ID
		}
		return agents[i].ScanCompletedAt.After(agents[j].ScanCompletedAt)
	})
	items := []DiscoveredAgentView{}
	now := e.clock()
	for _, a := range agents {
		if !discoveryMatches(a.NodeID, a.AccountID, a.ID, f) {
			continue
		}
		v := discoveredAgentView(a, f, now, policy)
		if (f.Category != "" || f.State != "") && len(v.Categories) == 0 {
			continue
		}
		items = append(items, v)
	}
	return discoveryPage(items, size, token, "discovered_agents", f, func(a DiscoveredAgentView) string { return a.ID })
}
func (e *Engine) discoveryAssetViews(f DiscoveryFilter) ([]AgentAssetView, error) {
	agents, assets, policy, err := e.discoveryInventory()
	if err != nil {
		return nil, err
	}
	type categoryKey struct {
		agent, category string
		scope           discovery.Scope
	}
	states := map[categoryKey]DiscoveredCategory{}
	for _, a := range agents {
		for _, c := range a.Categories {
			states[categoryKey{a.ID, c.Category.Category, c.Scope}] = c
		}
	}
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].ScanCompletedAt.Equal(assets[j].ScanCompletedAt) {
			return assets[i].AssetID > assets[j].AssetID
		}
		return assets[i].ScanCompletedAt.After(assets[j].ScanCompletedAt)
	})
	items := []AgentAssetView{}
	now := e.clock()
	for _, a := range assets {
		c, ok := states[categoryKey{a.DiscoveredAgentID, a.Category, a.Scope}]
		if !ok {
			return nil, errors.New("discovery asset category missing")
		}
		if discoveryMatches(a.NodeID, a.AccountID, a.DiscoveredAgentID, f) && discoveryCategoryMatches(c, f) {
			items = append(items, agentAssetView(a, c, now, policy))
		}
	}
	return items, nil
}
func (e *Engine) AgentAssets(size int, token string, f DiscoveryFilter) (DiscoveryPage[AgentAssetView], error) {
	if size < 0 || !validDiscoveryFilter(f) {
		return DiscoveryPage[AgentAssetView]{}, ErrDiscoveryQuery
	}
	items, err := e.discoveryAssetViews(f)
	if err != nil {
		return DiscoveryPage[AgentAssetView]{}, err
	}
	return discoveryPage(items, size, token, "agent_assets", f, func(a AgentAssetView) string { return a.AssetID })
}
func (e *Engine) AgentAsset(id string) (AgentAssetView, error) {
	items, err := e.discoveryAssetViews(DiscoveryFilter{})
	if err != nil {
		return AgentAssetView{}, err
	}
	for _, a := range items {
		if a.AssetID == id {
			return a, nil
		}
	}
	return AgentAssetView{}, sql.ErrNoRows
}
