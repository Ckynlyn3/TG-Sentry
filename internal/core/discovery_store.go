package core

import (
	"aegishook/internal/core/discovery"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrStaleDiscoveryReport  = errors.New("stale_discovery_report")
	ErrDiscoveryClient       = errors.New("discovery requires enrolled device credentials")
	ErrDiscoveryNodeMismatch = errors.New("discovery node identity mismatch")
)

// DiscoveryNodeState keeps the RAW completion as the replay watermark, including
// future-dated reports. Inventory timestamps instead use min(completion, receipt)
// so an endpoint's clock cannot extend read-side freshness (plan §3.8/LD10).
type DiscoveryNodeState struct {
	LastScanCompletedAt time.Time `json:"lastScanCompletedAt"`
	ReceivedAt          time.Time `json:"receivedAt"`
}

type DiscoveredCategory struct {
	discovery.Category
	LastScanCompletedAt time.Time `json:"lastScanCompletedAt"`
}

type DiscoveredAgent struct {
	ID                   string               `json:"id"`
	NodeID               string               `json:"nodeId"`
	AccountID            string               `json:"accountId"`
	ObservedLocalAccount string               `json:"observedLocalAccount"`
	HomePath             string               `json:"homePath"`
	Family               string               `json:"family"`
	Found                discovery.FoundState `json:"found"`
	Evidence             discovery.Evidence   `json:"evidence"`
	Version              string               `json:"version"`
	State                string               `json:"state"`
	Categories           []DiscoveredCategory `json:"categories"`
	ScanCompletedAt      time.Time            `json:"scanCompletedAt"`
}

type AgentAsset struct {
	discovery.Asset
	DiscoveredAgentID string          `json:"discoveredAgentId"`
	NodeID            string          `json:"nodeId"`
	AccountID         string          `json:"accountId"`
	Family            string          `json:"family"`
	Scope             discovery.Scope `json:"scope"`
	ScanCompletedAt   time.Time       `json:"scanCompletedAt"`
}

// IngestDiscoveryReport uses the existing tenant transaction and record kinds.
// No absent account, failed home or incomplete category implies deletion.
func (e *Engine) IngestDiscoveryReport(ctx context.Context, nodeID string, report discovery.Report) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	receivedAt := e.clock()
	tx, err := e.beginTenantTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateDiscoveryReport(nodeID, report); err != nil {
		return err
	}
	if err := e.discoveryClient(tx, nodeID); err != nil {
		return err
	}
	var state DiscoveryNodeState
	err = discoveryRecord(tx, "discovery_node_state", nodeID, &state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Named local exception §9.3: RFC 9110 §15.5.10, conflict with node state.
	if err == nil && !report.ScanCompletedAt.After(state.LastScanCompletedAt) {
		return ErrStaleDiscoveryReport
	}
	effective := report.ScanCompletedAt
	if effective.After(receivedAt) {
		effective = receivedAt
	}
	for _, account := range report.Accounts {
		if account.HomeState != discovery.HomeReadable {
			continue
		}
		for _, agent := range account.Agents {
			if err := e.reconcileDiscoveryAgent(tx, report.NodeID, account, agent, effective); err != nil {
				return err
			}
		}
	}
	state = DiscoveryNodeState{LastScanCompletedAt: report.ScanCompletedAt, ReceivedAt: receivedAt}
	if err := putDiscoveryRecord(tx, "discovery_node_state", nodeID, state); err != nil {
		return err
	}
	if err := appendDiscoveryAudit(tx, report, receivedAt); err != nil {
		return err
	}
	return tx.Commit()
}

// Mirror issueClientCredential: mutation and metadata-only audit commit together.
// Attribution comes from the authenticated node, never reported account labels.
func appendDiscoveryAudit(tx *sql.Tx, report discovery.Report, receivedAt time.Time) error {
	agents, assets := 0, 0
	for _, account := range report.Accounts {
		agents += len(account.Agents)
		for _, agent := range account.Agents {
			for _, category := range agent.Categories {
				assets += len(category.Assets)
			}
		}
	}
	audit := Audit{Actor: Actor{Kind: "device", Subject: report.NodeID}, ID: ID(), Action: "discovery.ingest", Subject: report.NodeID, Detail: fmt.Sprintf("accounts=%d agents=%d assets=%d", len(report.Accounts), agents, assets), CreatedAt: receivedAt}
	payload, err := json.Marshal(audit)
	if err != nil {
		return err
	}
	_, err = tx.Exec(insertRecord, eventTenant(), "audit", audit.ID, string(payload))
	return err
}

func validateDiscoveryReport(nodeID string, report discovery.Report) error {
	if err := report.Validate(); err != nil {
		return err
	}
	if nodeID == "" {
		return ErrDiscoveryClient
	}
	if report.NodeID != nodeID {
		return ErrDiscoveryNodeMismatch
	}
	if report.ScanStartedAt.IsZero() || report.ScanCompletedAt.IsZero() || report.ScanCompletedAt.Before(report.ScanStartedAt) {
		return discovery.ErrInvalidReport
	}
	accounts := map[string]bool{}
	for _, account := range report.Accounts {
		if account.AccountID == "" || accounts[account.AccountID] {
			return discovery.ErrInvalidReport
		}
		accounts[account.AccountID] = true
		families := map[string]bool{}
		for _, agent := range account.Agents {
			if agent.Family == "" || families[agent.Family] {
				return discovery.ErrInvalidReport
			}
			families[agent.Family] = true
			// Probe's NotFound is conclusive only with empty evidence (probe.go).
			if agent.Found == discovery.NotFound && (agent.Evidence.Kind != "" || agent.Evidence.RelPath != "" || agent.Evidence.Mtime != nil) {
				return discovery.ErrInvalidReport
			}
			for _, category := range agent.Categories {
				for _, asset := range category.Assets {
					id, err := discovery.AssetID(nodeID, account.AccountID, agent.Family, category.Category, asset.SourceRelPath, asset.Name)
					if err != nil || asset.AssetID != id || asset.Category != category.Category || agent.Found == discovery.NotFound {
						return discovery.ErrInvalidReport
					}
				}
			}
		}
	}
	return nil
}

func (e *Engine) discoveryClient(tx *sql.Tx, nodeID string) error {
	query := "SELECT payload FROM records WHERE tenant_id=$1 AND kind='client_nodes' AND id=$2"
	if e.postgres {
		// Serialize even the first report against this existing enrolled-node row.
		// https://www.postgresql.org/docs/16/explicit-locking.html#LOCKING-ROWS
		query += " FOR UPDATE"
	}
	var payload []byte
	if err := tx.QueryRow(query, eventTenant(), nodeID).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDiscoveryClient
		}
		return err
	}
	var node ClientNode
	if err := json.Unmarshal(payload, &node); err != nil {
		return err
	}
	if node.ID != nodeID || node.Revoked {
		return ErrDiscoveryClient
	}
	return nil
}

func discoveryRecord(tx *sql.Tx, kind, id string, out any) error {
	var payload []byte
	if err := tx.QueryRow("SELECT payload FROM records WHERE tenant_id=$1 AND kind=$2 AND id=$3", eventTenant(), kind, id).Scan(&payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, out)
}

func putDiscoveryRecord(tx *sql.Tx, kind, id string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = tx.Exec(upsertRecord, eventTenant(), kind, id, string(payload))
	return err
}

func (e *Engine) reconcileDiscoveryAgent(tx *sql.Tx, nodeID string, account discovery.Account, agent discovery.Agent, effective time.Time) error {
	id, err := discovery.DiscoveredAgentID(nodeID, account.AccountID, agent.Family)
	if err != nil {
		return err
	}
	var prior DiscoveredAgent
	if err := discoveryRecord(tx, "discovered_agents", id, &prior); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	row := DiscoveredAgent{ID: id, NodeID: nodeID, AccountID: account.AccountID, ObservedLocalAccount: account.ObservedLocalAccount, HomePath: account.HomePath, Family: agent.Family, Found: agent.Found, Evidence: agent.Evidence, Version: agent.Version, State: "unknown", Categories: append([]DiscoveredCategory(nil), prior.Categories...), ScanCompletedAt: effective}
	switch agent.Found {
	case discovery.Found:
		row.State = "present"
	case discovery.NotFound:
		row.State = "absent"
	}
	for _, category := range agent.Categories {
		state := DiscoveredCategory{Category: category}
		state.Assets = nil // Assets live only in agent_assets; the row retains state.
		index := -1
		for i, old := range row.Categories {
			if old.Category.Category == category.Category && old.Scope == category.Scope {
				index = i
				state.LastScanCompletedAt = old.LastScanCompletedAt
				break
			}
		}
		if category.ScanState == discovery.ScanScanned {
			if err := e.replaceDiscoveryAssets(tx, row, category, effective); err != nil {
				return err
			}
			state.LastScanCompletedAt = effective
		}
		if index < 0 {
			row.Categories = append(row.Categories, state)
		} else {
			row.Categories[index] = state
		}
	}
	return putDiscoveryRecord(tx, "discovered_agents", id, row)
}

func (e *Engine) replaceDiscoveryAssets(tx *sql.Tx, agent DiscoveredAgent, category discovery.Category, effective time.Time) error {
	// An asset ID deliberately omits scope (§3.2). Do not let a different scope
	// overwrite retained inventory under the same ID (§11 R3).
	for _, asset := range category.Assets {
		var prior AgentAsset
		err := discoveryRecord(tx, "agent_assets", asset.AssetID, &prior)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && (prior.DiscoveredAgentID != agent.ID || prior.Scope != category.Scope) {
			return discovery.ErrInvalidReport
		}
	}
	// R3: only this explicit completed category/scope authorizes deletion, even
	// when NotFound confirms agent absence. Deferred scopes remain untouched.
	_, err := tx.Exec("DELETE FROM records WHERE tenant_id=$1 AND kind='agent_assets' AND "+e.jsonField("", "discoveredAgentId")+"=$2 AND "+e.jsonField("", "category")+"=$3 AND "+e.jsonField("", "scope")+"=$4", eventTenant(), agent.ID, category.Category, category.Scope)
	if err != nil {
		return err
	}
	for _, asset := range category.Assets {
		row := AgentAsset{Asset: asset, DiscoveredAgentID: agent.ID, NodeID: agent.NodeID, AccountID: agent.AccountID, Family: agent.Family, Scope: category.Scope, ScanCompletedAt: effective}
		if err := putDiscoveryRecord(tx, "agent_assets", asset.AssetID, row); err != nil {
			return err
		}
	}
	return nil
}
