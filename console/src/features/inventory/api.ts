import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { request } from "../../lib/api";
import { agentAssetPageSchema, agentAssetSchema, discoveredAgentPageSchema } from "./schema";

export interface InventoryQuery {
  node?: string;
  account?: string;
  agent?: string;
  category?: string;
  state?: string;
  cursor?: string;
}

// The server's default page (internal/core/discovery_list.go discoveryPage: 0 → 20, max 100, AIP-158).
export const INVENTORY_PAGE_SIZE = 20;
// Asset rows are listed for one narrowed agent, one page at the server's maximum.
export const ASSET_PAGE_SIZE = 100;

const query = (size: number, { node, account, agent, category, state, cursor }: InventoryQuery) => {
  const p = new URLSearchParams({ page_size: String(size) });
  if (cursor) p.set("page_token", cursor);
  for (const [k, v] of Object.entries({ node, account, agent, category, state })) if (v) p.set(k, v);
  return p;
};

export const listDiscoveredAgents = (q: InventoryQuery) => request(`/api/v1/discovered-agents?${query(INVENTORY_PAGE_SIZE, q)}`, discoveredAgentPageSchema);

export const useDiscoveredAgents = (q: InventoryQuery) =>
  useQuery({ queryKey: ["discovered-agents", q], queryFn: () => listDiscoveredAgents(q), placeholderData: keepPreviousData });

// ponytail: one page of assets per narrowed agent; the ledger says when more exist. A cursor pager on the asset
// rows is the upgrade if agents routinely carry more than ASSET_PAGE_SIZE assets.
export function useAgentAssets({ node, account, agent, category, state }: InventoryQuery) {
  const q = { node, account, agent, category, state };
  return useQuery({
    queryKey: ["agent-assets", q],
    queryFn: () => request(`/api/v1/agent-assets?${query(ASSET_PAGE_SIZE, q)}`, agentAssetPageSchema),
    enabled: Boolean(agent),
  });
}

export const getAgentAsset = (id: string) => request(`/api/v1/agent-assets/${encodeURIComponent(id)}`, agentAssetSchema);
