import { z } from "zod";
import { instantSchema } from "../../lib/schema";

// GET /api/v1/discovered-agents (internal/core/discovery_list.go DiscoveredAgentView / DiscoveryPage;
// enums from internal/core/discovery/report.go). Closed sets stay closed: an unknown value is a contract
// break, not a state to guess at.
export const INVENTORY_CATEGORIES = ["skills", "mcp", "plugins", "builtin_tools", "memory"] as const;
export const SCAN_STATES = ["not_supported", "not_scanned", "scanned", "error", "unknown"] as const;
const SCOPES = ["home", "project", "auto_memory"] as const;
const HASH_KINDS = ["file_sha256", "descriptor_sha256"] as const;
const FRESHNESS = ["fresh", "stale", "not_scanned"] as const;
const REASONS = [
  "project_scope_deferred",
  "unreadable",
  "not_regular_file",
  "escaped_root",
  "parse_failed",
  "too_large",
  "too_many_entries",
  "changed_during_read",
  "canceled",
  "unparsed_format",
  "tg_target_only",
  "home_denied",
  "home_unavailable",
  "owner_mismatch",
] as const;

// Go's zero time.Time marshals as this literal; a category that was never scanned carries it.
// It becomes null here so nothing downstream can render it as year 1.
const GO_ZERO_TIME = "0001-01-01T00:00:00Z";
const scanTime = instantSchema.transform((v) => (v === GO_ZERO_TIME ? null : v));

const categorySchema = z.object({
  category: z.enum(INVENTORY_CATEGORIES),
  scope: z.enum(SCOPES),
  scanState: z.enum(SCAN_STATES),
  reason: z.enum(REASONS).optional(),
  lastScanCompletedAt: scanTime,
  freshness: z.enum(FRESHNESS),
});

// observedLocalAccount, homePath and evidence.relPath are omitted for roles without content access
// (internal/server/discovery_list.go projectDiscoveredAgent): undefined means restricted, never empty.
export const discoveredAgentSchema = z.object({
  id: z.string().min(1),
  nodeId: z.string(),
  accountId: z.string(),
  observedLocalAccount: z.string().optional(),
  homePath: z.string().optional(),
  family: z.string(),
  found: z.enum(["found", "not_found", "unknown"]),
  evidence: z.object({ kind: z.string(), relPath: z.string().optional(), mtime: instantSchema.optional() }),
  version: z.string(),
  state: z.enum(["present", "absent", "unknown"]),
  categories: z.array(categorySchema),
  scanCompletedAt: scanTime,
  freshness: z.enum(FRESHNESS),
});
export type DiscoveredAgent = z.infer<typeof discoveredAgentSchema>;

export const discoveredAgentPageSchema = z.object({ items: z.array(discoveredAgentSchema), next_page_token: z.string() });

// GET /api/v1/agent-assets[/{id}] (internal/core/discovery_list.go AgentAssetView). sourceRelPath is omitted for
// roles without content access (internal/server/discovery_list.go projectAgentAsset): undefined means restricted.
// The MCP descriptor is the allowed projection only (internal/core/discovery/report.go MCPDescriptor): names and
// key names. Unknown fields are stripped here, so a value the server should never send can never render.
export const agentAssetSchema = z.object({
  assetId: z.string().min(1),
  name: z.string(),
  category: z.enum(INVENTORY_CATEGORIES),
  sourceRelPath: z.string().optional(),
  size: z.number().int().nonnegative().optional(),
  mtime: instantSchema.optional(),
  hash: z.string(),
  hashKind: z.enum(HASH_KINDS),
  descriptor: z.object({ name: z.string(), transport: z.string(), envKeys: z.array(z.string()), headerKeys: z.array(z.string()) }).optional(),
  discoveredAgentId: z.string(),
  nodeId: z.string(),
  accountId: z.string(),
  family: z.string(),
  scope: z.enum(SCOPES),
  scanCompletedAt: scanTime,
  scanState: z.enum(SCAN_STATES),
  reason: z.enum(REASONS).optional(),
  freshness: z.enum(FRESHNESS),
});
export type AgentAsset = z.infer<typeof agentAssetSchema>;

export const agentAssetPageSchema = z.object({ items: z.array(agentAssetSchema), next_page_token: z.string() });
