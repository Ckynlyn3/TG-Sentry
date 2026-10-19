// Session audit list (#16 S4): pure helpers for the filter bar. No React here.

// Presets of the AgentSentry audit-log filter (plan §2 "Presets 1h/24h/7d/Custom", AgentSentry filters).
export const SESSION_PRESETS = ["1h", "24h", "7d", "custom"] as const;
export type SessionPreset = (typeof SESSION_PRESETS)[number];
export type RelativePreset = Exclude<SessionPreset, "custom">;

const HOUR = 3_600_000;
const PRESET_MS: Record<RelativePreset, number> = { "1h": HOUR, "24h": 24 * HOUR, "7d": 7 * 24 * HOUR };

export const isRelative = (p: SessionPreset | undefined): p is RelativePreset => p !== undefined && p !== "custom";

// The client computes RFC 3339 instants (plan §3.4, LD6). `to` is the exclusive upper bound (plan A3).
export function presetRange(preset: RelativePreset, now = Date.now()) {
  return { from: new Date(now - PRESET_MS[preset]).toISOString(), to: new Date(now).toISOString() };
}

const pad = (n: number) => String(n).padStart(2, "0");

// <input type="datetime-local"> holds local wall time without an offset (HTML living standard,
// "local date and time string"); convert at the edge so the URL and the API only see instants.
export function toLocalInput(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// A date-time string without an offset is local time (ECMA-262 Date.parse).
export function fromLocalInput(value: string): string | undefined {
  if (!value) return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

// Agent families the control plane names: keys and product names of internal/core/agents.go AgentName.
// The summary `agent` filter takes the family ID; an empty family is stored as "pi" (AgentID).
export const AGENT_NAMES: Readonly<Record<string, string>> = {
  claude: "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
  opencode: "OpenCode",
  openclaw: "OpenClaw",
  grok: "Grok Build",
  pi: "Pi",
};

// Own properties only: "__proto__", "constructor" or "toString" are agent IDs as reported, not prototype members.
export const agentLabel = (id: string) => (Object.hasOwn(AGENT_NAMES, id) ? (AGENT_NAMES[id] ?? id) : id);

// Callers pass validated instants (isInstant); a non-finite date is still never handed to Intl, which throws.
export function formatRangeTime(iso: string, lng: string) {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  return new Intl.DateTimeFormat(lng, { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(ms);
}
