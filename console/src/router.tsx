import { QueryClient } from "@tanstack/react-query";
import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  lazyRouteComponent,
  Outlet,
  redirect,
  type RouterHistory,
} from "@tanstack/react-router";
import { z } from "zod";
import { isApiStatus, meQuery, SESSIONS_MAX_PAGE_SIZE } from "./lib/api";
import { ACL_EFFECTS, ACL_SUBJECTS, CATEGORIES, instantSchema, SEVERITIES, STATS_WINDOWS } from "./lib/schema";
import { NotFound } from "./components/NotFound";
import { Toast } from "./components/Toast";
import { LoginPage } from "./features/auth/LoginPage";
import { SESSION_PRESETS } from "./features/sessions/model";
import { INVENTORY_CATEGORIES, SCAN_STATES } from "./features/inventory/schema";

// Only a same-origin path survives as a post-login target (no open redirect). Ported from the server
// predicate (internal/server/redirect.go safeNext, plan §3.8): reject any control byte (< 0x20), DEL
// (0x7F) or backslash; require a path-absolute, non-protocol-relative target whose URL resolves back to the
// current origin. Anything else falls back to undefined (the caller then lands on /events).
export const safeRedirect = (v: unknown): string | undefined => {
  if (typeof v !== "string" || !v.startsWith("/") || v.startsWith("//")) return undefined;
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || c === 0x5c) return undefined; // control char, DEL, or backslash
  }
  try {
    return new URL(v, window.location.origin).origin === window.location.origin ? v : undefined;
  } catch {
    return undefined;
  }
};

// URL is state (design §4): filters, cursor and the open event are search params; invalid values drop out.
export const eventsSearchSchema = z.object({
  severity: z.enum(SEVERITIES).optional().catch(undefined),
  category: z.enum(CATEGORIES).optional().catch(undefined),
  agent: z.string().trim().min(1).optional().catch(undefined),
  cursor: z.string().min(1).optional().catch(undefined),
  event: z.string().min(1).optional().catch(undefined),
});
export type EventsSearch = z.infer<typeof eventsSearchSchema>;

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: () => (
    <>
      <Outlet />
      <Toast />
    </>
  ),
  notFoundComponent: NotFound,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  validateSearch: (s: Record<string, unknown>) => ({ redirect: safeRedirect(s.redirect) }),
  component: LoginPage,
});

// Auth guard: every console route needs the admin session (GET /api/v1/me). 401 → login.
const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  beforeLoad: async ({ context, location }) => {
    try {
      await context.queryClient.ensureQueryData(meQuery);
    } catch (e) {
      if (isApiStatus(e, 401)) throw redirect({ to: "/login", search: { redirect: location.href } });
      throw e;
    }
  },
  // Lazy (#92): the shell's Radix dialog/popover stack is not needed to paint /login (react.dev/reference/react/lazy).
  component: lazyRouteComponent(() => import("./components/AppShell"), "AppShell"),
  errorComponent: lazyRouteComponent(() => import("./components/AppShell"), "ShellError"),
});

const indexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/",
  // Overview is M6 (#46); land on risk events until then (design Q1 lead answer).
  beforeLoad: () => {
    throw redirect({ to: "/events" });
  },
});

const eventsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/events",
  validateSearch: (s: Record<string, unknown>) => eventsSearchSchema.parse(s),
  component: lazyRouteComponent(() => import("./features/events/EventsPage"), "EventsPage"),
});

// Overview (#46). Landing stays on risk events (design Q1 lead answer) until the stats surface ships.
// Default window is the backend's own (internal/server/risk_stats.go:12 — empty window → 7d); absent, invalid
// and the retired 30d all fall back to 7d, matching what the server would compute for no window.
export const overviewSearchSchema = z.object({ range: z.enum(STATS_WINDOWS).catch("7d").default("7d") });

const overviewRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/overview",
  validateSearch: (s: Record<string, unknown>) => overviewSearchSchema.parse(s),
  component: lazyRouteComponent(() => import("./features/overview/OverviewPage"), "OverviewPage"),
});

// Session audit (#16, plan §3.4): filters, page and the open session live in the URL; invalid values drop
// out. `open` is parsed for the drawer deep link (S5) and not acted on yet.
const optionalText = z.string().trim().min(1).optional().catch(undefined);
const optionalInstant = instantSchema.optional().catch(undefined);
export const sessionsSearchSchema = z.object({
  preset: z.enum(SESSION_PRESETS).optional().catch(undefined),
  from: optionalInstant,
  to: optionalInstant,
  agent: optionalText,
  nodeId: optionalText,
  sessionKey: optionalText,
  page: z.coerce.number().int().min(1).optional().catch(undefined),
  size: z.coerce.number().int().min(1).max(SESSIONS_MAX_PAGE_SIZE).optional().catch(undefined),
  open: optionalText,
});
export type SessionsSearch = z.infer<typeof sessionsSearchSchema>;

// An invalid from/to drops the whole time selection back to the default (no preset, any time) rather than
// keeping half a range under a preset that no longer describes it.
export function parseSessionsSearch(raw: Record<string, unknown>): SessionsSearch {
  const s = sessionsSearchSchema.parse(raw);
  const dropped = (k: "from" | "to") => raw[k] !== undefined && s[k] === undefined;
  return dropped("from") || dropped("to") ? { ...s, preset: undefined, from: undefined, to: undefined } : s;
}

const sessionsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/sessions",
  validateSearch: parseSessionsSearch,
  component: lazyRouteComponent(() => import("./features/sessions/SessionsPage"), "SessionsPage"),
});

// Asset scan ledger (#38/#41 S11, plan §3.10): filters and cursor live in the URL; invalid values drop out.
// The cursor is bound to the filters server-side, so a filter change drops it (as /events).
// TanStack's default parseSearch turns a canonical number or boolean into a JSON value (router-core qss.ts
// toValue, searchParams.ts parseSearchWith), so `?account=501` arrives as 501; ids are text, so convert back.
// ponytail: a non-canonical numeric (`1.0`, `1e3`) is canonicalised by JSON.parse before this sees it; uids,
// SIDs and node ids never take that form. A custom parseSearch is the upgrade if one ever does.
const optionalId = z.union([z.string(), z.number(), z.boolean()]).transform(String).pipe(z.string().trim().min(1)).optional().catch(undefined);
export const inventorySearchSchema = z.object({
  node: optionalId,
  account: optionalId,
  agent: optionalId,
  category: z.enum(INVENTORY_CATEGORIES).optional().catch(undefined),
  state: z.enum(SCAN_STATES).optional().catch(undefined),
  cursor: z.string().min(1).optional().catch(undefined),
});
export type InventorySearch = z.infer<typeof inventorySearchSchema>;

const inventoryRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/inventory",
  validateSearch: (s: Record<string, unknown>) => inventorySearchSchema.parse(s),
  component: lazyRouteComponent(() => import("./features/inventory/InventoryPage"), "InventoryPage"),
});

// Tool access control (#44 plan §3.9): name/applies-to/effect filters live in the URL; invalid values drop out.
export const aclSearchSchema = z.object({
  q: optionalText,
  subject: z.enum(ACL_SUBJECTS).optional().catch(undefined),
  effect: z.enum(ACL_EFFECTS).optional().catch(undefined),
});

const aclRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/acl",
  validateSearch: (s: Record<string, unknown>) => aclSearchSchema.parse(s),
  component: lazyRouteComponent(() => import("./features/acl/AclPage"), "AclPage"),
});

// Asset drawer deep link (#38/#41 S12, plan §6 "real /inventory/{id}"): a path under the ledger, inheriting its
// search params. The ledger owns the drawer (as EventsPage owns EventDrawer), so this route renders nothing itself.
const inventoryAssetRoute = createRoute({ getParentRoute: () => inventoryRoute, path: "$assetId" });

// #40 verification_uri: configured origin + /device. Optional complete-URI code is prefill only.
const deviceRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/device",
  validateSearch: (s: Record<string, unknown>) => ({ user_code: z.string().optional().catch(undefined).parse(s.user_code) }),
  component: lazyRouteComponent(() => import("./features/device-approval/DeviceApprovalPage"), "DeviceApprovalPage"),
});

// #72 S2: the verified employee's association continuation renders outside the console
// shell. A roleless human is denied /api/v1/me, audits and management (U3), so the shell's
// auth guard and navigation would fail; the endpoint itself denies any unbound session.
const deviceAssociationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/device/associate",
  validateSearch: (s: Record<string, unknown>) => ({ continuation: z.literal("confirm").optional().catch(undefined).parse(s.continuation) }),
  component: lazyRouteComponent(() => import("./features/device-approval/DeviceApprovalPage"), "DeviceAssociationPage"),
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  deviceAssociationRoute,
  appRoute.addChildren([indexRoute, overviewRoute, eventsRoute, sessionsRoute, inventoryRoute.addChildren([inventoryAssetRoute]), aclRoute, deviceRoute]),
]);

export function createAppRouter(queryClient: QueryClient, history?: RouterHistory) {
  return createRouter({ routeTree, context: { queryClient }, history, defaultPreload: false });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
