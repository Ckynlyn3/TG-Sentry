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
import { CATEGORIES, instantSchema, SEVERITIES, STATS_WINDOWS } from "./lib/schema";
import { AppShell, ShellError } from "./components/AppShell";
import { NotFound } from "./components/NotFound";
import { Toast } from "./components/Toast";
import { LoginPage } from "./features/auth/LoginPage";
import { SESSION_PRESETS } from "./features/sessions/model";

// Only same-origin paths survive as a post-login target (no open redirect).
export const safeRedirect = (v: unknown): string | undefined =>
  typeof v === "string" && v.startsWith("/") && !v.startsWith("//") && !v.startsWith("/\\") ? v : undefined;

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
  component: AppShell,
  errorComponent: ShellError,
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
export const overviewSearchSchema = z.object({ range: z.enum(STATS_WINDOWS).catch("24h").default("24h") });

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

const routeTree = rootRoute.addChildren([loginRoute, appRoute.addChildren([indexRoute, overviewRoute, eventsRoute, sessionsRoute])]);

export function createAppRouter(queryClient: QueryClient, history?: RouterHistory) {
  return createRouter({ routeTree, context: { queryClient }, history, defaultPreload: false });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
