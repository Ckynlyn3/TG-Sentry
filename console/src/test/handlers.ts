import { http, HttpResponse } from "msw";
import { allEvents, callsPage, clientNodes, firstPage, instances, lastPage, me, policiesPage, sessionSummaries, sessionSummariesPage3, templatesPage } from "./fixtures";

// Default happy-path handlers mirroring the control plane routes; tests override per case.
// No POST /api/v1/login: the admin-token path is removed (#12 AC2). SSO initiation is a browser 302 chain
// handled by GET /api/v1/auth/login, mocked per-test in the auth suite.
export const requests: URL[] = [];

export const handlers = [
  http.get("*/api/v1/me", () => HttpResponse.json(me)),
  http.post("*/api/v1/logout", () => HttpResponse.json({ ok: true })),
  http.get("*/api/v1/risk-events", ({ request }) => {
    const url = new URL(request.url);
    requests.push(url);
    return HttpResponse.json(url.searchParams.get("page_token") === "cursor-page-2" ? lastPage : firstPage);
  }),
  http.get("*/api/v1/client-nodes", () => HttpResponse.json(clientNodes)),
  http.get("*/api/v1/session-summaries", ({ request }) => {
    const url = new URL(request.url);
    requests.push(url);
    return HttpResponse.json(url.searchParams.get("page") === "3" ? sessionSummariesPage3 : sessionSummaries);
  }),
  http.get("*/api/v1/instances", () => HttpResponse.json(instances)),
  http.get("*/api/v1/calls", () => HttpResponse.json(callsPage)),
  http.get("*/api/v1/policies", () => HttpResponse.json(policiesPage)),
  http.get("*/api/v1/templates", () => HttpResponse.json(templatesPage)),
  http.get("*/api/v1/risk-events/:id", ({ params }) => {
    const e = allEvents.find((x) => x.id === params.id);
    return e ? HttpResponse.json(e) : HttpResponse.json({ error: "事件不存在" }, { status: 404 });
  }),
];
