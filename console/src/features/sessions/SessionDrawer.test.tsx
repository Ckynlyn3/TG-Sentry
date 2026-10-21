import { beforeEach, describe, expect, it } from "vitest";
import { delay, http, HttpResponse } from "msw";
import { waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { axeViolations, renderApp, screen } from "../../test/render";
import { callItems, callsForSession, sessionSummaries } from "../../test/fixtures";

const SESSION_KEY = sessionSummaries.items[0]!.sessionId;
const callRequests: URL[] = [];

beforeEach(() => {
  callRequests.length = 0;
  server.use(
    http.get("*/api/v1/calls", ({ request }) => {
      callRequests.push(new URL(request.url));
      return HttpResponse.json(callsForSession);
    }),
  );
});

describe("session evidence drawer", () => {
  it("opens from a session row, shows paired evidence and script metadata, and Esc restores focus", async () => {
    const payload = "<script>alert(1)</script>";
    server.use(
      http.get("*/api/v1/calls", ({ request }) => {
        callRequests.push(new URL(request.url));
        return HttpResponse.json({
          ...callsForSession,
          items: [{ ...callItems.captured, result: payload, scriptFiles: [{ path: "run.sh", sha256: "ab", bytes: 3, complete: true }] }],
          total: 1,
          pendingTotal: 0,
        });
      }),
    );
    const { router } = await renderApp("/sessions");
    const opener = await screen.findByRole("link", { name: SESSION_KEY });
    await userEvent.click(opener);
    const d = await screen.findByRole("dialog", { name: "会话证据" });

    expect(router.state.location.search).toEqual({ open: SESSION_KEY });
    expect(callRequests).toHaveLength(1);
    expect(Object.fromEntries(callRequests[0]!.searchParams)).toEqual({ sessionKey: SESSION_KEY, page: "1", size: "20" });
    await waitFor(() => expect(within(d).getByRole("button", { name: "关闭会话证据" })).toHaveFocus());

    const table = within(d).getByRole("table", { name: "会话调用记录" });
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["调用", "输入", "结果", "决策", "执行"]);
    const row = within(table).getAllByRole("row")[1]!;
    expect(row).toHaveTextContent("Bash");
    expect(row).toHaveTextContent("ls -la");
    expect(row).toHaveTextContent("列出文件");
    expect(within(row).getAllByText("已记录")).toHaveLength(2);
    expect(row).toHaveTextContent("已批准");
    expect(row).toHaveTextContent("执行成功");
    expect(row).toHaveTextContent("run.sh");
    expect(row).toHaveTextContent("ab");
    expect(row).toHaveTextContent("3 字节");
    expect(row).toHaveTextContent("完整");
    expect(d).toHaveTextContent(payload);
    expect(d.querySelector("script")).toBeNull();
    expect(within(d).queryByRole("tab")).toBeNull();
    expect(await axeViolations(document.body)).toEqual([]);

    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(router.state.location.search).toEqual({});
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it("shows restricted input and output as state badges while retaining allowed script metadata", async () => {
    server.use(
      http.get("*/api/v1/calls", () =>
        HttpResponse.json({
          ...callsForSession,
          items: [{ ...callItems.restricted, scriptFiles: [{ path: "run.sh", sha256: "ab", bytes: 3, complete: true }] }],
          total: 1,
          pendingTotal: 0,
        }),
      ),
    );
    await renderApp("/sessions");
    await userEvent.click(await screen.findByRole("link", { name: SESSION_KEY }));
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    const row = within(d).getAllByRole("row")[1]!;
    expect(within(row).getAllByText("无权查看")).toHaveLength(2);
    expect(row).toHaveTextContent("run.sh");
    expect(row).toHaveTextContent("3 字节");
  });

  it.each([
    ["argumentsObj", { argumentsObj: { command: "SENTINEL_restricted_arguments" } }, "SENTINEL_restricted_arguments"],
    ["userMessage", { userMessage: "SENTINEL_restricted_message" }, "SENTINEL_restricted_message"],
    ["context", { context: "SENTINEL_restricted_context" }, "SENTINEL_restricted_context"],
    ["modelContext", { modelContext: "SENTINEL_restricted_model_context" }, "SENTINEL_restricted_model_context"],
    ["modelInput", { modelInput: { messages: [{ content: "SENTINEL_restricted_model_input" }] } }, "SENTINEL_restricted_model_input"],
    [
      "scriptFiles.content",
      { scriptFiles: [{ path: "run.sh", sha256: "ab", bytes: 3, complete: true, content: "SENTINEL_restricted_script" }] },
      "SENTINEL_restricted_script",
    ],
    ["result", { result: "SENTINEL_restricted_result" }, "SENTINEL_restricted_result"],
  ])("rejects restricted %s without rendering its sentinel", async (_field, leak, sentinel) => {
    server.use(
      http.get("*/api/v1/calls", () =>
        HttpResponse.json({ ...callsForSession, items: [{ ...callItems.restricted, ...leak }], total: 1, pendingTotal: 0 }),
      ),
    );
    await renderApp(`/sessions?open=${SESSION_KEY}`);
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    expect(await within(d).findByRole("alert")).toHaveTextContent("服务返回的数据不符合事件约定");
    expect(d).not.toHaveTextContent(sentinel);
  });

  it("hides every populated input field when input is policy_omitted", async () => {
    const sentinels = ["SENTINEL_omitted_input_arguments", "SENTINEL_omitted_input_message", "SENTINEL_omitted_input_context"];
    server.use(
      http.get("*/api/v1/calls", () =>
        HttpResponse.json({
          ...callsForSession,
          items: [
            {
              ...callItems.captured,
              inputState: "policy_omitted",
              outputState: "captured",
              argumentsObj: { command: sentinels[0] },
              userMessage: sentinels[1],
              context: sentinels[2],
              result: "VISIBLE_output",
            },
          ],
          total: 1,
          pendingTotal: 0,
        }),
      ),
    );
    await renderApp(`/sessions?open=${SESSION_KEY}`);
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    await within(d).findByRole("table", { name: "会话调用记录" });
    expect(d).toHaveTextContent("VISIBLE_output");
    expect(d).toHaveTextContent("按策略省略");
    for (const sentinel of sentinels) expect(d).not.toHaveTextContent(sentinel);
  });

  it("hides a populated result when output is policy_omitted", async () => {
    server.use(
      http.get("*/api/v1/calls", () =>
        HttpResponse.json({
          ...callsForSession,
          items: [
            {
              ...callItems.captured,
              outputState: "policy_omitted",
              argumentsObj: { command: "VISIBLE_input" },
              result: "SENTINEL_omitted_output_result",
            },
          ],
          total: 1,
          pendingTotal: 0,
        }),
      ),
    );
    await renderApp(`/sessions?open=${SESSION_KEY}`);
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    await within(d).findByRole("table", { name: "会话调用记录" });
    expect(d).toHaveTextContent("VISIBLE_input");
    expect(d).toHaveTextContent("按策略省略");
    expect(d).not.toHaveTextContent("SENTINEL_omitted_output_result");
  });

  it("shows a loading status while calls are in flight", async () => {
    server.use(
      http.get("*/api/v1/calls", async () => {
        await delay("infinite");
        return HttpResponse.json(callsForSession);
      }),
    );
    await renderApp(`/sessions?open=${SESSION_KEY}`);
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    expect(within(d).getByRole("status")).toHaveTextContent("正在加载会话证据");
  });

  it("shows an empty state when the session has no calls", async () => {
    server.use(http.get("*/api/v1/calls", () => HttpResponse.json({ ...callsForSession, items: [], total: 0, pendingTotal: 0 })));
    await renderApp(`/sessions?open=${SESSION_KEY}`);
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    expect(await within(d).findByRole("heading", { name: "这个会话还没有调用记录" })).toBeInTheDocument();
  });

  it("shows an error and retries the same session query", async () => {
    let fail = true;
    server.use(
      http.get("*/api/v1/calls", ({ request }) => {
        callRequests.push(new URL(request.url));
        return fail ? HttpResponse.json({ error: "synthetic failure" }, { status: 500 }) : HttpResponse.json(callsForSession);
      }),
    );
    await renderApp(`/sessions?open=${SESSION_KEY}`);
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    expect(await within(d).findByRole("alert")).toHaveTextContent("会话证据没有加载出来");
    fail = false;
    await userEvent.click(within(d).getByRole("button", { name: "重试" }));
    expect(await within(d).findByRole("table", { name: "会话调用记录" })).toBeInTheDocument();
    expect(callRequests).toHaveLength(2);
    expect(callRequests[1]!.searchParams.get("sessionKey")).toBe(SESSION_KEY);
  });

  it("pages through all calls and resets to page 1 when the session changes", async () => {
    const otherKey = sessionSummaries.items[1]!.sessionId;
    const firstPage = Array.from({ length: 20 }, (_, index) => ({
      ...callItems.captured,
      id: `rev-page-1-${index}`,
      result: `FIRST_PAGE_RESULT_${index}`,
    }));
    const secondPage = [{ ...callItems.captured, id: "rev-page-2", toolName: "Read", result: "SECOND_PAGE_RESULT" }];
    server.use(
      http.get("*/api/v1/calls", ({ request }) => {
        const url = new URL(request.url);
        callRequests.push(url);
        const page = Number(url.searchParams.get("page"));
        return HttpResponse.json({ ...callsForSession, items: page === 1 ? firstPage : secondPage, total: 21, page, pageSize: 20, pendingTotal: 0 });
      }),
    );
    await renderApp("/sessions");
    await userEvent.click(await screen.findByRole("link", { name: SESSION_KEY }));
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    await within(d).findByRole("table", { name: "会话调用记录" });
    expect(d).toHaveTextContent("第 1–20 条，共 21 条");
    expect(within(d).queryByRole("button", { name: "上一页" })).toBeNull();

    await userEvent.click(within(d).getByRole("button", { name: "下一页" }));
    await within(d).findByText("SECOND_PAGE_RESULT");
    expect(d).toHaveTextContent("第 21–21 条，共 21 条");
    expect(within(d).queryByRole("button", { name: "下一页" })).toBeNull();
    expect(callRequests.at(-1)?.searchParams.get("page")).toBe("2");

    await userEvent.click(within(d).getByRole("button", { name: "上一页" }));
    await within(d).findByText("FIRST_PAGE_RESULT_0");
    await userEvent.click(within(d).getByRole("button", { name: "下一页" }));
    await within(d).findByText("SECOND_PAGE_RESULT");
    await userEvent.click(within(d).getByRole("button", { name: "关闭会话证据" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    await userEvent.click(await screen.findByRole("link", { name: otherKey }));
    const other = await screen.findByRole("dialog", { name: "会话证据" });
    await within(other).findByText("FIRST_PAGE_RESULT_0");
    expect(Object.fromEntries(callRequests.at(-1)!.searchParams)).toEqual({ sessionKey: otherKey, page: "1", size: "20" });
  });

  it("keeps pagination controls focused while a delayed last page loads", async () => {
    const firstPage = Array.from({ length: 20 }, (_, index) => ({ ...callItems.captured, id: `rev-focus-1-${index}` }));
    const secondPage = [{ ...callItems.captured, id: "rev-focus-2", result: "SECOND_PAGE_RESULT" }];
    let releaseSecondPage: (() => void) | undefined;
    const secondPageReady = new Promise<void>((resolve) => {
      releaseSecondPage = resolve;
    });
    server.use(
      http.get("*/api/v1/calls", async ({ request }) => {
        const page = Number(new URL(request.url).searchParams.get("page"));
        if (page === 2) await secondPageReady;
        return HttpResponse.json({ ...callsForSession, items: page === 1 ? firstPage : secondPage, total: 21, page, pageSize: 20, pendingTotal: 0 });
      }),
    );
    await renderApp("/sessions");
    await userEvent.click(await screen.findByRole("link", { name: SESSION_KEY }));
    const d = await screen.findByRole("dialog", { name: "会话证据" });
    const table = await within(d).findByRole("table", { name: "会话调用记录" });
    const next = within(d).getByRole("button", { name: "下一页" });
    next.focus();
    await userEvent.keyboard("{Enter}");

    try {
      await waitFor(() => expect(next).toBeDisabled());
      expect(table).toHaveAttribute("aria-busy", "true");
      expect(within(d).getByRole("button", { name: "下一页" })).toBe(next);
      expect(document.activeElement).toBe(next);
    } finally {
      releaseSecondPage?.();
    }

    await within(d).findByText("SECOND_PAGE_RESULT");
    const previous = within(d).getByRole("button", { name: "上一页" });
    await waitFor(() => expect(document.activeElement).toBe(previous));
    expect(within(d).queryByRole("button", { name: "下一页" })).toBeNull();
    expect(table).toHaveAttribute("aria-busy", "false");
  });
});
