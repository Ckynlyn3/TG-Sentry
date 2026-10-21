import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { server } from "../../test/setup";
import { me } from "../../test/fixtures";
import { axeViolations, renderApp, screen } from "../../test/render";

const grant = { grantId: "grant-1", userCode: "BCDF-GHJK", name: "研发笔记本", platform: "linux", source: "127.0.0.1", status: "pending", associatedUser: null };
let lookups: unknown[] = [];
let decisions: unknown[] = [];

beforeEach(() => {
  lookups = [];
  decisions = [];
  server.use(
    http.post("*/api/v1/device-grants/lookup", async ({ request }) => {
      lookups.push(await request.json());
      return HttpResponse.json(grant, { headers: { ETag: '"grant-tag"' } });
    }),
    http.post("*/api/v1/device-grants/decision", async ({ request }) => {
      const body = await request.json();
      // #72 U4: the reviewed lookup ETag must be sent back as If-Match.
      expect(request.headers.get("If-Match")).toBe('"grant-tag"');
      decisions.push(body);
      const decision = typeof body === "object" && body !== null && "decision" in body ? body.decision : undefined;
      return HttpResponse.json({ grantId: grant.grantId, status: decision === "approve" ? "approved" : "denied" });
    }),
  );
});

async function review(path = "/device?user_code=bcdfghjk") {
  const app = await renderApp(path);
  await userEvent.click(await screen.findByRole("button", { name: "查看设备" }));
  await screen.findByRole("heading", { name: "核对发起设备" });
  return app;
}

const confirmCode = () => screen.getByRole("checkbox", { name: /我已核对.*BCDF-GHJK/ });

describe("#40 device verification at /device", () => {
  it("prefills user_code but performs no lookup or approval on navigation; entry is labelled and axe clean", async () => {
    const { container } = await renderApp("/device?user_code=bcdf-ghjk");
    const input = await screen.findByRole("textbox", { name: "验证码" });
    expect(input).toHaveValue("bcdf-ghjk");
    expect(lookups).toEqual([]);
    expect(decisions).toEqual([]);
    expect(screen.queryByRole("button", { name: "批准" })).toBeNull();
    expect(await axeViolations(container)).toEqual([]);
  });
  it("supports manual entry, normalizes ASCII case/hyphen and requires displayed-code confirmation before either action", async () => {
    const user = userEvent.setup();
    const { container } = await renderApp("/device");
    await user.type(await screen.findByRole("textbox", { name: "验证码" }), "bcdf-ghjk");
    await user.keyboard("{Enter}");
    const heading = await screen.findByRole("heading", { name: "核对发起设备" });
    expect(heading).toHaveFocus();
    expect(lookups).toEqual([{ userCode: grant.userCode }]);
    expect(screen.getByText(grant.name)).toBeInTheDocument();
    expect(screen.getByText(grant.platform)).toBeInTheDocument();
    expect(screen.getByText(grant.source)).toBeInTheDocument();
    expect(screen.getByText(/设备名称和平台由发起设备填写/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "批准" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "拒绝" })).toBeDisabled();
    await user.keyboard("{Enter}"); // the review heading is not a default submit action
    expect(decisions).toEqual([]);
    expect(await axeViolations(container)).toEqual([]);
    await user.click(confirmCode());
    expect(screen.getByRole("button", { name: "批准" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "拒绝" })).toBeEnabled();
  });
  it.each(["approve", "deny"])("records %s only after explicit action; terminal heading is focused and announced", async (decision) => {
    const { container } = await review();
    const user = userEvent.setup();
    await user.click(confirmCode());
    await user.click(screen.getByRole("button", { name: decision === "approve" ? "批准" : "拒绝" }));
    const heading = await screen.findByRole("heading", { name: decision === "approve" ? "已批准设备请求" : "已拒绝设备请求" });
    expect(heading).toHaveFocus();
    expect(decisions).toEqual([{ grantId: grant.grantId, decision }]);
    expect(screen.getByRole("status", { name: "设备请求状态" })).toHaveTextContent(heading.textContent ?? "");
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("button", { name: "批准" })).toBeNull();
    expect(await axeViolations(container)).toEqual([]);
  });
  it.each(["readonly", "auditor"])("denies the %s role before any lookup", async (role) => {
    server.use(http.get("*/api/v1/me", () => HttpResponse.json({ ...me, role })));
    const { container } = await renderApp("/device?user_code=BCDF-GHJK");
    expect(await screen.findByRole("heading", { name: "需要管理员权限" })).toHaveFocus();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(lookups).toEqual([]);
    expect(decisions).toEqual([]);
    expect(await axeViolations(container)).toEqual([]);
  });
  it("denies a CLI session even when its role is admin", async () => {
    server.use(http.get("*/api/v1/me", () => HttpResponse.json({ ...me, role: "admin", kind: "cli" })));
    await renderApp("/device");
    expect(await screen.findByRole("heading", { name: "需要管理员权限" })).toHaveFocus();
    expect(screen.queryByRole("button", { name: "查看设备" })).toBeNull();
    expect(lookups).toEqual([]);
  });
  it("uses the existing login guard and preserves the prefilled return URI", async () => {
    server.use(http.get("*/api/v1/me", () => HttpResponse.json({ error: "unauthorized" }, { status: 401 })));
    const { router } = await renderApp("/device?user_code=bcdf-ghjk");
    await screen.findByRole("heading", { name: "登录控制台" });
    expect(router.state.location.search).toEqual({ redirect: "/device?user_code=bcdf-ghjk" });
    expect(lookups).toEqual([]);
  });
  it("rejects invalid input locally, links the error to the field, and allows correction", async () => {
    const user = userEvent.setup();
    await renderApp("/device?user_code=BCDF-1234");
    const input = await screen.findByRole("textbox", { name: "验证码" });
    await user.click(screen.getByRole("button", { name: "查看设备" }));
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveFocus();
    expect(screen.getByRole("alert")).toHaveTextContent("请输入设备上显示的 8 位字母验证码");
    expect(lookups).toEqual([]);
    await user.clear(input);
    await user.type(input, "BCDFGHJK");
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { name: "核对发起设备" })).toBeInTheDocument();
  });
  it.each(["approved", "denied", "consumed", "expired"])("does not offer a decision for lookup status %s", async (status) => {
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json({ ...grant, status }, { headers: { ETag: '"grant-tag"' } })));
    await renderApp("/device?user_code=BCDF-GHJK");
    await userEvent.click(await screen.findByRole("button", { name: "查看设备" }));
    const title = status === "expired" ? "验证码无效或已过期" : status === "approved" ? "已批准设备请求" : status === "denied" ? "已拒绝设备请求" : "请求已处理";
    expect(await screen.findByRole("heading", { name: title })).toHaveFocus();
    expect(screen.queryByRole("button", { name: "批准" })).toBeNull();
    expect(decisions).toEqual([]);
  });
  it.each([404, 403, 500])("shows lookup HTTP %s as an explicit outcome", async (status) => {
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json({ error: "refused" }, { status })));
    const { container } = await renderApp("/device?user_code=BCDF-GHJK");
    await userEvent.click(await screen.findByRole("button", { name: "查看设备" }));
    expect(await screen.findByRole("heading", { name: status === 404 ? "验证码无效或已过期" : status === 403 ? "需要管理员权限" : "无法完成请求" })).toHaveFocus();
    expect(decisions).toEqual([]);
    expect(await axeViolations(container)).toEqual([]);
  });
  it.each([404, 409, 403, 500])("shows decision HTTP %s without retrying the decision", async (status) => {
    let calls = 0;
    server.use(http.post("*/api/v1/device-grants/decision", () => { calls++; return HttpResponse.json({ error: "refused" }, { status }); }));
    await review();
    await userEvent.click(confirmCode());
    await userEvent.click(screen.getByRole("button", { name: "批准" }));
    expect(await screen.findByRole("heading", { name: status === 404 ? "验证码无效或已过期" : status === 409 ? "请求已处理" : status === 403 ? "需要管理员权限" : "无法完成请求" })).toHaveFocus();
    expect(calls).toBe(1);
    expect(screen.queryByRole("button", { name: "批准" })).toBeNull();
  });
  it("explains an uncertain network result and requires a fresh lookup, never automatic approval retry", async () => {
    let calls = 0;
    server.use(http.post("*/api/v1/device-grants/decision", () => { calls++; return HttpResponse.error(); }));
    await review();
    await userEvent.click(confirmCode());
    await userEvent.click(screen.getByRole("button", { name: "批准" }));
    await screen.findByRole("heading", { name: "无法完成请求" });
    expect(screen.getByText(/决定可能已经保存/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "重试" }));
    expect(await screen.findByRole("textbox", { name: "验证码" })).toHaveValue("bcdfghjk");
    expect(calls).toBe(1);
  });
  it("sends an expired session back through SSO with the entered code preserved", async () => {
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json({ error: "unauthorized" }, { status: 401 })));
    const { router } = await renderApp("/device");
    await userEvent.type(await screen.findByRole("textbox", { name: "验证码" }), "BCDF-GHJK");
    await userEvent.click(screen.getByRole("button", { name: "查看设备" }));
    await screen.findByRole("heading", { name: "登录控制台" });
    expect(router.state.location.search).toEqual({ redirect: "/device?user_code=BCDF-GHJK" });
  });
  it("prevents double lookup submissions while the first request is pending", async () => {
    let complete = () => {};
    const pending = new Promise<void>((resolve) => { complete = resolve; });
    server.use(http.post("*/api/v1/device-grants/lookup", async ({ request }) => {
      lookups.push(await request.json());
      await pending;
      return HttpResponse.json(grant, { headers: { ETag: '"grant-tag"' } });
    }));
    await renderApp("/device?user_code=BCDF-GHJK");
    const input = await screen.findByRole("textbox", { name: "验证码" });
    const form = input.closest("form");
    expect(form).not.toBeNull();
    if (!form) throw new Error("missing code-entry form");
    fireEvent.submit(form);
    fireEvent.submit(form);
    await waitFor(() => expect(lookups).toHaveLength(1));
    expect(input).toBeDisabled();
    complete();
    await screen.findByRole("heading", { name: "核对发起设备" });
  });
  it("displays an unassociated device and a verified associated account", async () => {
    const app = await review();
    expect(screen.getByText("未关联账号")).toBeInTheDocument();
    app.unmount();
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json({ ...grant, associatedUser: { issuer: "https://idp.example", subject: "employee-1", name: "张三" } }, { headers: { ETag: '"associated-tag"' } })));
    await review();
    expect(screen.getByText("张三 (employee-1)")).toBeInTheDocument();
    expect(screen.getByText("https://idp.example")).toBeInTheDocument();
  });
  it("requires a fresh lookup and new confirmation after a late association (412), with no automatic retry", async () => {
    let calls = 0;
    const tags: (string | null)[] = [];
    server.use(http.post("*/api/v1/device-grants/decision", ({ request }) => {
      tags.push(request.headers.get("If-Match")); calls++;
      return calls === 1 ? HttpResponse.json({ error: "device grant changed; review again" }, { status: 412 }) : HttpResponse.json({ grantId: grant.grantId, status: "approved" });
    }));
    await review();
    expect(screen.getByText("未关联账号")).toBeInTheDocument();
    await userEvent.click(confirmCode());
    await userEvent.click(screen.getByRole("button", { name: "批准" }));
    expect(await screen.findByRole("heading", { name: "设备请求已变更" })).toBeInTheDocument();
    expect(calls).toBe(1); expect(lookups).toHaveLength(1);
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json({ ...grant, associatedUser: { issuer: "https://idp.example", subject: "employee-1", name: "张三" } }, { headers: { ETag: '"fresh-tag"' } })));
    await userEvent.click(screen.getByRole("button", { name: "重新查询设备" }));
    await screen.findByRole("heading", { name: "核对发起设备" });
    expect(screen.getByText("张三 (employee-1)")).toBeInTheDocument();
    expect(confirmCode()).not.toBeChecked();
    expect(screen.getByRole("button", { name: "批准" })).toBeDisabled();
    expect(calls).toBe(1);
    await userEvent.click(confirmCode());
    await userEvent.click(screen.getByRole("button", { name: "批准" }));
    await screen.findByRole("heading", { name: "已批准设备请求" });
    expect(tags).toEqual(['"grant-tag"', '"fresh-tag"']);
  });
  it("prevents double decision submissions including approve/deny racing", async () => {
    let complete = () => {};
    const pending = new Promise<void>((resolve) => { complete = resolve; });
    server.use(http.post("*/api/v1/device-grants/decision", async ({ request }) => {
      decisions.push(await request.json());
      await pending;
      return HttpResponse.json({ grantId: grant.grantId, status: "approved" });
    }));
    await review();
    await userEvent.click(confirmCode());
    const approve = screen.getByRole("button", { name: "批准" });
    fireEvent.click(approve);
    fireEvent.click(approve);
    fireEvent.click(screen.getByRole("button", { name: "拒绝" }));
    await waitFor(() => expect(decisions).toHaveLength(1));
    expect(approve).toBeDisabled();
    expect(confirmCode()).toBeDisabled();
    complete();
    await screen.findByRole("heading", { name: "已批准设备请求" });
  });
  it("lets the operator leave review for another code with confirmation reset", async () => {
    await review();
    await userEvent.click(confirmCode());
    await userEvent.click(screen.getByRole("button", { name: "输入其他验证码" }));
    await userEvent.click(await screen.findByRole("button", { name: "查看设备" }));
    await screen.findByRole("heading", { name: "核对发起设备" });
    expect(confirmCode()).not.toBeChecked();
    expect(screen.getByRole("button", { name: "批准" })).toBeDisabled();
  });
  it("renders endpoint-supplied metadata as text, not markup", async () => {
    const name = '<img src=x onerror="alert(1)">';
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json({ ...grant, name }, { headers: { ETag: '"grant-tag"' } })));
    await review();
    expect(screen.getByText(name)).toBeInTheDocument();
    expect(screen.queryByRole("img")).toBeNull();
  });
  it("shows a lookup network failure without retrying or exposing decision controls", async () => {
    let calls = 0;
    server.use(http.post("*/api/v1/device-grants/lookup", () => { calls++; return HttpResponse.error(); }));
    await renderApp("/device?user_code=BCDF-GHJK");
    await userEvent.click(await screen.findByRole("button", { name: "查看设备" }));
    expect(await screen.findByRole("heading", { name: "无法完成请求" })).toHaveFocus();
    expect(calls).toBe(1);
    expect(screen.queryByRole("button", { name: "批准" })).toBeNull();
  });
  it("fails closed when the lookup response breaks the frozen contract", async () => {
    server.use(http.post("*/api/v1/device-grants/lookup", () => HttpResponse.json({ ...grant, status: "new-status" })));
    await renderApp("/device?user_code=BCDF-GHJK");
    await userEvent.click(await screen.findByRole("button", { name: "查看设备" }));
    expect(await screen.findByRole("heading", { name: "无法完成请求" })).toHaveFocus();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(decisions).toEqual([]);
  });
  it("has an English device verification locale", async () => {
    await renderApp("/device");
    await userEvent.click(await screen.findByRole("button", { name: "语言：简体中文。切换到 English" }));
    expect(await screen.findByRole("heading", { name: "Verify a device", level: 1 })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "User code" })).toBeInTheDocument();
  });
});

describe("#72 S2 grant-bound association continuation at /device/associate", () => {
  const preview = {
    grant: { grantId: "grant-1", userCode: "BCDF-GHJK", name: "研发笔记本", platform: "linux", source: "127.0.0.1", status: "pending", associatedUser: null },
    user: { issuer: "https://idp.example", subject: "employee-1", name: "张三" },
    confirmation: "preview-token",
  };
  it("lets a roleless verified employee confirm the server-bound device without any admin authority", async () => {
    const confirmed: unknown[] = [];
    server.use(
      http.get("*/api/v1/me", () => HttpResponse.json({ ...me, role: "", kind: "human" })),
      http.get("*/api/v1/device-grants/association/confirm", () => HttpResponse.json(preview)),
      http.post("*/api/v1/device-grants/association/confirm", async ({ request }) => {
        confirmed.push(await request.json());
        return HttpResponse.json({ ...preview.grant, associatedUser: preview.user });
      }),
    );
    const { container } = await renderApp("/device/associate?continuation=confirm");
    const heading = await screen.findByRole("heading", { name: "确认这台设备" });
    expect(heading).toHaveFocus();
    // The verified account and the server-selected device are shown; no grant selector exists.
    expect(screen.getByText("张三 (employee-1)")).toBeInTheDocument();
    expect(screen.getByText("研发笔记本")).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("button", { name: "批准" })).toBeNull();
    expect(lookups).toEqual([]);
    expect(await axeViolations(container)).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: "确认这是我的设备" }));
    expect(await screen.findByRole("heading", { name: "设备已确认" })).toBeInTheDocument();
    // Confirmation carries the flag and preview token, never an identity or a grant id.
    expect(confirmed).toEqual([{ confirm: true, confirmation: "preview-token" }]);
  });
  it("shows the unbound/expired denial instead of the console and never confirms", async () => {
    let posts = 0;
    server.use(
      http.get("*/api/v1/device-grants/association/confirm", () => HttpResponse.json({ error: "grant-bound association continuation required" }, { status: 403 })),
      http.post("*/api/v1/device-grants/association/confirm", () => { posts++; return HttpResponse.json({ error: "refused" }, { status: 403 }); }),
    );
    await renderApp("/device/associate?continuation=confirm");
    expect(await screen.findByRole("heading", { name: "设备确认已失效" })).toHaveFocus();
    expect(screen.queryByRole("button", { name: "确认这是我的设备" })).toBeNull();
    expect(posts).toBe(0);
  });
  it("shows the restart guidance for an expired session instead of redirecting a roleless employee to console login", async () => {
    server.use(
      http.get("*/api/v1/me", () => HttpResponse.json({ error: "unauthorized" }, { status: 401 })),
      http.get("*/api/v1/device-grants/association/confirm", () => HttpResponse.json({ error: "unauthorized" }, { status: 401 })),
    );
    const { router } = await renderApp("/device/associate?continuation=confirm");
    expect(await screen.findByRole("heading", { name: "设备确认已失效" })).toHaveFocus();
    expect(screen.getByRole("link", { name: "重新输入设备验证码" })).toHaveAttribute("href", "/device/associate");
    expect(router.state.location.pathname).toBe("/device/associate");
  });
  it("treats a decided or expired bound grant as no longer confirmable", async () => {
    server.use(http.get("*/api/v1/device-grants/association/confirm", () => HttpResponse.json({ error: "device grant already decided" }, { status: 409 })));
    await renderApp("/device/associate?continuation=confirm");
    expect(await screen.findByRole("heading", { name: "设备确认已失效" })).toHaveFocus();
    expect(screen.queryByRole("button", { name: "确认这是我的设备" })).toBeNull();
  });
});

 it("offers an unguarded employee code entry with a native begin form", async () => {
   const { container } = await renderApp("/device/associate");
   expect(await screen.findByRole("textbox", { name: "验证码" })).toBeInTheDocument();
   expect(screen.getByRole("button", { name: "继续登录" })).toBeInTheDocument();
   expect(container.querySelector("form")).toHaveAttribute("action", "/api/v1/device-grants/association/begin");
   expect(container.querySelector("form")).toHaveAttribute("method", "post");
   expect(await axeViolations(container)).toEqual([]);
 });
