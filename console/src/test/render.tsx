import { render, screen } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import axe from "axe-core";
import "../i18n";
import i18n from "../i18n";
import { createApp } from "../app";

export async function renderApp(path: string) {
  await i18n.changeLanguage("zh-CN");
  const history = createMemoryHistory({ initialEntries: [path] });
  const { queryClient, router } = createApp(history);
  queryClient.setDefaultOptions({ queries: { ...queryClient.getDefaultOptions().queries, retry: false } });
  const utils = render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { ...utils, router, history, queryClient };
}

// axe in jsdom: structural WCAG 2.x A/AA rules. Colour contrast needs real layout and runs in Playwright.
export async function axeViolations(node: Element = document.body) {
  const r = await axe.run(node, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

export { screen };
