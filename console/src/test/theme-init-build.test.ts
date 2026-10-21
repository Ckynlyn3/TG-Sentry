import { describe, expect, test } from "vitest";
import { inlineThemeInit } from "../../inline-theme-init";

describe("production theme initializer", () => {
  test("normalizes CRLF and CR so emitted script bytes match HTML-parsed text", () => {
    const source = '// theme\r\ndocument.documentElement.dataset.theme = "dark";\r';
    const html = inlineThemeInit('<script src="/theme-init.js"></script>', source);
    const emitted = html.match(/<script id="theme-init">([\s\S]*?)<\/script>/)?.[1];
    const parsed = new DOMParser().parseFromString(html, "text/html").querySelector("script")?.textContent;
    expect(emitted).toBe('// theme\ndocument.documentElement.dataset.theme = "dark";\n');
    expect(emitted).toBe(parsed);
    expect(html).not.toContain('src="/theme-init.js"');
  });
});
