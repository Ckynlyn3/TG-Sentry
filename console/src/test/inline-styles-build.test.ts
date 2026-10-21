import { describe, expect, test } from "vitest";
import { inlineStyles } from "../../inline-styles";

describe("production stylesheet inlining", () => {
  const link = '<link rel="stylesheet" crossorigin href="/assets/index-a1b2c3.css">';

  test("replaces the emitted stylesheet link with an inline style element", () => {
    expect(inlineStyles(`<head>${link}</head>`, "body{margin:0}")).toBe("<head><style>body{margin:0}</style></head>");
  });

  test("leaves the document unchanged when the emitted stylesheet link is absent", () => {
    expect(inlineStyles("<head></head>", "x")).toBe("<head></head>");
    const other = '<link rel="stylesheet" href="/assets/index-a1b2c3.css">'; // not Vite's emitted spelling
    expect(inlineStyles(other, "x")).toBe(other);
  });

  test("treats $ sequences in the minified stylesheet as literal text, not replacement patterns", () => {
    const css = "a::after{content:\"$&$`$'\"}";
    expect(inlineStyles(link, css)).toBe(`<style>${css}</style>`);
  });
});
