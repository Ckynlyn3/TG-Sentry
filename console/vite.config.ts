/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import { readFileSync } from "node:fs";
import react from "@vitejs/plugin-react";
import { inlineThemeInit } from "./inline-theme-init";
import { emittedStylesheetPath, inlineStyles } from "./inline-styles";

// Dev only: proxy the API to a local control plane on its default address (cmd/aegishook/cli.go:
// --host 127.0.0.1 --port 18790). The server rejects a foreign Origin, so the proxy drops it.
export default defineConfig({
  plugins: [
    react(),
    {
      name: "inline-theme-init",
      apply: "build",
      // Vite transformIndexHtml pre hook preserves this classic script before first paint.
      // The server hashes the emitted text, not this source (CSP3 §2.3.1 hash-source).
      transformIndexHtml: {
        order: "pre",
        handler: (html) => inlineThemeInit(html, readFileSync(new URL("./public/theme-init.js", import.meta.url), "utf8")),
      },
    },
    {
      name: "inline-styles",
      apply: "build",
      // Post hook: Vite has injected the hashed stylesheet link. Inlining its asset removes the
      // last render-blocking request from the first paint (#92); the emitted element changes but
      // no script markup does, so the CSP script-hash layout in internal/server/console_csp.go
      // is unaffected. The emitted FILE is kept: lazy chunks' dependency maps still preload it
      // (OverviewPage → assets/index-*.css) — deleting it 404s behind the SPA fallback and the
      // lazy surface fails on the nosniff HTML answer (#92 R1 review).
      transformIndexHtml: {
        order: "post",
        handler: (html, ctx) => {
          const path = emittedStylesheetPath(html);
          const asset = path ? ctx.bundle?.[path] : undefined;
          if (!path || !asset || asset.type !== "asset" || typeof asset.source !== "string") return html;
          return inlineStyles(html, asset.source);
        },
      },
    },
  ],
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:18790",
        changeOrigin: true,
        configure: (proxy) => proxy.on("proxyReq", (req) => req.removeHeader("origin")),
      },
    },
  },
  build: { target: "es2022", sourcemap: false },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
  },
});
