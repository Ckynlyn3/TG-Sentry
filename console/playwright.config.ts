import { defineConfig } from "@playwright/test";

// Runs against the production bundle (`vite preview` of dist/); the API is answered by test-only
// fixtures through page.route. PLAYWRIGHT_CHROMIUM lets a machine reuse an installed Chromium, the
// same mechanism as AegisHook's web/playwright.config.ts (AEGIS_CHROMIUM).
export default defineConfig({
  testDir: "e2e",
  workers: 1,
  reporter: "list",
  outputDir: "test-results",
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined },
  },
  webServer: { command: "npm run preview", url: "http://127.0.0.1:4173", reuseExistingServer: !process.env.CI },
});
