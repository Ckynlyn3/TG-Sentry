import "@testing-library/jest-dom/vitest";
import { afterAll, afterEach, beforeAll } from "vitest";
import { cleanup } from "@testing-library/react";
import { setupServer } from "msw/node";
import { handlers, requests } from "./handlers";

export const server = setupServer(...handlers);

// jsdom lacks matchMedia and ResizeObserver (Radix Popover measures its anchor).
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false, media: query, onchange: null,
    addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
  }),
});
// TanStack Router scroll restoration calls scrollTo; axe probes canvas. Neither exists in jsdom.
window.scrollTo = () => {};
HTMLCanvasElement.prototype.getContext = () => null;
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} };

let nativeFetch: typeof fetch;
beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
  // Node's fetch has no document base URL; resolve the app's same-origin paths like a browser would.
  nativeFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => nativeFetch(typeof input === "string" && input.startsWith("/") ? new URL(input, window.location.origin) : input, init);
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  requests.length = 0;
  localStorage.clear();
});
afterAll(() => {
  globalThis.fetch = nativeFetch;
  server.close();
});
