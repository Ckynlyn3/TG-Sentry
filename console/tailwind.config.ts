import type { Config } from "tailwindcss";

// Tailwind over the design-contract CSS variables (docs/design/CONSOLE-DESIGN.md §9).
// Utilities resolve to semantic tokens only; raw palette values live in src/styles/tokens.css.
const v = (name: string) => `var(--${name})`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    borderRadius: { none: "0", DEFAULT: v("radius"), full: "9999px" },
    colors: {
      transparent: "transparent",
      current: "currentColor",
      surface: { canvas: v("surface-canvas"), 1: v("surface-1"), 2: v("surface-2"), sunken: v("surface-sunken") },
      text: { primary: v("text-primary"), secondary: v("text-secondary"), tertiary: v("text-tertiary") },
      border: { subtle: v("border-subtle"), strong: v("border-strong") },
      brand: { DEFAULT: v("brand"), soft: v("brand-soft") },
      status: { block: v("status-block"), alert: v("status-alert"), ok: v("status-ok"), unknown: v("status-unknown") },
    },
    spacing: { 0: "0", 1: v("s-1"), 2: v("s-2"), 3: v("s-3"), 4: v("s-4"), 5: v("s-5"), 6: v("s-6"), 7: v("s-7"), 8: v("s-8"), 9: v("s-9") },
    fontFamily: { sans: v("font-sans"), mono: v("font-mono") },
    fontSize: {
      label: [v("type-label"), v("lead-label")],
      ui: [v("type-ui"), v("lead-ui")],
      section: [v("type-section"), v("lead-section")],
      page: [v("type-page"), v("lead-page")],
    },
    extend: {},
  },
  plugins: [],
} satisfies Config;
