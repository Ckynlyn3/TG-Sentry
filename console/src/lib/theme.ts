import { useEffect, useState } from "react";

// Light and dark are both first-class (design §11): default follows prefers-color-scheme, an explicit
// choice persists. public/theme-init.js applies the same rule before first paint.
export type Theme = "light" | "dark";
const KEY = "tgs-theme";
const media = () => window.matchMedia("(prefers-color-scheme: dark)");

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === "dark" || v === "light" ? v : null;
  } catch {
    return null;
  }
}

const apply = (t: Theme) => {
  document.documentElement.dataset.theme = t;
};

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(() => stored() ?? (media().matches ? "dark" : "light"));
  useEffect(() => apply(theme), [theme]);
  useEffect(() => {
    const m = media();
    const onChange = () => {
      if (!stored()) setTheme(m.matches ? "dark" : "light");
    };
    m.addEventListener("change", onChange);
    return () => m.removeEventListener("change", onChange);
  }, []);
  const toggle = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    try {
      localStorage.setItem(KEY, next);
    } catch {
      /* storage blocked: the choice still applies for this page */
    }
    setTheme(next);
    return next;
  };
  return { theme, toggle };
}
