// Vite emits exactly one stylesheet link of this spelling; only that element is render-blocking.
const emittedStylesheetLink = /<link rel="stylesheet" crossorigin href="\/assets\/[^"]+\.css">/;

// Inlines the production stylesheet into the document head, removing the only render-blocking
// request from the first paint (web.dev/articles/render-blocking-resources). Critters-style
// critical-CSS extraction inlines only what its (default 0 kB) thresholds keep
// (https://github.com/GoogleChromeLabs/critters#properties); inlining the WHOLE 33 kB sheet here
// is a measured local choice for this app, not a universal critical-CSS practice.
// CSP: style-src 'self' 'unsafe-inline' (internal/server/console_csp.go) already permits this.
export function inlineStyles(html: string, source: string): string {
  return html.replace(emittedStylesheetLink, () => `<style>${source}</style>`);
}

export function emittedStylesheetPath(html: string): string | undefined {
  return html.match(emittedStylesheetLink)?.[0].match(/href="\/([^"]+)"/)?.[1];
}
