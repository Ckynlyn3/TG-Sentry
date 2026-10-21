// Keep the emitted element spelling aligned with internal/server/console_csp.go.
export function inlineThemeInit(html: string, source: string): string {
  // WHATWG HTML §13.2.3.5 normalizes CRLF/CR to LF before the browser hashes text.
  const script = source.replace(/\r\n?/g, "\n");
  return html.replace(
    '<script src="/theme-init.js"></script>',
    () => `<script id="theme-init">${script}</script>`,
  );
}
