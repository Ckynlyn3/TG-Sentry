// Applies the stored or system theme before first paint. External file because the control
// plane CSP is default-src 'self' (no inline scripts). Same key as the design mockups.
(function () {
  var t = null;
  try { t = localStorage.getItem("tgs-theme"); } catch (e) {}
  if (t !== "dark" && t !== "light") t = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.dataset.theme = t;
  try { var l = localStorage.getItem("tgs-lang"); if (l === "en") document.documentElement.lang = "en"; } catch (e) {}
})();
