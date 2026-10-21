// Applies the stored or system theme before first paint. Vite inlines this in production;
// the control plane permits its exact emitted bytes with a CSP hash. External in dev only.
(function () {
  var t = null;
  try { t = localStorage.getItem("tgs-theme"); } catch (e) {}
  if (t !== "dark" && t !== "light") t = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.dataset.theme = t;
  try { var l = localStorage.getItem("tgs-lang"); if (l === "en") document.documentElement.lang = "en"; } catch (e) {}
})();
