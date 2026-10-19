import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import zhCN from "./zh-CN";
import en from "./en";

export type Lang = "zh-CN" | "en";
const KEY = "tgs-lang";

function initialLang(): Lang {
  try {
    return localStorage.getItem(KEY) === "en" ? "en" : "zh-CN";
  } catch {
    return "zh-CN";
  }
}

i18n.on("languageChanged", (lng) => {
  document.documentElement.lang = lng;
  document.title = i18n.t("app.title");
});

void i18n.use(initReactI18next).init({
  resources: { "zh-CN": { translation: zhCN }, en: { translation: en } },
  lng: initialLang(),
  fallbackLng: "zh-CN",
  nsSeparator: false, // keys contain "category::…" (the #10 category ids)
  interpolation: { escapeValue: false }, // React escapes output
});

export function setLanguage(lng: Lang) {
  try {
    localStorage.setItem(KEY, lng);
  } catch {
    /* storage blocked: applies to this page only */
  }
  void i18n.changeLanguage(lng);
}

export default i18n;
