import { useState } from "react";
import { getRouteApi } from "@tanstack/react-router";
import { Moon, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { ssoLoginHref } from "../../lib/api";
import { announce } from "../../lib/announce";
import { useTheme } from "../../lib/theme";
import { setLanguage } from "../../i18n";

const route = getRouteApi("/login");

// M2 SSO sign-in (#12): the console starts the server's OIDC BFF flow by navigating the browser to
// GET /api/v1/auth/login?next=… (ssoLoginHref). The admin-token browser form is removed (AC2); local admin
// break-glass is a server-side CLI bind, not a console form. The hand-off is a direct
// window.location.assign — no client pre-flight: a fetch to the login endpoint would start a spurious OIDC
// transaction (state+nonce+cookie). The server runs the 302 chain and sets the session cookie, or returns
// 503 sso_not_configured, which the server owns (internal/server/oidc.go; internal/server/oidc_test.go).

export function LoginPage() {
  const { t, i18n } = useTranslation();
  const { redirect } = route.useSearch();
  const { theme, toggle } = useTheme();
  const [pending, setPending] = useState(false);

  function signIn() {
    setPending(true);
    window.location.assign(ssoLoginHref(redirect));
  }

  return (
    <div className="login">
      <section className="login-art" aria-label={t("app.title")}>
        <div>
          <p className="brand-mark">
            <ShieldCheck size={22} strokeWidth={1.5} aria-hidden focusable={false} />
            <span>{t("app.name")}</span>
          </p>
          <p className="claim">{t("login.claim")}</p>
          <p className="sub">{t("login.sub")}</p>
          {/* Static by design (§11): nothing on the login page moves on its own. */}
          <div className="login-ledger" role="img" aria-label={t("login.ledgerLabel")}>
            <div><span>10:31:15</span><span>Bash  npm ci</span><span className="v-pass">{t("login.pass")}</span></div>
            <div><span>10:31:40</span><span>Bash  curl … | sh</span><span className="v-block">{t("login.block")}</span></div>
            <div><span>10:32:26</span><span>Read  .env</span><span className="v-alert">{t("login.alert")}</span></div>
            <div><span>10:33:02</span><span>MCP   github.create_issue</span><span className="v-pass">{t("login.pass")}</span></div>
          </div>
        </div>
        <p className="faint" style={{ color: "inherit", opacity: 0.75 }}>{t("login.deploy")}</p>
      </section>
      <main className="login-form-wrap" id="main">
        <div className="login-form" aria-labelledby="login-h">
          <h1 id="login-h">{t("login.title")}</h1>
          <p className="faint">{t("login.ssoIntro")}</p>
          <button className="btn btn-primary btn-lg" type="button" disabled={pending} onClick={signIn}>
            <ShieldCheck size={18} strokeWidth={1.5} aria-hidden focusable={false} />
            {pending ? t("login.ssoBusy") : t("login.sso")}
          </button>
          <p className="faint">{t("login.note")}</p>
          <div className="login-meta">
            <label>
              <span className="sr-only">{t("shell.langLabel")}</span>
              <select className="input" value={i18n.language} onChange={(e) => setLanguage(e.target.value === "en" ? "en" : "zh-CN")}>
                <option value="zh-CN" lang="zh-CN">简体中文</option>
                <option value="en" lang="en">English</option>
              </select>
            </label>
            <button
              className="btn btn-ghost"
              type="button"
              aria-pressed={theme === "dark"}
              onClick={() => announce(t(toggle() === "dark" ? "shell.toDark" : "shell.toLight"))}
            >
              <Moon size={16} strokeWidth={1.5} aria-hidden focusable={false} />
              {t("shell.darkTheme")}
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}
