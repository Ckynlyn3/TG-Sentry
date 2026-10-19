import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getRouteApi, useRouter } from "@tanstack/react-router";
import { Moon, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { ApiError, login } from "../../lib/api";
import { announce } from "../../lib/announce";
import { useTheme } from "../../lib/theme";
import { setLanguage } from "../../i18n";

const route = getRouteApi("/login");
const formSchema = z.object({ token: z.string().trim().min(1) });
type Form = z.infer<typeof formSchema>;

// M1 local break-glass login: POST /api/v1/login {token} with the admin token (internal/server/server.go).
// Paste and password managers allowed, no CAPTCHA (WCAG 2.2 SC 3.3.8). SSO is M2 (#12).
export function LoginPage() {
  const { t, i18n } = useTranslation();
  const { redirect } = route.useSearch();
  const router = useRouter();
  const qc = useQueryClient();
  const { theme, toggle } = useTheme();
  const form = useForm<Form>({ resolver: zodResolver(formSchema), defaultValues: { token: "" } });
  const signIn = useMutation({
    mutationFn: (v: Form) => login(v.token),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["me"] });
      router.history.push(redirect ?? "/events");
    },
  });

  useEffect(() => {
    if (isInvalid(signIn.error)) form.setFocus("token");
  }, [signIn.error, form]);

  const fieldError = form.formState.errors.token ? t("login.required") : isInvalid(signIn.error) ? t("login.invalid") : undefined;
  const formError = signIn.error && !isInvalid(signIn.error) ? loginFailure(t, signIn.error) : undefined;

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
        <form className="login-form" noValidate aria-labelledby="login-h" onSubmit={form.handleSubmit((v) => signIn.mutate(v))}>
          <h1 id="login-h">{t("login.title")}</h1>
          <div className="field">
            <label htmlFor="token">{t("login.token")}</label>
            <input
              id="token"
              className="input"
              type="password"
              autoComplete="current-password"
              aria-invalid={fieldError ? true : undefined}
              aria-describedby={fieldError ? "token-hint token-error" : "token-hint"}
              {...form.register("token")}
            />
            <p className="hint" id="token-hint">{t("login.tokenHint")}</p>
            {fieldError && <p className="error" id="token-error">{fieldError}</p>}
          </div>
          {formError && <p className="banner banner-error" role="alert">{formError}</p>}
          <button className="btn btn-primary btn-lg" type="submit" disabled={signIn.isPending}>
            {signIn.isPending ? t("login.submitting") : t("login.submit")}
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
        </form>
      </main>
    </div>
  );
}

const isInvalid = (e: unknown) => e instanceof ApiError && e.status === 401;

function loginFailure(t: (k: string, o?: Record<string, unknown>) => string, e: unknown) {
  if (e instanceof ApiError && e.kind === "network") return t("login.network");
  return t("login.failed", { status: e instanceof ApiError ? e.status : "?" });
}
