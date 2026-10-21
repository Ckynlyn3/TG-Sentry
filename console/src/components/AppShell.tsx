import { useEffect, useState, useSyncExternalStore } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useNavigate, useRouter, useRouterState, type ErrorComponentProps } from "@tanstack/react-router";
import * as Dialog from "@radix-ui/react-dialog";
import * as Popover from "@radix-ui/react-popover";
import { Globe, LayoutDashboard, ListChecks, Menu, Moon, PackageSearch, ScrollText, ShieldCheck, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { logout, meQuery } from "../lib/api";
import { announce } from "../lib/announce";
import { useTheme } from "../lib/theme";
import { setLanguage, type Lang } from "../i18n";
import type { Role } from "../lib/schema";
import { ErrorPanel } from "./States";

const ICON = { size: 16, strokeWidth: 1.5, "aria-hidden": true, focusable: false } as const;

// The three landed roles (core.Role*) map to their own labels; exhaustive over the schema enum.
const ROLE_LABEL: Record<Role, string> = { admin: "shell.roleAdmin", auditor: "shell.roleAuditor", readonly: "shell.roleReadonly" };

// Carbon UI shell (design §4): 48 px header + 232 px rail; rail becomes an overlay below 1056 px.
// Only built surfaces appear in the rail (capability-gated, design §4): overview, risk events, session audit,
// asset scan, access control (design §3 IA: 防护 → 访问控制).
export function AppShell() {
  const { t, i18n } = useTranslation();
  const me = useQuery(meQuery).data;
  const { theme, toggle } = useTheme();
  const [navOpen, setNavOpen] = useState(false);
  const narrow = useNarrow();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  useEffect(() => setNavOpen(false), [pathname, narrow]);

  const nextLang: Lang = i18n.language === "en" ? "zh-CN" : "en";

  return (
    // Narrow screens: the rail is a Radix modal dialog (focus trap, inert background, Esc and
    // focus return per WAI-ARIA APG dialog pattern), so nothing behind the panel takes focus (SC 2.4.11).
    <Dialog.Root open={navOpen} onOpenChange={setNavOpen}>
      <a
        className="skip-link"
        href="#main"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("main")?.focus();
        }}
      >
        {t("shell.skip")}
      </a>
      <header className="app-header">
        <Dialog.Trigger className="icon-btn nav-toggle" aria-label={t("shell.openNav")}>
          <Menu {...ICON} />
        </Dialog.Trigger>
        <Link className="brand-mark" to="/events">
          <ShieldCheck size={20} strokeWidth={1.5} aria-hidden focusable={false} />
          <span>{t("app.name")}</span>
          <small>{t("app.tagline")}</small>
        </Link>
        <span className="header-spacer" />
        {/* Tenant + role stay visible at every width (design §4), read from /api/v1/me (#12). The auth
            guard resolves /me before the shell mounts, so both are present; role is one of the closed Go
            set. Role-driven hiding of admin-only affordances is defense-in-depth over server RBAC and
            follows the #46 OverviewPage capability gate — the shell has no admin-only affordance in S5. */}
        <div className="tenant-switch">
          <span>
            <span className="sr-only">{t("shell.tenant")}：</span>
            {me?.tenant}
          </span>
          <span className="role">
            <span className="sr-only">{t("shell.role")}：</span>
            {me && t(ROLE_LABEL[me.role])}
          </span>
        </div>
        <button
          className="icon-btn"
          type="button"
          aria-pressed={theme === "dark"}
          aria-label={t("shell.darkTheme")}
          onClick={() => announce(t(toggle() === "dark" ? "shell.toDark" : "shell.toLight"))}
        >
          <Moon {...ICON} />
        </button>
        <button className="icon-btn hide-sm" type="button" aria-label={t("shell.langToggle")} onClick={() => setLanguage(nextLang)}>
          <Globe {...ICON} />
        </button>
        <AccountMenu name={me?.name ?? ""} version={me?.version ?? ""} />
      </header>
      <div className="app-body">
        {narrow ? (
          <Dialog.Portal>
            <Dialog.Overlay className="nav-scrim" />
            <Dialog.Content
              className="nav-sheet"
              aria-describedby={undefined}
              // Radix skips links when choosing initial focus; APG dialog: focus the first focusable element.
              onOpenAutoFocus={(e) => {
                e.preventDefault();
                if (e.currentTarget instanceof HTMLElement) e.currentTarget.querySelector("a")?.focus();
              }}
            >
              <Dialog.Title className="sr-only">{t("shell.navLabel")}</Dialog.Title>
              <AppNav onNavigate={() => setNavOpen(false)} />
            </Dialog.Content>
          </Dialog.Portal>
        ) : (
          <AppNav />
        )}
        <main className="app-main" id="main" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </Dialog.Root>
  );
}

// Carbon lg breakpoint (1056 px), matching the CSS media query in index.css.
const NARROW = "(max-width: 1055px)";
const subscribeNarrow = (cb: () => void) => {
  const mq = window.matchMedia(NARROW);
  mq.addEventListener("change", cb);
  return () => mq.removeEventListener("change", cb);
};
function useNarrow(): boolean {
  return useSyncExternalStore(subscribeNarrow, () => window.matchMedia(NARROW).matches);
}

// Activating a link always closes the overlay, including the link to the current page.
function AppNav({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useTranslation();
  return (
    <nav className="app-nav" id="app-nav" aria-label={t("shell.navLabel")}>
      <ul>
        <li>
          <Link to="/overview" search={{ range: "24h" }} activeProps={{ "aria-current": "page" }} activeOptions={{ includeSearch: false }} onClick={onNavigate}>
            <LayoutDashboard {...ICON} />
            <span>{t("nav.overview")}</span>
          </Link>
        </li>
      </ul>
      <p className="nav-group">{t("shell.groupOperations")}</p>
      <ul>
        <li>
          <Link to="/events" activeProps={{ "aria-current": "page" }} onClick={onNavigate}>
            <TriangleAlert {...ICON} />
            <span>{t("nav.events")}</span>
          </Link>
        </li>
        <li>
          <Link to="/sessions" activeProps={{ "aria-current": "page" }} activeOptions={{ includeSearch: false }} onClick={onNavigate}>
            <ScrollText {...ICON} />
            <span>{t("nav.sessions")}</span>
          </Link>
        </li>
      </ul>
      <p className="nav-group">{t("shell.groupAssets")}</p>
      <ul>
        <li>
          <Link to="/inventory" activeProps={{ "aria-current": "page" }} activeOptions={{ includeSearch: false }} onClick={onNavigate}>
            <PackageSearch {...ICON} />
            <span>{t("nav.inventory")}</span>
          </Link>
        </li>
      </ul>
      <p className="nav-group">{t("acl.navGroup")}</p>
      <ul>
        <li>
          <Link to="/acl" activeProps={{ "aria-current": "page" }} activeOptions={{ includeSearch: false }} onClick={onNavigate}>
            <ListChecks {...ICON} />
            <span>{t("acl.nav")}</span>
          </Link>
        </li>
      </ul>
    </nav>
  );
}

function AccountMenu({ name, version }: { name: string; version: string }) {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const out = useMutation({
    mutationFn: logout,
    onSuccess: () => {
      qc.clear();
      void navigate({ to: "/login", search: { redirect: undefined } });
    },
    onError: () => announce(t("shell.logoutFailed")),
  });
  return (
    <Popover.Root>
      <Popover.Trigger className="icon-btn" aria-label={t("shell.account", { name })}>
        <span className="avatar" aria-hidden>
          {Array.from(name)[0] ?? "?"}
        </span>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content className="menu" align="end" sideOffset={6}>
          <p className="font-semibold">{name}</p>
          <p className="faint mono">{t("shell.version", { version })}</p>
          <label className="field mt-3">
            <span className="label">{t("shell.langLabel")}</span>
            <select className="input" value={i18n.language} onChange={(e) => setLanguage(e.target.value === "en" ? "en" : "zh-CN")}>
              <option value="zh-CN" lang="zh-CN">
                简体中文
              </option>
              <option value="en" lang="en">
                English
              </option>
            </select>
          </label>
          <button className="btn btn-secondary mt-3" type="button" disabled={out.isPending} onClick={() => out.mutate()}>
            {t("shell.logout")}
          </button>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

export function ShellError({ error }: ErrorComponentProps) {
  const { t } = useTranslation();
  const router = useRouter();
  return (
    <main className="app-main" id="main" tabIndex={-1}>
      <ErrorPanel title={t("shellError.title")} error={error} onRetry={() => void router.invalidate()} />
    </main>
  );
}
