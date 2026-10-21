import { useState, type FormEvent } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { isApiStatus } from "../../lib/api";
import type { ClientNode } from "../../lib/schema";
import type { SessionsSearch } from "../../router";
import { AGENT_NAMES, agentLabel, fromLocalInput, isRelative, presetRange, SESSION_PRESETS, toLocalInput } from "./model";

export type FilterPatch = Partial<Pick<SessionsSearch, "preset" | "from" | "to" | "agent" | "nodeId" | "sessionKey">>;

interface Props {
  search: SessionsSearch;
  onFilter: (patch: FilterPatch) => void;
  nodes: UseQueryResult<ClientNode[]>;
  filtered: boolean;
}

const text = (v: FormDataEntryValue | null) => (typeof v === "string" && v.trim() ? v.trim() : undefined);

// Filter bar (plan §3.4, design §V2.7): native controls only, so keyboard and AT behaviour is the
// platform's. Values the server accepts but the option lists lack (a shared link) stay selectable.
export function SessionFilters({ search, onFilter, nodes, filtered }: Props) {
  const { t } = useTranslation();
  const preset = search.preset ?? "";
  const agentIds = Object.keys(AGENT_NAMES);
  const nodeList = nodes.data ?? [];
  const nodeHint = nodes.isPending
    ? t("sessions.devicesLoading")
    : isApiStatus(nodes.error, 403)
      ? t("sessions.devicesForbidden")
      : nodes.isError
        ? t("sessions.devicesFailed")
        : undefined;

  const choosePreset = (value: string) => {
    const p = SESSION_PRESETS.find((x) => x === value);
    if (!p) return onFilter({ preset: undefined, from: undefined, to: undefined });
    onFilter(isRelative(p) ? { preset: p, ...presetRange(p) } : { preset: p });
  };
  const applyKey = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    onFilter({ sessionKey: text(new FormData(e.currentTarget).get("sessionKey")) });
  };

  return (
    <div className="toolbar" role="search" aria-label={t("sessions.filters")}>
      <label className="field">
        <span className="label">{t("sessions.time")}</span>
        <select className="input" value={preset} onChange={(e) => choosePreset(e.target.value)}>
          <option value="">{t("sessions.presetAll")}</option>
          {SESSION_PRESETS.map((p) => (
            <option key={p} value={p}>
              {t(`sessions.preset.${p}`)}
            </option>
          ))}
        </select>
      </label>
      {preset === "custom" && <CustomRange from={search.from} to={search.to} onApply={(from, to) => onFilter({ preset: "custom", from, to })} />}
      <label className="field">
        <span className="label">{t("sessions.agent")}</span>
        <select className="input" value={search.agent ?? ""} onChange={(e) => onFilter({ agent: e.target.value || undefined })}>
          <option value="">{t("sessions.any")}</option>
          {search.agent && !agentIds.includes(search.agent) && <option value={search.agent}>{search.agent}</option>}
          {agentIds.map((id) => (
            <option key={id} value={id}>
              {agentLabel(id)}
            </option>
          ))}
        </select>
      </label>
      <div className="field">
        <label className="label" htmlFor="device-filter">
          {t("sessions.device")}
        </label>
        <select
          id="device-filter"
          className="input"
          value={search.nodeId ?? ""}
          onChange={(e) => onFilter({ nodeId: e.target.value || undefined })}
          aria-describedby={nodeHint ? "device-hint" : undefined}
        >
          <option value="">{t("sessions.any")}</option>
          {search.nodeId && !nodeList.some((n) => n.id === search.nodeId) && <option value={search.nodeId}>{search.nodeId}</option>}
          {nodeList.map((n) => (
            <option key={n.id} value={n.id}>
              {t(n.revoked ? "sessions.deviceOptionRevoked" : "sessions.deviceOption", { name: n.name || n.id, id: n.id })}
            </option>
          ))}
        </select>
        {nodeHint && (
          <span className="hint" id="device-hint">
            {nodeHint}
          </span>
        )}
      </div>
      {/* key resets the uncontrolled input when the URL changes (back/forward, reset). */}
      <form className="field" onSubmit={applyKey} key={search.sessionKey ?? ""}>
        <label className="label" htmlFor="session-key-filter">
          {t("sessions.sessionKey")}
        </label>
        <span className="row">
          <input
            id="session-key-filter"
            name="sessionKey"
            className="input mono"
            defaultValue={search.sessionKey ?? ""}
            aria-describedby="session-key-hint"
            autoComplete="off"
            spellCheck={false}
          />
          <button className="btn btn-secondary" type="submit">
            {t("sessions.apply")}
          </button>
        </span>
        <span className="hint" id="session-key-hint">
          {t("sessions.sessionKeyHint")}
        </span>
      </form>
      {/* No verified user association exists yet (plan LD5, #72): the filter is shown, disabled, with why. */}
      <div className="field">
        <label className="label" htmlFor="user-filter">
          {t("sessions.user")}
        </label>
        <select id="user-filter" className="input" disabled aria-describedby="user-hint">
          <option value="">{t("sessions.any")}</option>
        </select>
        <span className="hint" id="user-hint">
          {t("sessions.userDisabled")}
        </span>
      </div>
      {filtered && (
        <span className="live-toggle">
          <Link className="btn btn-ghost" to="/sessions" search={{}}>
            {t("sessions.reset")}
          </Link>
        </span>
      )}
    </div>
  );
}

function CustomRange({ from, to, onApply }: { from?: string; to?: string; onApply: (from?: string, to?: string) => void }) {
  const { t } = useTranslation();
  const [invalid, setInvalid] = useState(false);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const f = fromLocalInput(String(data.get("from") ?? ""));
    const tt = fromLocalInput(String(data.get("to") ?? ""));
    // The server rejects a reversed range with 400 (plan A3); say so before asking.
    if (f && tt && f > tt) return setInvalid(true);
    setInvalid(false);
    onApply(f, tt);
  };
  return (
    <form className="field" onSubmit={submit} key={`${from ?? ""}|${to ?? ""}`} aria-label={t("sessions.preset.custom")}>
      <span className="row">
        <label className="field">
          <span className="label">{t("sessions.from")}</span>
          <input className="input" type="datetime-local" name="from" defaultValue={toLocalInput(from)} aria-invalid={invalid || undefined} aria-describedby="range-hint" />
        </label>
        <label className="field">
          <span className="label">{t("sessions.to")}</span>
          <input className="input" type="datetime-local" name="to" defaultValue={toLocalInput(to)} aria-invalid={invalid || undefined} aria-describedby="range-hint" />
        </label>
        <button className="btn btn-secondary" type="submit">
          {t("sessions.apply")}
        </button>
      </span>
      <span className={invalid ? "error" : "hint"} id="range-hint" role={invalid ? "alert" : undefined}>
        {invalid ? t("sessions.rangeInvalid") : t("sessions.rangeHint")}
      </span>
    </form>
  );
}
