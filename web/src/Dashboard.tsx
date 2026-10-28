import { useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import type { Api, Blocking, CheckResult, ClientGroup, Clients, DomainCount } from "./api";
import type { Snapshot } from "./App";
import { count, days, duration, percent } from "./format";

// Domain names come from whoever can query the resolver. React escapes text,
// and nothing here uses dangerouslySetInnerHTML, so they are never parsed as HTML.

export function Dashboard(props: {
  api: Api;
  snapshot: Snapshot;
  refresh: () => Promise<void>;
  fail: (e: unknown) => void;
}) {
  const { api, snapshot, refresh, fail } = props;
  const { stats, blocking, cache, clients } = snapshot;
  const q = stats.queries;

  // Runs an action, then refreshes so every panel shows its effect.
  const act = async (action: () => Promise<unknown>) => {
    try {
      await action();
      await refresh();
    } catch (e) {
      fail(e);
    }
  };

  return (
    <div className="content">
      <section className="tiles" aria-label="Query counts">
        <Tile label="Queries" value={count(q.total)} />
        <Tile label="Blocked" value={count(q.blocked)} sub={q.total ? `${percent(stats.blocked_ratio)} of queries` : undefined} />
        <Tile label="From cache" value={count(q.cached)} />
        <Tile label="Forwarded" value={count(q.forwarded)} />
        <Tile label="Failed" value={count(q.failed)} />
        <Tile label="Uptime" value={duration(stats.uptime_secs)} />
      </section>

      <section className="grid">
        <Card title="Top queried">
          <Ranks items={stats.top_queried} />
        </Card>
        <Card title="Top blocked">
          <Ranks items={stats.top_blocked} blocked />
        </Card>
      </section>

      <section className="grid">
        <CheckDomain api={api} fail={fail} />
        <Card title="Maintenance">
          <dl className="facts">
            <dt>Cached answers</dt>
            <dd>{count(cache.entries)}</dd>
          </dl>
          <div className="row">
            <ActionButton onClick={() => act(() => api.clearCache())}>Clear cache</ActionButton>
            <ActionButton
              onClick={() => (confirm("Reset all query counters?") ? act(() => api.resetStats()) : Promise.resolve())}
            >
              Reset stats
            </ActionButton>
          </div>
        </Card>
      </section>

      {clients.groups.length > 0 && (
        <ClientGroups clients={clients} onPause={(name, secs) => act(() => api.pauseClient(name, secs))} />
      )}

      <Blocklists blocking={blocking} onReload={() => act(() => api.reload())} />
    </div>
  );
}

function Tile(props: { label: string; value: string; sub?: string }) {
  return (
    <div className="tile">
      <span className="label">{props.label}</span>
      <span className="value">{props.value}</span>
      {props.sub && <span className="sub">{props.sub}</span>}
    </div>
  );
}

function Card(props: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <div className="card">
      <div className="head">
        <h2>{props.title}</h2>
        {props.action}
      </div>
      {props.children}
    </div>
  );
}

/** A secondary button that stays disabled while its action runs. */
function ActionButton(props: { onClick: () => Promise<void>; children: ReactNode }) {
  const [busy, setBusy] = useState(false);
  return (
    <button
      type="button"
      className="secondary"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          await props.onClick();
        } finally {
          setBusy(false);
        }
      }}
    >
      {props.children}
    </button>
  );
}

function Ranks(props: { items: DomainCount[]; blocked?: boolean }) {
  const { items, blocked } = props;
  if (!items.length) return <p className="empty">Nothing yet</p>;
  const max = items[0].count || 1;
  return (
    <ol className={blocked ? "ranks blocked" : "ranks"}>
      {items.map(({ name, count: n }) => (
        <li key={name} style={{ "--w": `${(n / max) * 100}%` } as CSSProperties}>
          <span className="name">{name}</span>
          <span className="count">{count(n)}</span>
        </li>
      ))}
    </ol>
  );
}

function CheckDomain(props: { api: Api; fail: (e: unknown) => void }) {
  const [name, setName] = useState("");
  const [client, setClient] = useState("");
  const [result, setResult] = useState<CheckResult | null>(null);
  return (
    <form
      className="card"
      onSubmit={async (e) => {
        e.preventDefault();
        if (!name.trim()) return;
        try {
          setResult(await props.api.check(name.trim(), client.trim() || undefined));
        } catch (err) {
          props.fail(err);
        }
      }}
    >
      <h2>Check a domain</h2>
      <div className="row">
        <input
          type="text"
          placeholder="ads.example.com"
          aria-label="Domain"
          autoComplete="off"
          spellCheck={false}
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <input
          type="text"
          className="client"
          placeholder="Client IP (optional)"
          aria-label="Client IP address"
          autoComplete="off"
          spellCheck={false}
          inputMode="decimal"
          value={client}
          onChange={(e) => setClient(e.target.value)}
        />
        <button type="submit">Check</button>
      </div>
      <p className={`verdict ${result ? (result.blocked ? "blocked" : "allowed") : ""}`} aria-live="polite">
        {result && verdict(result)}
      </p>
    </form>
  );
}

function verdict(result: CheckResult): string {
  const forWhom = result.client ? ` for ${result.client}` : "";
  if (!result.blocked) return `${result.name} is not blocked${forWhom}`;
  const by = result.rule === "*" ? "a schedule that blocks everything" : result.rule;
  return `${result.name} is blocked${forWhom} by ${by}`;
}

const PAUSE_SECS = 3600;

function ClientGroups(props: { clients: Clients; onPause: (name: string, secs: number) => Promise<void> }) {
  return (
    <Card title="Client groups">
      <ul className="groups">
        {props.clients.groups.map((group) => (
          <li key={group.name}>
            <div className="group-head">
              <div>
                <strong>{group.name}</strong>
                <span className="muted addresses">{group.addresses.join(", ")}</span>
              </div>
              <div className="group-status">
                <span className={group.paused_for_secs ? "muted" : "ok"}>
                  {group.paused_for_secs ? `Paused, ${duration(group.paused_for_secs)} left` : "Active"}
                </span>
                {group.paused_for_secs ? (
                  <ActionButton onClick={() => props.onPause(group.name, 0)}>Resume</ActionButton>
                ) : (
                  <ActionButton onClick={() => props.onPause(group.name, PAUSE_SECS)}>Pause 1h</ActionButton>
                )}
              </div>
            </div>
            <p className="group-rules">{rules(group)}</p>
            {group.schedules.map((s, i) => (
              <p key={i} className={s.active ? "schedule open" : "schedule"}>
                {days(s.days)} {s.from}–{s.to}: {s.block_all ? "block all" : `block ${count(s.denylist)}`}
                {s.active && " (open now)"}
              </p>
            ))}
          </li>
        ))}
      </ul>
      <p className="note">
        Times are server time ({props.clients.now.replace("T", " ")} now). A paused group gets only the shared
        rules.
      </p>
    </Card>
  );
}

function rules(group: ClientGroup): string {
  const parts = [
    group.denylist && `${count(group.denylist)} denied`,
    group.allowlist && `${count(group.allowlist)} allowed`,
    group.sources.length && `${count(group.list_domains)} from ${group.sources.length} list${group.sources.length === 1 ? "" : "s"}`,
    group.blocklists ? "shared lists" : "no shared lists",
  ];
  const failed = group.sources.filter((s) => s.error).length;
  if (failed) parts.push(`${failed} list${failed === 1 ? "" : "s"} failed`);
  return parts.filter(Boolean).join(" · ");
}

function Blocklists(props: { blocking: Blocking; onReload: () => Promise<void> }) {
  const { blocking } = props;
  return (
    <Card title="Blocklists" action={<ActionButton onClick={props.onReload}>Reload now</ActionButton>}>
      <dl className="facts">
        <dt>Blocked domains</dt>
        <dd>{count(blocking.blocked_domains)}</dd>
        <dt>Allowed domains</dt>
        <dd>{count(blocking.allowed_domains)}</dd>
        <dt>Last reload</dt>
        <dd>{blocking.last_reload ? new Date(blocking.last_reload * 1000).toLocaleString() : "Never"}</dd>
      </dl>
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th className="num">Domains</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {blocking.sources.length === 0 && (
              <tr>
                <td colSpan={3} className="empty">
                  No lists configured
                </td>
              </tr>
            )}
            {blocking.sources.map((source) => (
              <tr key={source.source}>
                <td className="source">{source.source}</td>
                <td className="num">{count(source.domains)}</td>
                <td className={source.error ? "bad" : "ok"}>{source.error ?? "OK"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
