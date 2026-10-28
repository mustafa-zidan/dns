import { useCallback, useEffect, useMemo, useState } from "react";
import { Api, loadConfig, Unauthorized } from "./api";
import type { Blocking, CacheStatus, Clients, Stats } from "./api";
import { Dashboard } from "./Dashboard";
import { Logo } from "./Logo";
import { duration, parseApiUrl } from "./format";
import { savedApiUrl, savedToken, saveApiUrl, saveToken } from "./storage";

const REFRESH_MS = 5000;
/** Where the source is, linked from the footer. */
const SOURCE_URL = "https://github.com/mustafa-zidan/hushdns";

export interface Snapshot {
  stats: Stats;
  blocking: Blocking;
  cache: CacheStatus;
  clients: Clients;
}

type Connection =
  | { kind: "loading" }
  // No API address configured: ask for one.
  | { kind: "setup" }
  | { kind: "ready"; apiUrl: string; fixed: boolean };

export function App() {
  const [connection, setConnection] = useState<Connection>({ kind: "loading" });
  const [token, setToken] = useState<string | null>(savedToken);
  const [needsToken, setNeedsToken] = useState(false);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadConfig().then(({ apiUrl }) => {
      const url = apiUrl ?? savedApiUrl();
      setConnection(url ? { kind: "ready", apiUrl: url, fixed: apiUrl !== null } : { kind: "setup" });
    });
  }, []);

  const api = useMemo(
    () => (connection.kind === "ready" ? new Api(connection.apiUrl, token) : null),
    [connection, token],
  );

  // Turns a failed call into the sign-in form or an error banner.
  const fail = useCallback((e: unknown) => {
    if (e instanceof Unauthorized) {
      saveToken(null);
      setNeedsToken(true);
    } else {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const refresh = useCallback(async () => {
    if (!api) return;
    try {
      const [stats, blocking, cache, clients] = await Promise.all([
        api.stats(),
        api.blocking(),
        api.cache(),
        api.clients(),
      ]);
      setSnapshot({ stats, blocking, cache, clients });
      setNeedsToken(false);
      setError(null);
    } catch (e) {
      fail(e);
    }
  }, [api, fail]);

  useEffect(() => {
    if (!api || needsToken) return;
    refresh();
    let timer: number | undefined;
    const schedule = () => {
      window.clearInterval(timer);
      timer = document.hidden ? undefined : window.setInterval(refresh, REFRESH_MS);
    };
    const onVisibility = () => {
      if (!document.hidden) refresh();
      schedule();
    };
    schedule();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [api, needsToken, refresh]);

  const signIn = (value: string) => {
    saveToken(value);
    setToken(value);
    setNeedsToken(false);
  };

  const connect = (url: string) => {
    saveApiUrl(url);
    setSnapshot(null);
    setError(null);
    setConnection({ kind: "ready", apiUrl: url, fixed: false });
  };

  const disconnect = () => {
    saveApiUrl(null);
    saveToken(null);
    setToken(null);
    setSnapshot(null);
    setError(null);
    setConnection({ kind: "setup" });
  };

  return (
    <>
      <Header
        blocking={needsToken ? null : (snapshot?.blocking ?? null)}
        status={connection.kind === "setup" ? "Not connected" : needsToken ? "Signed out" : "Connecting"}
        disabled={!api || needsToken || !snapshot}
        onChange={async (enabled, pauseSecs) => {
          if (!api) return;
          try {
            const blocking = await api.setBlocking(enabled, pauseSecs);
            setSnapshot((s) => (s ? { ...s, blocking } : s));
          } catch (e) {
            fail(e);
          }
        }}
      />
      <main>
        {error && <p className="error">{error}</p>}
        {connection.kind === "setup" && <ServerForm onSubmit={connect} />}
        {connection.kind === "ready" && needsToken && <TokenForm apiUrl={connection.apiUrl} onSubmit={signIn} />}
        {api && !needsToken && snapshot && (
          <Dashboard api={api} snapshot={snapshot} refresh={refresh} fail={fail} />
        )}
        {connection.kind === "ready" && !connection.fixed && (
          <p className="muted footer">
            Connected to {connection.apiUrl}.{" "}
            <button type="button" className="link" onClick={disconnect}>
              Change server
            </button>
          </p>
        )}
        <p className="muted footer">
          hushdns is free software under the{" "}
          <a href={`${SOURCE_URL}/blob/main/LICENSE`}>GNU GPL</a>.{" "}
          <a href={SOURCE_URL}>Source code</a>
        </p>
      </main>
    </>
  );
}

function Header(props: {
  blocking: Blocking | null;
  /** Shown while there is no blocking state to show. */
  status: string;
  disabled: boolean;
  onChange: (enabled: boolean, pauseSecs?: number) => Promise<void>;
}) {
  const { blocking, status, disabled, onChange } = props;
  const [busy, setBusy] = useState(false);
  const run = async (enabled: boolean, pauseSecs?: number) => {
    setBusy(true);
    await onChange(enabled, pauseSecs);
    setBusy(false);
  };

  let state = { text: status, className: "pill" };
  if (blocking?.active) state = { text: "Blocking on", className: "pill on" };
  else if (blocking?.paused_for_secs != null) state = { text: `Paused, ${duration(blocking.paused_for_secs)} left`, className: "pill off" };
  else if (blocking) state = { text: "Blocking off", className: "pill off" };

  return (
    <header className="bar">
      <h1 className="brand">
        <Logo />
        hushdns
      </h1>
      <span className={state.className}>{state.text}</span>
      {blocking && (
        <div className="actions">
          <button type="button" disabled={disabled || busy} onClick={() => run(!blocking.active)}>
            {blocking.active ? "Turn off blocking" : "Turn on blocking"}
          </button>
          {blocking.active && (
            <select
              aria-label="Pause blocking"
              value=""
              disabled={disabled || busy}
              onChange={(e) => e.target.value && run(false, Number(e.target.value))}
            >
              <option value="">Pause for…</option>
              <option value="300">5 minutes</option>
              <option value="1800">30 minutes</option>
              <option value="3600">1 hour</option>
            </select>
          )}
        </div>
      )}
    </header>
  );
}

function ServerForm(props: { onSubmit: (url: string) => void }) {
  const [value, setValue] = useState("http://127.0.0.1:8053");
  const [invalid, setInvalid] = useState(false);
  return (
    <form
      className="card"
      onSubmit={(e) => {
        e.preventDefault();
        const url = parseApiUrl(value);
        setInvalid(!url);
        if (url) props.onSubmit(url);
      }}
    >
      <h2>Connect to a DNS server</h2>
      <p className="muted">
        Enter the address of the server's API. The server must list this page's origin ({location.origin}) in{" "}
        <code>api.cors_origins</code>.
      </p>
      <div className="row">
        <input
          type="url"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          aria-invalid={invalid}
          aria-label="API address"
          required
        />
        <button type="submit">Connect</button>
      </div>
      {invalid && <p className="verdict blocked">Use an http:// or https:// address.</p>}
    </form>
  );
}

function TokenForm(props: { apiUrl: string; onSubmit: (token: string) => void }) {
  const [value, setValue] = useState("");
  return (
    <form
      className="card"
      onSubmit={(e) => {
        e.preventDefault();
        if (value) props.onSubmit(value);
      }}
    >
      <h2>Sign in</h2>
      <p className="muted">{props.apiUrl} needs its API token. It is kept in this tab only.</p>
      <div className="row">
        <input
          type="password"
          autoComplete="current-password"
          placeholder="API token"
          aria-label="API token"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoFocus
          required
        />
        <button type="submit">Sign in</button>
      </div>
    </form>
  );
}
