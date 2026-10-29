// Client for the DNS server's HTTP API. Types mirror the JSON in src/api.rs.

export interface Counts {
  total: number;
  blocked: number;
  cached: number;
  forwarded: number;
  failed: number;
  invalid: number;
}

export interface DomainCount {
  name: string;
  count: number;
}

export interface Stats {
  uptime_secs: number;
  queries: Counts;
  blocked_ratio: number;
  top_queried: DomainCount[];
  top_blocked: DomainCount[];
}

export interface SourceStatus {
  source: string;
  domains: number;
  error: string | null;
}

export interface Blocking {
  active: boolean;
  paused_for_secs: number | null;
  blocked_domains: number;
  allowed_domains: number;
  last_reload: number | null;
  sources: SourceStatus[];
}

export interface CheckResult {
  name: string;
  blocked: boolean;
  rule: string | null;
  /** The client group whose rules applied, when a client address was given. */
  client: string | null;
}

export type Day = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun";

export interface ScheduleStatus {
  days: Day[];
  from: string;
  to: string;
  block_all: boolean;
  denylist: number;
  /** Whether the window is open right now. */
  active: boolean;
}

export interface ClientGroup {
  name: string;
  addresses: string[];
  /** Whether the shared lists apply to this group. */
  blocklists: boolean;
  denylist: number;
  allowlist: number;
  list_domains: number;
  sources: SourceStatus[];
  schedules: ScheduleStatus[];
  paused_for_secs: number | null;
}

export interface Clients {
  /** Local time in the schedules' time zone. */
  now: string;
  groups: ClientGroup[];
}

export interface CacheStatus {
  entries: number;
}

export type Role = "viewer" | "admin";

/** Who the dashboard is signed in as. */
export interface Me {
  name: string;
  role: Role;
  /** A session from signing in, an API token, or nothing when the API is open. */
  via: "session" | "token" | "open";
}

export interface Login {
  token: string;
  user: Me;
  expires_in_secs: number;
}

export interface AuditEvent {
  /** Unix time, in seconds. */
  time: number;
  user: string;
  action: string;
  detail: string;
  address: string | null;
}

/** The credentials are missing, wrong, or their session has ended. */
export class Unauthorized extends Error {
  constructor() {
    super("The server needs you to sign in");
  }
}

/** A response other than 401 that isn't a success. */
export class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export class Api {
  readonly base: string;
  private readonly token: string | null;

  constructor(base: string, token: string | null) {
    this.base = base.replace(/\/+$/, "");
    this.token = token;
  }

  /** Signs in with an account. The returned token goes to `new Api`. */
  login(name: string, password: string): Promise<Login> {
    return this.request("login", { method: "POST", body: { name, password } });
  }

  logout(): Promise<null> {
    return this.request("logout", { method: "POST" });
  }

  me(): Promise<Me> {
    return this.request("me");
  }

  /** Recent sign-ins and changes, newest first. Admins only. */
  audit(): Promise<AuditEvent[]> {
    return this.request("audit");
  }

  stats(top = 10): Promise<Stats> {
    return this.request(`stats?top=${top}`);
  }

  resetStats(): Promise<null> {
    return this.request("stats", { method: "DELETE" });
  }

  blocking(): Promise<Blocking> {
    return this.request("blocking");
  }

  setBlocking(enabled: boolean, pauseSecs?: number): Promise<Blocking> {
    const body = pauseSecs === undefined ? { enabled } : { enabled, pause_secs: pauseSecs };
    return this.request("blocking", { method: "PUT", body });
  }

  reload(): Promise<Blocking> {
    return this.request("blocking/reload", { method: "POST" });
  }

  check(name: string, client?: string): Promise<CheckResult> {
    const query = client ? `&client=${encodeURIComponent(client)}` : "";
    return this.request(`check?name=${encodeURIComponent(name)}${query}`);
  }

  clients(): Promise<Clients> {
    return this.request("clients");
  }

  /** Gives a group only the shared rules for `secs` seconds; 0 resumes it. */
  pauseClient(name: string, secs: number): Promise<ClientGroup> {
    return this.request(`clients/${encodeURIComponent(name)}`, { method: "PUT", body: { pause_secs: secs } });
  }

  cache(): Promise<CacheStatus> {
    return this.request("cache");
  }

  clearCache(): Promise<null> {
    return this.request("cache", { method: "DELETE" });
  }

  private async request<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    let response: Response;
    try {
      response = await fetch(`${this.base}/api/${path}`, {
        method: options.method ?? "GET",
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch {
      // Browsers report CORS refusals and unreachable hosts the same way.
      throw new Error(
        `Could not reach ${this.base}. Check that the server is running and lists this page's origin (${location.origin}) in api.cors_origins.`,
      );
    }
    if (response.status === 401) throw new Unauthorized();
    if (!response.ok) {
      const text = await response.text();
      throw new HttpError(response.status, text || `${response.status} ${response.statusText}`);
    }
    return (response.status === 204 ? null : await response.json()) as T;
  }
}

export interface RuntimeConfig {
  /** Base URL of the DNS server's API, such as http://127.0.0.1:8053. */
  apiUrl: string | null;
}

/** Reads config.json, which the container writes from HUSHDNS_API_URL. */
export async function loadConfig(): Promise<RuntimeConfig> {
  try {
    const response = await fetch("config.json", { cache: "no-store" });
    if (!response.ok) return { apiUrl: null };
    const config = (await response.json()) as Partial<RuntimeConfig>;
    return { apiUrl: typeof config.apiUrl === "string" && config.apiUrl ? config.apiUrl : null };
  } catch {
    return { apiUrl: null };
  }
}
