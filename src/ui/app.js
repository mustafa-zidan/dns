// Dashboard for the DNS server's HTTP API. Every value from the server is
// written with textContent, since domain names come from whoever can query
// the resolver and must never be parsed as HTML.
"use strict";

const REFRESH_MS = 5000;
const TOKEN_KEY = "dns-api-token";
const $ = (id) => document.getElementById(id);
const number = new Intl.NumberFormat();

let blockingActive = true;
let timer = null;

function token() {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

function setToken(value) {
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* storage blocked; the token lasts until the page reloads */ }
  memoryToken = value;
}
let memoryToken = token();

class Unauthorized extends Error {}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (memoryToken) headers.Authorization = `Bearer ${memoryToken}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`/api/${path}`, {
    ...options,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    cache: "no-store",
  });
  if (response.status === 401) throw new Unauthorized();
  if (!response.ok) throw new Error(`${response.status} ${(await response.text()) || response.statusText}`);
  return response.status === 204 ? null : response.json();
}

function showError(error) {
  const box = $("error");
  if (!error) { box.hidden = true; return; }
  box.textContent = `Could not reach the server: ${error.message}`;
  box.hidden = false;
}

function showLogin() {
  $("login").hidden = false;
  $("content").hidden = true;
  setControls(false);
  $("token").focus();
}

function setControls(enabled) {
  for (const id of ["toggle", "pause"]) $(id).disabled = !enabled;
}

function duration(secs) {
  const d = Math.floor(secs / 86400), h = Math.floor(secs / 3600) % 24;
  const m = Math.floor(secs / 60) % 60, s = secs % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function ranks(list, items) {
  list.replaceChildren();
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "Nothing yet";
    list.append(li);
    return;
  }
  const max = items[0].count || 1;
  for (const { name, count } of items) {
    const li = document.createElement("li");
    li.style.setProperty("--w", `${(count / max) * 100}%`);
    const label = document.createElement("span");
    label.className = "name";
    label.textContent = name;
    const value = document.createElement("span");
    value.className = "count";
    value.textContent = number.format(count);
    li.append(label, value);
    list.append(li);
  }
}

function renderStats(stats) {
  const q = stats.queries;
  for (const key of ["total", "blocked", "cached", "forwarded", "failed"]) {
    $(key).textContent = number.format(q[key]);
  }
  $("ratio").textContent = q.total ? `${(stats.blocked_ratio * 100).toFixed(1)}% of queries` : "";
  $("uptime").textContent = duration(stats.uptime_secs);
  ranks($("top-queried"), stats.top_queried);
  ranks($("top-blocked"), stats.top_blocked);
}

function renderBlocking(status) {
  blockingActive = status.active;
  const state = $("state");
  if (status.active) {
    state.textContent = "Blocking on";
    state.className = "pill on";
  } else if (status.paused_for_secs != null) {
    state.textContent = `Paused, ${duration(status.paused_for_secs)} left`;
    state.className = "pill off";
  } else {
    state.textContent = "Blocking off";
    state.className = "pill off";
  }
  $("toggle").textContent = status.active ? "Turn off blocking" : "Turn on blocking";
  $("pause").hidden = !status.active;

  $("blocked-domains").textContent = number.format(status.blocked_domains);
  $("allowed-domains").textContent = number.format(status.allowed_domains);
  $("last-reload").textContent = status.last_reload
    ? new Date(status.last_reload * 1000).toLocaleString()
    : "Never";

  const rows = status.sources.map((source) => {
    const tr = document.createElement("tr");
    const name = document.createElement("td");
    name.className = "source";
    name.textContent = source.source;
    const domains = document.createElement("td");
    domains.className = "num";
    domains.textContent = number.format(source.domains);
    const result = document.createElement("td");
    result.className = source.error ? "bad" : "ok";
    result.textContent = source.error || "OK";
    tr.append(name, domains, result);
    return tr;
  });
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 3;
    td.className = "empty";
    td.textContent = "No lists configured";
    tr.append(td);
    rows.push(tr);
  }
  $("sources").replaceChildren(...rows);
}

async function refresh() {
  try {
    const [stats, blocking, cache] = await Promise.all([
      api("stats?top=10"),
      api("blocking"),
      api("cache"),
    ]);
    renderStats(stats);
    renderBlocking(blocking);
    $("cache-entries").textContent = number.format(cache.entries);
    $("login").hidden = true;
    $("content").hidden = false;
    setControls(true);
    showError(null);
  } catch (error) {
    if (error instanceof Unauthorized) {
      setToken(null);
      showLogin();
    } else {
      showError(error);
    }
  }
}

function schedule() {
  clearInterval(timer);
  timer = document.hidden ? null : setInterval(refresh, REFRESH_MS);
}

// Runs an action from a button, keeping the button disabled until it is done.
async function act(button, action) {
  button.disabled = true;
  try {
    await action();
    await refresh();
  } catch (error) {
    if (error instanceof Unauthorized) showLogin();
    else showError(error);
  } finally {
    button.disabled = false;
  }
}

$("toggle").addEventListener("click", (event) =>
  act(event.currentTarget, async () => {
    renderBlocking(await api("blocking", { method: "PUT", body: { enabled: !blockingActive } }));
  }),
);

$("pause").addEventListener("change", (event) => {
  const select = event.currentTarget;
  const secs = Number(select.value);
  select.value = "";
  if (secs) act(select, () => api("blocking", { method: "PUT", body: { enabled: false, pause_secs: secs } }));
});

$("reload").addEventListener("click", (event) =>
  act(event.currentTarget, () => api("blocking/reload", { method: "POST" })),
);

$("clear-cache").addEventListener("click", (event) =>
  act(event.currentTarget, () => api("cache", { method: "DELETE" })),
);

$("reset-stats").addEventListener("click", (event) => {
  if (confirm("Reset all query counters?")) act(event.currentTarget, () => api("stats", { method: "DELETE" }));
});

$("check").addEventListener("submit", async (event) => {
  event.preventDefault();
  const verdict = $("verdict");
  const name = $("name").value.trim();
  if (!name) return;
  try {
    const result = await api(`check?name=${encodeURIComponent(name)}`);
    verdict.className = `verdict ${result.blocked ? "blocked" : "allowed"}`;
    verdict.textContent = result.blocked
      ? `${result.name} is blocked by ${result.rule}`
      : `${result.name} is not blocked`;
  } catch (error) {
    if (error instanceof Unauthorized) showLogin();
    else showError(error);
  }
});

$("login").addEventListener("submit", (event) => {
  event.preventDefault();
  setToken($("token").value);
  $("token").value = "";
  refresh();
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refresh();
  schedule();
});

refresh();
schedule();
