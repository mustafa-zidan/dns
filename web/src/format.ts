const integer = new Intl.NumberFormat();

export function count(value: number): string {
  return integer.format(value);
}

/** Formats seconds as the two largest units, such as "3h 12m". */
export function duration(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const d = Math.floor(s / 86400);
  const h = Math.floor(s / 3600) % 24;
  const m = Math.floor(s / 60) % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

export function percent(ratio: number): string {
  return `${(ratio * 100).toFixed(1)}%`;
}

/** Checks that a user-entered API address is an http(s) URL. */
export function parseApiUrl(input: string): string | null {
  try {
    const url = new URL(input.trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.origin + url.pathname.replace(/\/+$/, "");
  } catch {
    return null;
  }
}
