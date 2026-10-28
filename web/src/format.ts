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

const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
const DAY_NAMES: Record<(typeof DAYS)[number], string> = {
  mon: "Mon",
  tue: "Tue",
  wed: "Wed",
  thu: "Thu",
  fri: "Fri",
  sat: "Sat",
  sun: "Sun",
};

/** Names the days a schedule runs on, collapsing runs such as "Mon–Fri". */
export function days(list: readonly string[]): string {
  const on = DAYS.map((day) => list.includes(day));
  if (on.every(Boolean)) return "Every day";
  // Start from a day that is off, so a run across Sunday stays in one piece.
  const start = on.indexOf(false);
  const runs: number[][] = [];
  let run: number[] = [];
  for (let i = 1; i <= DAYS.length; i++) {
    const day = (start + i) % DAYS.length;
    if (on[day]) {
      run.push(day);
      continue;
    }
    if (run.length) runs.push(run);
    run = [];
  }
  // Monday first, except that a run across Sunday leads.
  const key = (r: number[]) => (r[0] > r[r.length - 1] ? -1 : r[0]);
  return runs
    .sort((a, b) => key(a) - key(b))
    .map(runLabel)
    .join(", ");
}

function runLabel(run: number[]): string {
  const first = DAY_NAMES[DAYS[run[0]]];
  const last = DAY_NAMES[DAYS[run[run.length - 1]]];
  if (run.length === 1) return first;
  if (run.length === 2) return `${first}, ${last}`;
  return `${first}–${last}`;
}
