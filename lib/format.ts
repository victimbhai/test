/**
 * Formatting helpers shared across the dashboard.
 */

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatSignedBytes(delta: number): string {
  if (delta === 0) return "0 B";
  const sign = delta > 0 ? "+" : "−";
  return `${sign}${formatBytes(Math.abs(delta))}`;
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  const sign = value > 0 ? "+" : "";
  return `${sign}${value.toFixed(1)}%`;
}

export function shortHash(hash: string | null | undefined, length = 12): string {
  if (!hash) return "—";
  return hash.slice(0, length);
}

/** Relative time, e.g. "4 minutes ago". Falls back to an absolute date. */
export function formatRelativeTime(
  value: string | null | undefined,
  now: Date = new Date(),
): string {
  if (!value) return "never";
  const then = new Date(value);
  if (Number.isNaN(then.getTime())) return "unknown";

  const diffMs = now.getTime() - then.getTime();
  const future = diffMs < 0;
  const abs = Math.abs(diffMs);

  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 365 * 24 * 60 * 60 * 1000],
    ["month", 30 * 24 * 60 * 60 * 1000],
    ["week", 7 * 24 * 60 * 60 * 1000],
    ["day", 24 * 60 * 60 * 1000],
    ["hour", 60 * 60 * 1000],
    ["minute", 60 * 1000],
    ["second", 1000],
  ];

  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === "second") {
      const amount = Math.round(abs / ms);
      return rtf.format(future ? amount : -amount, unit);
    }
  }
  return "just now";
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  if (minutes < 60) return `${minutes}m ${rest}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

/** Extract a readable filename from a URL for display. */
export function urlFilename(url: string): string {
  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split("/").filter(Boolean);
    return segments.length ? segments[segments.length - 1] : parsed.hostname;
  } catch {
    return url;
  }
}

export function urlHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

/**
 * Human-readable cron description for the common schedules.
 * Falls back to the raw expression for anything unusual.
 */
export function describeCron(expression: string): string {
  const parts = expression.trim().split(/\s+/);
  if (parts.length !== 5) return expression;

  const [minute, hour, dom, month, dow] = parts;

  if (minute.startsWith("*/") && hour === "*" && dom === "*" && month === "*" && dow === "*") {
    const step = Number(minute.slice(2));
    if (Number.isFinite(step)) return `Every ${step} minutes`;
  }

  if (
    /^\d+(,\d+)*$/.test(minute) &&
    hour === "*" &&
    dom === "*" &&
    month === "*" &&
    dow === "*"
  ) {
    const minutes = minute.split(",").map(Number);
    if (minutes.length > 1) {
      const step = minutes[1] - minutes[0];
      if (step > 0 && minutes.every((m, i) => m === minutes[0] + i * step)) {
        return `Every ${step} minutes (at :${minutes
          .map((m) => String(m).padStart(2, "0"))
          .join(", :")})`;
      }
    }
    return `Hourly at :${minutes.map((m) => String(m).padStart(2, "0")).join(", :")}`;
  }

  if (dow !== "*" && hour === "*") {
    const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    const day = days[Number(dow)];
    return day ? `Weekly on ${day} at :${String(minute).padStart(2, "0")}` : expression;
  }

  return expression;
}

/** Next occurrence of a simple interval-based cron, for "next expected scan". */
export function nextCronOccurrence(
  expression: string,
  from: Date = new Date(),
): Date | null {
  const parts = expression.trim().split(/\s+/);
  if (parts.length !== 5) return null;
  const [minutePart, hourPart] = parts;

  const minutes: number[] = [];
  if (minutePart === "*") {
    for (let m = 0; m < 60; m += 1) minutes.push(m);
  } else if (minutePart.startsWith("*/")) {
    const step = Number(minutePart.slice(2));
    for (let m = 0; m < 60; m += step) minutes.push(m);
  } else {
    for (const piece of minutePart.split(",")) {
      const n = Number(piece);
      if (Number.isFinite(n)) minutes.push(n);
    }
  }
  if (minutes.length === 0) return null;
  minutes.sort((a, b) => a - b);

  const hours: number[] | null =
    hourPart === "*"
      ? null
      : hourPart
          .split(",")
          .map(Number)
          .filter((n) => Number.isFinite(n));

  const candidate = new Date(from.getTime());
  candidate.setSeconds(0, 0);
  candidate.setMinutes(candidate.getMinutes() + 1);

  for (let i = 0; i < 60 * 24 * 8; i += 1) {
    if (hours && !hours.includes(candidate.getHours())) {
      candidate.setHours(candidate.getHours() + 1, 0, 0, 0);
      continue;
    }
    if (!minutes.includes(candidate.getMinutes())) {
      candidate.setMinutes(candidate.getMinutes() + 1);
      continue;
    }
    return candidate;
  }
  return null;
}
