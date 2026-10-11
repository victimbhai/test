import { z } from "zod";

/**
 * Request validation schemas.
 *
 * These mirror the Python engine's checks (monitor/jsmon/ssrf.py) so a URL
 * rejected server-side is also rejected in the browser with a useful message.
 * Client-side checks are UX only — every API route re-validates.
 */

export const MAX_URL_LENGTH = 2048;
export const MAX_BULK_URLS = 500;

const hostnameRegex =
  /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/i;

/** Hostnames that must never be fetched, even if DNS resolves them publicly. */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "instance-data.ec2.internal",
]);

function isPrivateIPv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = nums;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 169 && b === 254) return true; // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 192 && b === 0) return true; // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast / reserved
  return false;
}

function isPrivateIPv6(host: string): boolean {
  const lower = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fe80")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // ULA
  if (lower.startsWith("::ffff:")) {
    // IPv4-mapped: judge the wrapped IPv4 address.
    const mapped = lower.slice("::ffff:".length);
    return isPrivateIPv4(mapped);
  }
  return false;
}

export function isBlockedHost(host: string): boolean {
  const lower = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_HOSTNAMES.has(lower)) return true;
  if (isPrivateIPv4(lower)) return true;
  if (isPrivateIPv6(lower)) return true;
  return false;
}

export interface ParsedUrl {
  url: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  path: string;
}

/**
 * Validate a monitoring target URL.
 *
 * Enforces: scheme allowlist, hostname shape, blocked networks/hostnames,
 * length limits. DNS resolution is performed by the Python engine at scan
 * time (the browser cannot reliably resolve), so this is a structural check.
 */
export function parseMonitoringUrl(raw: string): ParsedUrl {
  const value = (raw ?? "").trim();

  if (!value) throw new Error("URL is required");
  if (value.length > MAX_URL_LENGTH) {
    throw new Error(`URL exceeds ${MAX_URL_LENGTH} characters`);
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Not a valid absolute URL");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http and https URLs are allowed");
  }

  if (parsed.username || parsed.password) {
    throw new Error("Credentials embedded in the URL are not allowed");
  }

  const host = parsed.hostname.toLowerCase();
  if (!host) throw new Error("URL has no hostname");

  if (!hostnameRegex.test(host) && !isPrivateIPv4(host) && !host.includes(":")) {
    throw new Error("Invalid hostname");
  }

  if (isBlockedHost(host)) {
    throw new Error(
      "Internal, loopback, private and cloud-metadata addresses are not permitted",
    );
  }

  const port = parsed.port
    ? Number(parsed.port)
    : parsed.protocol === "https:"
      ? 443
      : 80;

  return {
    url: value,
    scheme: parsed.protocol === "https:" ? "https" : "http",
    host,
    port,
    path: `${parsed.pathname}${parsed.search}`,
  };
}

export function isValidMonitoringUrl(raw: string): boolean {
  try {
    parseMonitoringUrl(raw);
    return true;
  } catch {
    return false;
  }
}

/** True when the URL looks like a JavaScript asset. */
export function looksLikeJavaScript(url: string): boolean {
  try {
    const parsed = new URL(url);
    const path = parsed.pathname.toLowerCase();
    if (/\.(mjs|cjs|js)(\?.*)?$/.test(path)) return true;
    return /\/(build|bundle|assets?|static|_next|webpack)\//.test(path);
  } catch {
    return false;
  }
}

export function isHostInScope(host: string, allowlist: string[]): boolean {
  if (!allowlist || allowlist.length === 0) return true;
  const lower = host.toLowerCase();
  return allowlist.some((entry) => {
    const clean = entry.trim().toLowerCase().replace(/^\*?\./, "").replace(/\.$/, "");
    if (!clean) return false;
    return lower === clean || lower.endsWith(`.${clean}`);
  });
}

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

export const urlSchema = z
  .string()
  .min(1, "URL is required")
  .max(MAX_URL_LENGTH)
  .refine((value) => isValidMonitoringUrl(value), {
    message: "Must be a valid public http(s) URL (no internal addresses)",
  });

export const projectNameSchema = z
  .string()
  .trim()
  .min(1, "Name is required")
  .max(120, "Name must be 120 characters or fewer");

export const hostAllowlistSchema = z
  .array(z.string().trim().min(1).max(253))
  .max(50)
  .default([])
  .refine(
    (hosts) =>
      hosts.every((h) => hostnameRegex.test(h.replace(/^\*?\./, "")) || isPrivateIPv4(h)),
    { message: "Each host must be a valid hostname" },
  );

export const createProjectSchema = z.object({
  name: projectNameSchema,
  primary_domain: z
    .string()
    .trim()
    .max(253)
    .optional()
    .nullable()
    .refine((v) => !v || hostnameRegex.test(v), {
      message: "Primary domain must be a valid hostname",
    }),
  description: z.string().trim().max(2000).optional().nullable(),
  tags: z.array(z.string().trim().min(1).max(40)).max(20).default([]),
  enabled: z.boolean().default(true),
  interval_minutes: z.coerce.number().int().min(1).max(10080).default(15),
  scope_notes: z.string().trim().max(4000).optional().nullable(),
  allowed_hosts: hostAllowlistSchema,
});

export const updateProjectSchema = createProjectSchema.partial();

export const createAssetSchema = z.object({
  project_id: z.string().uuid(),
  urls: z
    .array(urlSchema)
    .min(1, "At least one URL is required")
    .max(MAX_BULK_URLS, `At most ${MAX_BULK_URLS} URLs per request`),
  enabled: z.boolean().default(true),
  discovery_source: z.enum(["manual", "discovery", "import"]).default("manual"),
});

export const bulkImportSchema = z.object({
  project_id: z.string().uuid(),
  text: z.string().min(1, "Paste at least one URL").max(200_000),
});

export const triggerScanSchema = z.object({
  project_id: z.string().uuid().optional().nullable(),
  asset_id: z.string().uuid().optional().nullable(),
  full_scan: z.boolean().default(true),
  notify: z.boolean().default(true),
  dry_run: z.boolean().default(false),
});

export const notificationSettingsSchema = z.object({
  project_id: z.string().uuid().optional().nullable(),
  channel: z.enum(["telegram", "slack", "email"]),
  enabled: z.boolean(),
  bot_token: z.string().trim().max(256).optional().nullable(),
  chat_id: z.string().trim().max(128).optional().nullable(),
  webhook_url: z.string().trim().url().max(2048).optional().nullable(),
  min_severity: z.enum(["low", "medium", "high"]).default("low"),
});

export const testNotificationSchema = z.object({
  channel: z.enum(["telegram", "slack", "email"]),
  project_id: z.string().uuid().optional().nullable(),
});

export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/** Parse a pasted URL list into (valid, invalid) with de-duplication. */
export function parseUrlList(text: string): {
  valid: string[];
  invalid: Array<{ line: string; reason: string }>;
  duplicates: number;
} {
  const valid: string[] = [];
  const invalid: Array<{ line: string; reason: string }> = [];
  const seen = new Set<string>();
  let duplicates = 0;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const candidates = line.includes(",") && !line.includes("://")
      ? line.split(",").map((p) => p.trim())
      : [line];

    for (const candidate of candidates) {
      if (!candidate) continue;
      try {
        const parsed = parseMonitoringUrl(candidate);
        const key = parsed.url.toLowerCase();
        if (seen.has(key)) {
          duplicates += 1;
          continue;
        }
        seen.add(key);
        valid.push(parsed.url);
      } catch (error) {
        invalid.push({
          line: candidate,
          reason: error instanceof Error ? error.message : "Invalid URL",
        });
      }
    }
  }

  return { valid, invalid, duplicates };
}
