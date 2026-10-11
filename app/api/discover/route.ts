import { NextResponse } from "next/server";

import { parseBody, requireAuth, withErrorHandling } from "@/lib/api/helpers";
import { z } from "zod";
import { looksLikeJavaScript, parseMonitoringUrl } from "@/lib/validation/schemas";

/**
 * POST /api/discover — find JavaScript URLs referenced by an authorized page.
 *
 * Discovery is scoped: only the single supplied page is fetched, and results
 * are split into in-scope (enrollable) and out-of-scope (surfaced for review,
 * never auto-enrolled). No crawling, no third-party following.
 *
 * The fetch happens here rather than in the browser so the request originates
 * from the server, and so the SSRF checks in the Python engine's spirit are
 * enforced before any outbound call.
 */

const discoverSchema = z.object({
  page_url: z
    .string()
    .url()
    .max(2048)
    .refine((value) => {
      try {
        parseMonitoringUrl(value);
        return true;
      } catch {
        return false;
      }
    }, "Must be a valid public http(s) URL"),
  allowed_hosts: z.array(z.string().trim().min(1).max(253)).max(50).default([]),
});

const SCRIPT_SRC =
  /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
const LINK_PRELOAD =
  /<link\b[^>]*?\brel\s*=\s*(?:"(modulepreload|preload)"|'(modulepreload|preload)')[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
const LINK_AS = /\bas\s*=\s*["']?(script|worker)["']?/i;

const MAX_PAGE_BYTES = 2 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 15_000;

export async function POST(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const body = await parseBody(request, discoverSchema);
    if (!body.ok) return body.response;

    const { page_url: pageUrl, allowed_hosts: allowedHosts } = body.data;
    const pageHost = new URL(pageUrl).hostname.toLowerCase();
    const scope = allowedHosts.length ? allowedHosts : [pageHost];

    let html: string;
    try {
      html = await fetchPage(pageUrl);
    } catch (error) {
      return NextResponse.json(
        {
          error:
            error instanceof Error
              ? `Could not fetch page: ${error.message.slice(0, 200)}`
              : "Could not fetch page",
        },
        { status: 502 },
      );
    }

    const candidates = new Set<string>();

    for (const match of html.matchAll(SCRIPT_SRC)) {
      const src = match[1] ?? match[2] ?? match[3];
      if (src) candidates.add(src.trim());
    }

    for (const match of html.matchAll(LINK_PRELOAD)) {
      const tag = match[0];
      const rel = (match[1] ?? match[2] ?? "").toLowerCase();
      const href = match[3] ?? match[4] ?? match[5];
      if (!href) continue;
      // A plain preload only counts when it declares a script-ish `as`.
      if (rel === "preload" && !LINK_AS.test(tag)) continue;
      candidates.add(href.trim());
    }

    const inScope: string[] = [];
    const outOfScope: string[] = [];
    const rejected: Array<{ url: string; reason: string }> = [];
    const seen = new Set<string>();

    for (const raw of candidates) {
      if (!raw || raw.startsWith("#") || raw.startsWith("data:")) continue;
      if (raw.toLowerCase().startsWith("javascript:")) continue;

      let absolute: string;
      try {
        absolute = new URL(raw, pageUrl).toString();
      } catch {
        rejected.push({ url: raw.slice(0, 200), reason: "Malformed reference" });
        continue;
      }

      // Strip the fragment; keep the query (cache-busting params matter).
      const url = new URL(absolute);
      url.hash = "";
      const normalised = url.toString();

      if (seen.has(normalised)) continue;
      seen.add(normalised);

      if (!looksLikeJavaScript(normalised)) {
        rejected.push({ url: normalised, reason: "Does not look like JavaScript" });
        continue;
      }

      let parsed;
      try {
        parsed = parseMonitoringUrl(normalised);
      } catch (error) {
        rejected.push({
          url: normalised,
          reason: error instanceof Error ? error.message : "Invalid URL",
        });
        continue;
      }

      if (isInScope(parsed.host, scope)) {
        inScope.push(normalised);
      } else {
        outOfScope.push(normalised);
      }
    }

    return NextResponse.json({
      page_url: pageUrl,
      in_scope: inScope,
      out_of_scope: outOfScope,
      rejected,
      total_found: inScope.length + outOfScope.length,
      scope,
    });
  });
}

async function fetchPage(url: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent":
          "JSMonitor/1.0 (+https://github.com/robre/jsmon; authorized security monitoring)",
        Accept: "text/html,application/xhtml+xml",
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const contentType = response.headers.get("content-type") ?? "";
    if (!/text\/html|application\/xhtml/i.test(contentType)) {
      throw new Error(`Unexpected content-type: ${contentType.slice(0, 80)}`);
    }

    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_PAGE_BYTES) {
      throw new Error(`Page exceeds ${MAX_PAGE_BYTES} bytes`);
    }

    return Buffer.from(buffer).toString("utf-8");
  } finally {
    clearTimeout(timer);
  }
}

function isInScope(host: string, scope: string[]): boolean {
  const lower = host.toLowerCase();
  return scope.some((entry) => {
    const clean = entry.trim().toLowerCase().replace(/^\*?\./, "").replace(/\.$/, "");
    if (!clean) return false;
    return lower === clean || lower.endsWith(`.${clean}`);
  });
}
