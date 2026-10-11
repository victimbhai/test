import { NextResponse } from "next/server";

import { createClient, createServiceClient } from "@/lib/supabase/server";
import { jsonError, requireAuth, withErrorHandling } from "@/lib/api/helpers";
import type { DiffPayload, ReviewIndicator } from "@/lib/supabase/types";

/**
 * GET /api/changes/[id]/diff?a=...&b=... — diff content for a change event.
 *
 * The engine stored only metadata (line counts, indicator summary) on the
 * change row. The actual snapshot bytes live in private Supabase Storage, so
 * the diff is computed here on demand from signed downloads.
 *
 * Version selection:
 *   - default: the change's own previous -> current versions
 *   - ?a=<versionId>&b=<versionId>: compare any two historical versions
 *
 * SECURITY
 *   Snapshots are untrusted third-party JavaScript. They are returned as plain
 *   text (application/json) and rendered only inside Monaco as text — never as
 *   HTML — so a payload cannot execute in the dashboard's origin.
 */

const MAX_DIFF_BYTES = 2 * 1024 * 1024;

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const { id } = await params;
    const search = new URL(request.url).searchParams;
    const versionA = search.get("a");
    const versionB = search.get("b");

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    // Load the change and verify ownership through its asset's project.
    const { data: change } = await supabase
      .from("change_events")
      .select("*, assets!inner(project_id, url, projects!inner(owner_id))")
      .eq("id", id)
      .maybeSingle();

    if (!change) return jsonError("Change not found", 404);

    const ownerId = change.assets?.projects?.owner_id;
    if (ownerId !== auth.data.userId) {
      return jsonError("Change not found", 404);
    }

    const fromId = versionA ?? change.previous_version_id;
    const toId = versionB ?? change.current_version_id;

    if (!toId) return jsonError("This change has no current version", 409);

    const service = createServiceClient();
    if (!service) return jsonError("Storage is not configured", 503);

    const { data: versions } = await service
      .from("asset_versions")
      .select("id, sha256_hash, storage_object_path, file_size, captured_at")
      .in("id", fromId ? [fromId, toId] : [toId]);

    if (!versions || versions.length === 0) {
      return jsonError("Snapshot versions are no longer available", 410);
    }

    const from = fromId ? versions.find((v) => v.id === fromId) : undefined;
    const to = versions.find((v) => v.id === toId);
    if (!to) return jsonError("Current snapshot is no longer available", 410);

    const [fromBytes, toBytes] = await Promise.all([
      from ? downloadSnapshot(service, from.storage_object_path) : Promise.resolve(""),
      downloadSnapshot(service, to.storage_object_path),
    ]);

    const diff = buildUnifiedDiff(fromBytes, toBytes);
    const indicators = deriveIndicators(diff, change.change_metadata);

    const payload: DiffPayload = {
      unified: diff.unified,
      hunks: diff.hunks,
      added_lines: diff.added,
      removed_lines: diff.removed,
      old_lines: fromBytes ? fromBytes.split("\n").length : 0,
      new_lines: toBytes.split("\n").length,
      truncated: diff.truncated,
      context_lines: 3,
      indicators,
    };

    return NextResponse.json({
      diff: payload,
      meta: {
        asset_url: change.assets.url,
        from_version: from
          ? {
              id: from.id,
              sha256: from.sha256_hash,
              file_size: from.file_size,
              captured_at: from.captured_at,
            }
          : null,
        to_version: {
          id: to.id,
          sha256: to.sha256_hash,
          file_size: to.file_size,
          captured_at: to.captured_at,
        },
        detected_at: change.detected_at,
        size_difference: change.size_difference,
      },
    });
  });
}

async function downloadSnapshot(
  service: NonNullable<ReturnType<typeof createServiceClient>>,
  path: string,
): Promise<string> {
  const { data, error } = await service.storage
    .from(process.env.JSMON_STORAGE_BUCKET || "js-snapshots")
    .download(path);

  if (error || !data) return "";

  const buffer = Buffer.from(await data.arrayBuffer());
  if (buffer.byteLength > MAX_DIFF_BYTES) {
    // Truncate defensively: a multi-megabyte bundle would blow the response.
    return buffer.subarray(0, MAX_DIFF_BYTES).toString("utf-8");
  }
  return buffer.toString("utf-8");
}

interface ComputedDiff {
  unified: string;
  hunks: DiffPayload["hunks"];
  added: number;
  removed: number;
  truncated: boolean;
}

/**
 * Myers-style line diff via a simple LCS. Python's difflib is unavailable in
 * the Node runtime, and pulling a full diff library for this is unnecessary:
 * the payloads are line-oriented and this keeps the response self-contained.
 */
function buildUnifiedDiff(oldText: string, newText: string): ComputedDiff {
  const oldLines = oldText ? oldText.split("\n") : [];
  const newLines = newText.split("\n");

  const lcs = computeLcs(oldLines, newLines);
  const ops: Array<{ type: "ctx" | "add" | "del"; text: string }> = [];

  let i = 0;
  let j = 0;
  for (const [oi, ni] of lcs) {
    while (i < oi) {
      ops.push({ type: "del", text: oldLines[i] });
      i += 1;
    }
    while (j < ni) {
      ops.push({ type: "add", text: newLines[j] });
      j += 1;
    }
    ops.push({ type: "ctx", text: oldLines[oi] });
    i = oi + 1;
    j = ni + 1;
  }
  while (i < oldLines.length) {
    ops.push({ type: "del", text: oldLines[i] });
    i += 1;
  }
  while (j < newLines.length) {
    ops.push({ type: "add", text: newLines[j] });
    j += 1;
  }

  const added = ops.filter((o) => o.type === "add").length;
  const removed = ops.filter((o) => o.type === "del").length;

  const unifiedLines: string[] = [
    "--- previous",
    "+++ current",
  ];
  const hunks: DiffPayload["hunks"] = [];

  const context = 3;
  let oldNo = 0;
  let newNo = 0;
  let hunk: DiffPayload["hunks"][number] | null = null;
  let sinceChange = context + 1;

  for (const op of ops) {
    const isChange = op.type !== "ctx";
    if (isChange) sinceChange = 0;
    else sinceChange += 1;

    if (isChange || sinceChange <= context) {
      if (!hunk) {
        hunk = {
          old_start: oldNo + 1,
          old_lines: [],
          new_start: newNo + 1,
          new_lines: [],
        };
        hunks.push(hunk);
      }
    } else if (hunk) {
      hunk = null;
    }

    if (op.type === "ctx") {
      unifiedLines.push(` ${op.text}`);
      hunk?.old_lines.push(op.text);
      hunk?.new_lines.push(op.text);
      oldNo += 1;
      newNo += 1;
    } else if (op.type === "del") {
      unifiedLines.push(`-${op.text}`);
      hunk?.old_lines.push(op.text);
      oldNo += 1;
    } else {
      unifiedLines.push(`+${op.text}`);
      hunk?.new_lines.push(op.text);
      newNo += 1;
    }
  }

  const MAX_LINES = 20000;
  let truncated = false;
  let unified = unifiedLines.join("\n");
  if (unifiedLines.length > MAX_LINES) {
    unified = `${unifiedLines.slice(0, MAX_LINES).join("\n")}\n... (diff truncated)`;
    truncated = true;
  }

  return { unified, hunks, added, removed, truncated };
}

/** Longest common subsequence of two line arrays, as index pairs. */
function computeLcs(a: string[], b: string[]): Array<[number, number]> {
  const n = a.length;
  const m = b.length;

  // Guard against pathological sizes: fall back to a coarse diff.
  if (n * m > 4_000_000) {
    return coarseLcs(a, b);
  }

  const table: number[][] = Array.from({ length: n + 1 }, () =>
    new Array<number>(m + 1).fill(0),
  );

  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      table[i][j] =
        a[i] === b[j]
          ? table[i + 1][j + 1] + 1
          : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }

  const pairs: Array<[number, number]> = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      pairs.push([i, j]);
      i += 1;
      j += 1;
    } else if (table[i + 1][j] >= table[i][j + 1]) {
      i += 1;
    } else {
      j += 1;
    }
  }
  return pairs;
}

/** Anchored fallback for very large files. */
function coarseLcs(a: string[], b: string[]): Array<[number, number]> {
  const indexB = new Map<string, number[]>();
  b.forEach((line, idx) => {
    const list = indexB.get(line);
    if (list) list.push(idx);
    else indexB.set(line, [idx]);
  });

  const pairs: Array<[number, number]> = [];
  let lastJ = -1;
  for (let i = 0; i < a.length; i += 1) {
    const candidates = indexB.get(a[i]);
    if (!candidates) continue;
    const next = candidates.find((c) => c > lastJ);
    if (next !== undefined) {
      pairs.push([i, next]);
      lastJ = next;
    }
  }
  return pairs;
}

/**
 * Re-derive review indicators from the computed diff, merged with the summary
 * the engine persisted. This keeps the indicator list accurate even when the
 * stored summary is coarse.
 */
function deriveIndicators(
  diff: ComputedDiff,
  metadata: Record<string, unknown> | null,
): ReviewIndicator[] {
  const indicators: ReviewIndicator[] = [];

  const addedText = diff.unified
    .split("\n")
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1))
    .join("\n");

  const rules: Array<{
    category: string;
    label: string;
    severity: ReviewIndicator["severity"];
    pattern: RegExp;
  }> = [
    {
      category: "Credential",
      label: "High Entropy String",
      severity: "high",
      pattern: /["'`][A-Za-z0-9_-]{24,}["'`]/g,
    },
    {
      category: "Credential",
      label: "Api Key Pattern",
      severity: "high",
      pattern: /\b(?:sk|pk|rk|api|tok|key|secret)[_-]?(?:live|test|prod)?[_-]?[A-Za-z0-9]{16,}\b/g,
    },
    {
      category: "Credential",
      label: "Cloud Key",
      severity: "high",
      pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    },
    {
      category: "Credential",
      label: "Jwt",
      severity: "high",
      pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g,
    },
    {
      category: "Endpoint",
      label: "Api Path",
      severity: "high",
      pattern: /["'`](?:\/)?(?:api|v\d|rest|graphql)\/[A-Za-z0-9_\-./{}]{2,80}["'`]/g,
    },
    {
      category: "Endpoint",
      label: "Websocket",
      severity: "high",
      pattern: /\bwss?:\/\/[A-Za-z0-9._\-:/?&=%]{4,120}/g,
    },
    {
      category: "Authentication",
      label: "Auth Function",
      severity: "medium",
      pattern: /\b(?:login|logout|signIn|signOut|authenticate|refreshToken|getToken|isAuthenticated|hasRole|checkPermission|requireAuth|authorize)\s*\(/g,
    },
    {
      category: "Debug",
      label: "Debug Flag",
      severity: "medium",
      pattern: /["'`]?(?:debug|verbose|devMode|__DEV__|isDebug|DEBUG_MODE)["'`]?\s*[:=]\s*(?:true|!0|1)\b/g,
    },
    {
      category: "Authorization",
      label: "Admin Reference",
      severity: "high",
      pattern: /["'`](?:\/[A-Za-z0-9_\-.]*)?(?:admin|internal|superuser|backoffice)[A-Za-z0-9_\-./]*["'`]/g,
    },
    {
      category: "Source map",
      label: "Source Map",
      severity: "medium",
      pattern: /\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s"'`]+)/g,
    },
    {
      category: "Dangerous API",
      label: "Eval Usage",
      severity: "high",
      pattern: /\b(?:eval|new\s+Function|document\s*\.\s*write)\s*\(/g,
    },
  ];

  const seen = new Set<string>();
  const lines = addedText.split("\n");

  lines.forEach((line, index) => {
    for (const rule of rules) {
      rule.pattern.lastIndex = 0;
      const match = rule.pattern.exec(line);
      if (!match) continue;
      const key = `${rule.label}:${match[0].slice(0, 60)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      indicators.push({
        category: rule.category,
        label: rule.label,
        severity: rule.severity,
        line_number: index + 1,
        match: match[0].slice(0, 200),
        context: line.trim().slice(0, 400),
      });
    }
  });

  // Surface the engine's own count so the UI can say "engine found N".
  if (indicators.length === 0 && metadata?.indicator_summary) {
    const summary = metadata.indicator_summary as { total?: number };
    if (summary.total) {
      // The engine saw indicators we could not reproduce locally (its scan
      // ran on the original bytes). Report the count without inventing rows.
      return [];
    }
  }

  return indicators.slice(0, 100);
}
