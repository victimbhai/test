import { NextResponse } from "next/server";

import { createClient } from "@/lib/supabase/server";
import {
  assertProjectOwnership,
  jsonError,
  requireAuth,
  withErrorHandling,
} from "@/lib/api/helpers";
import { paginationSchema } from "@/lib/validation/schemas";
import type { AssetVersion, ScanRun } from "@/lib/supabase/types";

/**
 * GET /api/versions?asset_id=... — snapshot history for one target.
 *
 * Version rows are immutable, so this is a pure read. Ordered newest first;
 * `limit` is honoured so a long-lived asset does not return thousands of rows.
 */

export async function GET(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const params = new URL(request.url).searchParams;
    const assetId = params.get("asset_id");
    if (!assetId) return jsonError("asset_id is required", 400);

    const parsed = paginationSchema.safeParse({
      limit: params.get("limit") ?? undefined,
      offset: params.get("offset") ?? undefined,
    });
    if (!parsed.success) return jsonError("Invalid pagination", 422);

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    // Ownership through the asset's project.
    const { data: asset } = await supabase
      .from("assets")
      .select("project_id")
      .eq("id", assetId)
      .maybeSingle();
    if (!asset) return jsonError("Target not found", 404);

    if (!(await assertProjectOwnership(supabase, asset.project_id, auth.data.userId))) {
      return jsonError("Target not found", 404);
    }

    const { data, error, count } = await supabase
      .from("asset_versions")
      .select("*", { count: "exact" })
      .eq("asset_id", assetId)
      .order("captured_at", { ascending: false })
      .range(parsed.data.offset, parsed.data.offset + parsed.data.limit - 1);

    if (error) return jsonError("Could not load version history", 500);

    return NextResponse.json({
      versions: (data ?? []) as AssetVersion[],
      total: count ?? 0,
      limit: parsed.data.limit,
      offset: parsed.data.offset,
    });
  });
}

/** GET /api/scans — monitoring run history. */
export async function POST(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const params = new URL(request.url).searchParams;
    const parsed = paginationSchema.safeParse({
      limit: params.get("limit") ?? undefined,
      offset: params.get("offset") ?? undefined,
    });
    if (!parsed.success) return jsonError("Invalid pagination", 422);

    const status = params.get("status");
    const projectId = params.get("project_id");

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    let query = supabase
      .from("scan_runs")
      .select("*", { count: "exact" })
      .order("started_at", { ascending: false })
      .range(parsed.data.offset, parsed.data.offset + parsed.data.limit - 1);

    if (status) query = query.eq("status", status);
    if (projectId) {
      if (!(await assertProjectOwnership(supabase, projectId, auth.data.userId))) {
        return jsonError("Project not found", 404);
      }
      query = query.eq("project_id", projectId);
    }

    const { data, error, count } = await query;
    if (error) return jsonError("Could not load scan history", 500);

    return NextResponse.json({
      runs: (data ?? []) as ScanRun[],
      total: count ?? 0,
      limit: parsed.data.limit,
      offset: parsed.data.offset,
    });
  });
}
