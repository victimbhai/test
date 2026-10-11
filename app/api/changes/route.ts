import { NextResponse } from "next/server";

import { createClient } from "@/lib/supabase/server";
import { jsonError, requireAuth, withErrorHandling } from "@/lib/api/helpers";
import { paginationSchema } from "@/lib/validation/schemas";
import type { RecentChange } from "@/lib/supabase/types";

/**
 * GET /api/changes — detected change events, newest first.
 *
 * Reads the `recent_changes` view, which joins the change to both of its
 * snapshots so the dashboard can render sizes and hashes without a second
 * round-trip. RLS on the underlying tables confines results to the owner.
 */

export async function GET(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const params = new URL(request.url).searchParams;
    const parsed = paginationSchema.safeParse({
      limit: params.get("limit") ?? undefined,
      offset: params.get("offset") ?? undefined,
    });
    if (!parsed.success) return jsonError("Invalid pagination", 422);

    const projectId = params.get("project_id");
    const assetId = params.get("asset_id");

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    let query = supabase
      .from("recent_changes")
      .select("*", { count: "exact" })
      .eq("owner_id", auth.data.userId)
      .order("detected_at", { ascending: false })
      .range(parsed.data.offset, parsed.data.offset + parsed.data.limit - 1);

    if (projectId) query = query.eq("project_id", projectId);
    if (assetId) query = query.eq("asset_id", assetId);

    const { data, error, count } = await query;
    if (error) return jsonError("Could not load changes", 500);

    return NextResponse.json({
      changes: (data ?? []) as RecentChange[],
      total: count ?? 0,
      limit: parsed.data.limit,
      offset: parsed.data.offset,
    });
  });
}
