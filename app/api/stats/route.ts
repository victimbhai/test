import { NextResponse } from "next/server";

import { createClient } from "@/lib/supabase/server";
import { jsonError, requireAuth, withErrorHandling } from "@/lib/api/helpers";
import type { DashboardStats, RecentChange } from "@/lib/supabase/types";

/**
 * GET /api/stats — overview metrics for the dashboard.
 *
 * Uses the `dashboard_stats()` SQL function when available (single round-trip,
 * computed in the database) and falls back to counting client-side so the
 * dashboard still renders before the function is deployed.
 */

export async function GET() {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    const { data: rpcData, error: rpcError } = await supabase.rpc("dashboard_stats", {
      p_owner: auth.data.userId,
    });

    if (!rpcError && rpcData) {
      return NextResponse.json({ stats: rpcData as DashboardStats, source: "sql" });
    }

    // Fallback: compute in JS.
    const { data: projects } = await supabase
      .from("projects")
      .select("id, enabled")
      .eq("owner_id", auth.data.userId);

    const projectIds = (projects ?? []).map((p) => p.id);
    const { data: assets } = projectIds.length
      ? await supabase
          .from("assets")
          .select("id, enabled, last_http_status, project_id")
          .in("project_id", projectIds)
      : { data: [] };

    const assetRows = assets ?? [];
    const { data: changes } = await supabase
      .from("recent_changes")
      .select("detected_at")
      .eq("owner_id", auth.data.userId)
      .gte("detected_at", new Date(Date.now() - 7 * 864e5).toISOString());

    const changeRows = (changes ?? []) as Array<{ detected_at: string }>;
    const now = Date.now();

    const stats: DashboardStats = {
      projects: projects?.length ?? 0,
      assets: assetRows.length,
      active_assets: assetRows.filter((a) => a.enabled).length,
      changes_24h: changeRows.filter(
        (c) => now - new Date(c.detected_at).getTime() < 864e5,
      ).length,
      changes_7d: changeRows.length,
      failed_checks: assetRows.filter(
        (a) => a.enabled && a.last_http_status !== null && a.last_http_status >= 400,
      ).length,
      last_successful_scan: null,
    };

    const { data: lastRun } = await supabase
      .from("scan_runs")
      .select("completed_at")
      .eq("status", "success")
      .order("completed_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    stats.last_successful_scan = lastRun?.completed_at ?? null;

    return NextResponse.json({ stats, source: "client" });
  });
}

/**
 * GET /api/stats/timeseries — change volume over time for the charts.
 *
 * Bucketed by day for the requested window (default 30 days).
 */
export async function POST(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    let days = 30;
    try {
      const body = await request.json();
      if (typeof body?.days === "number") {
        days = Math.min(365, Math.max(1, Math.floor(body.days)));
      }
    } catch {
      // default window
    }

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    const since = new Date(Date.now() - days * 864e5).toISOString();

    const { data, error } = await supabase
      .from("recent_changes")
      .select("detected_at, size_difference, project_name, asset_url")
      .eq("owner_id", auth.data.userId)
      .gte("detected_at", since)
      .order("detected_at", { ascending: true });

    if (error) return jsonError("Could not load change history", 500);

    const rows = (data ?? []) as RecentChange[];

    const buckets = new Map<string, { date: string; changes: number; bytes: number }>();
    for (let i = days - 1; i >= 0; i -= 1) {
      const d = new Date(Date.now() - i * 864e5);
      const key = d.toISOString().slice(0, 10);
      buckets.set(key, { date: key, changes: 0, bytes: 0 });
    }

    const byProject = new Map<string, number>();
    const byAsset = new Map<string, number>();

    for (const row of rows) {
      const key = row.detected_at.slice(0, 10);
      const bucket = buckets.get(key);
      if (bucket) {
        bucket.changes += 1;
        bucket.bytes += Math.abs(row.size_difference ?? 0);
      }
      byProject.set(row.project_name, (byProject.get(row.project_name) ?? 0) + 1);
      byAsset.set(row.asset_url, (byAsset.get(row.asset_url) ?? 0) + 1);
    }

    return NextResponse.json({
      window_days: days,
      series: Array.from(buckets.values()),
      by_project: Array.from(byProject.entries())
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      by_asset: Array.from(byAsset.entries())
        .map(([url, count]) => ({ url, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
    });
  });
}
