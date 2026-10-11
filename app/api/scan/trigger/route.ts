import { NextResponse } from "next/server";

import { createClient, createServiceClient } from "@/lib/supabase/server";
import {
  assertProjectOwnership,
  jsonError,
  parseBody,
  requireAuth,
  withErrorHandling,
} from "@/lib/api/helpers";
import { triggerScanSchema } from "@/lib/validation/schemas";

/**
 * POST /api/scan/trigger — "Run Scan Now".
 *
 * This does NOT call GitHub directly. It writes a durable dispatch job (which
 * the partial unique index makes idempotent per asset) and then attempts an
 * immediate drain so the user sees "Queued" without waiting for the cron.
 *
 * A 202 means "accepted and queued", never "scan completed".
 */

export async function POST(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const body = await parseBody(request, triggerScanSchema);
    if (!body.ok) return body.response;

    const { project_id: projectId, asset_id: assetId, notify, dry_run } = body.data;

    if (!projectId && !assetId) {
      return jsonError("Provide project_id or asset_id", 400);
    }

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    // Ownership: an asset must be reached through its project.
    let resolvedProjectId = projectId;
    if (assetId) {
      const { data: asset } = await supabase
        .from("assets")
        .select("project_id")
        .eq("id", assetId)
        .maybeSingle();
      if (!asset) return jsonError("Target not found", 404);
      resolvedProjectId = asset.project_id;
    }

    if (!resolvedProjectId) return jsonError("Project could not be resolved", 400);

    if (!(await assertProjectOwnership(supabase, resolvedProjectId, auth.data.userId))) {
      return jsonError("Project not found", 404);
    }

    const service = createServiceClient();
    if (!service) {
      return jsonError(
        "Server is missing the Supabase service key; cannot queue a scan.",
        503,
      );
    }

    const { data: jobId, error } = await service.rpc("enqueue_scan", {
      p_owner: auth.data.userId,
      p_project_id: resolvedProjectId,
      p_asset_id: assetId ?? null,
      p_reason: "manual",
      p_payload: { notify, dry_run, full_scan: !assetId },
    });

    if (error || !jobId) {
      return jsonError("Could not queue the scan", 500);
    }

    // Best-effort immediate dispatch. If it fails the job stays pending and
    // the cron-based drain retries with backoff, so the scan is not lost.
    const { drainDispatchQueue } = await import("@/lib/monitoring/dispatcher");
    const drain = await drainDispatchQueue(1).catch(() => null);

    const dispatched = drain?.jobs.some((j) => j.id === jobId && j.status === "queued");

    return NextResponse.json(
      {
        job_id: jobId,
        status: dispatched ? "queued" : "pending",
        message: dispatched
          ? "Scan accepted by GitHub Actions and queued."
          : "Scan queued. GitHub dispatch is pending and will retry automatically.",
        project_id: resolvedProjectId,
        asset_id: assetId ?? null,
      },
      { status: 202 },
    );
  });
}

/** GET /api/scan/trigger — list recent dispatch jobs for the caller. */
export async function GET(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const projectId = new URL(request.url).searchParams.get("project_id");
    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    let query = supabase
      .from("dispatch_jobs")
      .select("*")
      .eq("owner_id", auth.data.userId)
      .order("created_at", { ascending: false })
      .limit(50);

    if (projectId) {
      if (!(await assertProjectOwnership(supabase, projectId, auth.data.userId))) {
        return jsonError("Project not found", 404);
      }
      query = query.eq("project_id", projectId);
    }

    const { data, error } = await query;
    if (error) return jsonError("Could not load scan jobs", 500);

    return NextResponse.json({ jobs: data ?? [] });
  });
}
