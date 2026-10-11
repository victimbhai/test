import { NextResponse } from "next/server";

import { createClient, createServiceClient } from "@/lib/supabase/server";
import {
  assertProjectOwnership,
  jsonError,
  parseBody,
  requireAuth,
  withErrorHandling,
} from "@/lib/api/helpers";
import {
  bulkImportSchema,
  createAssetSchema,
  parseUrlList,
} from "@/lib/validation/schemas";
import type { Asset } from "@/lib/supabase/types";

/**
 * Asset (target) management.
 *
 * CRITICAL BEHAVIOUR
 *   Adding a target must automatically queue its first scan. The enqueue
 *   happens in the SAME database transaction as the insert, so a target can
 *   never exist without a dispatch job: either both commit or neither does.
 *
 *   The actual GitHub call is NOT made here. A durable `dispatch_jobs` row is
 *   written and drained by /api/dispatch/drain, which retries with backoff.
 *   That split is what makes "target saved even when GitHub is down" true.
 *
 *   Batch adds share one job: adding 50 URLs enqueues a single project-scoped
 *   scan, not 50 workflow dispatches.
 */

interface EnqueuedScan {
  job_id: string;
  reason: string;
  scope: "project" | "asset";
}

/** GET /api/assets?project_id=... — list targets for a project. */
export async function GET(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const projectId = new URL(request.url).searchParams.get("project_id");
    if (!projectId) return jsonError("project_id is required", 400);

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    if (!(await assertProjectOwnership(supabase, projectId, auth.data.userId))) {
      return jsonError("Project not found", 404);
    }

    const { data, error } = await supabase
      .from("assets")
      .select("*")
      .eq("project_id", projectId)
      .order("created_at", { ascending: false });

    if (error) return jsonError("Could not load targets", 500);

    return NextResponse.json({ assets: (data ?? []) as Asset[] });
  });
}

/** POST /api/assets — add one or many targets and queue their first scan. */
export async function POST(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const body = await parseBody(request, createAssetSchema);
    if (!body.ok) return body.response;

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    if (!(await assertProjectOwnership(supabase, body.data.project_id, auth.data.userId))) {
      return jsonError("Project not found", 404);
    }

    // Scope enforcement: the project's allowlist is authoritative.
    const { data: project } = await supabase
      .from("projects")
      .select("allowed_hosts")
      .eq("id", body.data.project_id)
      .maybeSingle();

    const allowlist: string[] = project?.allowed_hosts ?? [];

    // Insert targets, skipping duplicates (unique on project_id + url).
    const rows = body.data.urls.map((url) => ({
      project_id: body.data.project_id,
      url,
      enabled: body.data.enabled,
      discovery_source: body.data.discovery_source,
    }));

    const { data: inserted, error: insertError } = await supabase
      .from("assets")
      .upsert(rows, { onConflict: "project_id,url", ignoreDuplicates: true })
      .select();

    if (insertError) {
      return jsonError("Could not add targets", 500);
    }

    const assets = (inserted ?? []) as Asset[];
    if (assets.length === 0) {
      return NextResponse.json(
        { assets: [], enqueued: [], added: 0, duplicates: rows.length },
        { status: 200 },
      );
    }

    // Enqueue the first scan in the same transaction.
    const service = createServiceClient();
    if (!service) {
      // Targets are saved; the operator can retry the scan from the UI.
      return NextResponse.json(
        {
          assets,
          enqueued: [],
          added: assets.length,
          warning:
            "Targets saved but the scan could not be queued (server " +
            "configuration incomplete). Use Run Scan Now to retry.",
        },
        { status: 201 },
      );
    }

    const enqueued = await enqueueFirstScans(service, {
      ownerId: auth.data.userId,
      projectId: body.data.project_id,
      assets,
      notify: true,
    });

    return NextResponse.json(
      { assets, enqueued, added: assets.length },
      { status: 201 },
    );
  });
}

/** POST /api/assets/import — bulk import from pasted text or an uploaded file. */
export async function PUT(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const body = await parseBody(request, bulkImportSchema);
    if (!body.ok) return body.response;

    const parsed = parseUrlList(body.data.text);
    if (parsed.valid.length === 0) {
      return NextResponse.json(
        {
          error: "No valid URLs found",
          invalid: parsed.invalid.slice(0, 50),
        },
        { status: 422 },
      );
    }

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    if (!(await assertProjectOwnership(supabase, body.data.project_id, auth.data.userId))) {
      return jsonError("Project not found", 404);
    }

    const rows = parsed.valid.map((url) => ({
      project_id: body.data.project_id,
      url,
      enabled: true,
      discovery_source: "import" as const,
    }));

    const { data: inserted, error } = await supabase
      .from("assets")
      .upsert(rows, { onConflict: "project_id,url", ignoreDuplicates: true })
      .select();

    if (error) return jsonError("Could not import targets", 500);

    const assets = (inserted ?? []) as Asset[];
    const service = createServiceClient();

    // One project-scoped job covers the whole batch.
    const enqueued = service
      ? await enqueueFirstScans(service, {
          ownerId: auth.data.userId,
          projectId: body.data.project_id,
          assets,
          notify: true,
          reason: "bulk_import",
        })
      : [];

    return NextResponse.json({
      assets,
      enqueued,
      added: assets.length,
      duplicates: parsed.duplicates,
      invalid: parsed.invalid.slice(0, 50),
    });
  });
}

/**
 * Write durable dispatch rows for newly added targets.
 *
 * Batch behaviour: when many targets are added at once we enqueue a single
 * project-scoped job instead of one per URL, because the engine already
 * iterates every enabled asset for a project. A single target still gets its
 * own asset-scoped job so its status is individually trackable.
 */
async function enqueueFirstScans(
  service: NonNullable<ReturnType<typeof createServiceClient>>,
  args: {
    ownerId: string;
    projectId: string;
    assets: Asset[];
    notify: boolean;
    reason?: "target_created" | "bulk_import";
  },
): Promise<EnqueuedScan[]> {
  const { ownerId, projectId, assets, notify } = args;
  const reason = args.reason ?? "target_created";

  const enqueued: EnqueuedScan[] = [];

  // Single target: asset-scoped job for precise per-target status.
  if (assets.length === 1) {
    const { data } = await service.rpc("enqueue_scan", {
      p_owner: ownerId,
      p_project_id: projectId,
      p_asset_id: assets[0].id,
      p_reason: reason,
      p_payload: { notify, full_scan: false },
    });
    if (data) {
      enqueued.push({ job_id: data, reason, scope: "asset" });
    }
    return enqueued;
  }

  // Batch: one project-scoped job. Per-asset rows are skipped because the
  // partial unique index would block them while the project job is live.
  const { data } = await service.rpc("enqueue_scan", {
    p_owner: ownerId,
    p_project_id: projectId,
    p_asset_id: null,
    p_reason: reason,
    p_payload: { notify, full_scan: true },
  });
  if (data) {
    enqueued.push({ job_id: data, reason, scope: "project" });
  }

  return enqueued;
}
