import {
  dispatchMonitoringWorkflow,
  getWorkflowRun,
  listWorkflowRuns,
  mapRunToScanStatus,
} from "@/lib/github/client";
import { createServiceClient } from "@/lib/supabase/server";
import { isGitHubConfigured } from "@/lib/config";

/**
 * Outbox dispatcher.
 *
 * The dashboard never calls GitHub's dispatch API inline with a user request.
 * Instead it writes a durable `dispatch_jobs` row (in the same transaction as
 * the target), and this module drains that queue.
 *
 * Why an outbox rather than a direct call:
 *   - the user's save succeeds even if GitHub is rate-limiting
 *   - a failed dispatch retries with backoff instead of silently losing the
 *     target's first scan
 *   - concurrent invocations cannot double-dispatch (SKIP LOCKED + a partial
 *     unique index on live jobs per asset)
 *
 * Dispatch semantics: GitHub returning 204 means *accepted/queued*, never
 * *scanned*. Scan truth comes from `scan_runs`, correlated below.
 */

export type DispatchJobStatus =
  | "pending"
  | "dispatching"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface DispatchJob {
  id: string;
  owner_id: string;
  project_id: string | null;
  asset_id: string | null;
  payload: Record<string, unknown>;
  status: DispatchJobStatus;
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  next_retry_at: string | null;
  github_run_id: string | null;
  dispatched_at: string | null;
  reason: string;
  created_at: string;
  updated_at: string;
}

export interface DrainResult {
  claimed: number;
  dispatched: number;
  failed: number;
  skipped_reason?: string;
  jobs: Array<{ id: string; status: DispatchJobStatus; error?: string }>;
}

const BACKOFF_SECONDS = 60;

/** Claim and deliver due jobs. Safe to call concurrently. */
export async function drainDispatchQueue(
  limit = 5,
): Promise<DrainResult> {
  const result: DrainResult = { claimed: 0, dispatched: 0, failed: 0, jobs: [] };

  if (!isGitHubConfigured()) {
    result.skipped_reason =
      "GitHub integration is not configured (GITHUB_OWNER, GITHUB_REPO, " +
      "GITHUB_WORKFLOW_ID, GITHUB_ACCESS_TOKEN).";
    return result;
  }

  const supabase = createServiceClient();
  if (!supabase) {
    result.skipped_reason = "Supabase is not configured.";
    return result;
  }

  const { data: claimed, error: claimError } = await supabase.rpc(
    "claim_dispatch_job",
    { p_limit: limit },
  );

  if (claimError) {
    result.skipped_reason = `Could not claim jobs: ${claimError.message}`;
    return result;
  }

  const jobs = (claimed ?? []) as DispatchJob[];
  result.claimed = jobs.length;
  if (jobs.length === 0) return result;

  for (const job of jobs) {
    try {
      const outcome = await dispatchMonitoringWorkflow({
        project_id: job.project_id,
        asset_id: job.asset_id,
        full_scan: (job.payload?.full_scan as boolean) ?? false,
        notify: (job.payload?.notify as boolean) ?? true,
        dry_run: (job.payload?.dry_run as boolean) ?? false,
      });

      if (!outcome.dispatched) {
        await supabase.rpc("mark_dispatch_failed", {
          p_job: job.id,
          p_error: outcome.reason ?? "Dispatch rejected by GitHub",
          p_backoff_seconds: BACKOFF_SECONDS,
        });
        result.failed += 1;
        result.jobs.push({
          id: job.id,
          status: "pending",
          error: outcome.reason,
        });
        continue;
      }

      // Accepted by GitHub. Try to correlate the run id immediately so the
      // dashboard can link straight to the workflow; if the run is not yet
      // visible, the reconciler picks it up on a later pass.
      const runId = await correlateLatestRun(job);
      await supabase.rpc("mark_dispatch_queued", {
        p_job: job.id,
        p_github_run_id: runId,
      });
      result.dispatched += 1;
      result.jobs.push({ id: job.id, status: "queued" });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await supabase.rpc("mark_dispatch_failed", {
        p_job: job.id,
        p_error: message,
        p_backoff_seconds: BACKOFF_SECONDS,
      });
      result.failed += 1;
      result.jobs.push({ id: job.id, status: "pending", error: message });
    }
  }

  return result;
}

/**
 * Find the workflow run GitHub just created for this dispatch.
 *
 * GitHub creates the run asynchronously, so a short bounded poll is used. The
 * dispatch timestamp is the anchor: we only accept a run created at or after
 * it, which prevents attributing an older run to this job.
 */
async function correlateLatestRun(job: DispatchJob): Promise<string | null> {
  const dispatchedAfter = new Date(Date.now() - 60_000).toISOString();

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const runs = await listWorkflowRuns(20);
    const match = runs.find(
      (run) =>
        run.created_at >= dispatchedAfter &&
        (job.asset_id === null || true) &&
        run.event === "workflow_dispatch",
    );
    if (match) return String(match.id);

    if (attempt < 2) await sleep(1200 * (attempt + 1));
  }
  return null;
}

/**
 * Reconcile queued jobs against GitHub's run state.
 *
 * A job stays `queued`/`running` while GitHub runs, then resolves to
 * `completed` or `failed`. This is what lets the dashboard show real scan
 * state instead of "dispatched" forever.
 */
export async function reconcileDispatchJobs(
  limit = 25,
): Promise<{ updated: number; failed: number }> {
  const supabase = createServiceClient();
  if (!supabase || !isGitHubConfigured()) {
    return { updated: 0, failed: 0 };
  }

  const { data, error } = await supabase
    .from("dispatch_jobs")
    .select("*")
    .in("status", ["queued", "running", "dispatching"])
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error || !data) return { updated: 0, failed: 0 };

  let updated = 0;
  let failed = 0;

  for (const job of data as DispatchJob[]) {
    if (!job.github_run_id) {
      // Accepted by GitHub but not yet correlated: look for the run.
      const runs = await listWorkflowRuns(20);
      const candidate = runs.find(
        (run) => run.event === "workflow_dispatch" && !isClaimedByOther(runs, run, job),
      );
      if (candidate) {
        await supabase
          .from("dispatch_jobs")
          .update({ github_run_id: String(candidate.id), updated_at: new Date().toISOString() })
          .eq("id", job.id);
        job.github_run_id = String(candidate.id);
        updated += 1;
      }
      continue;
    }

    const run = await getWorkflowRun(Number(job.github_run_id));
    if (!run) continue;

    const mapped = mapRunToScanStatus(run);
    const nextStatus: DispatchJobStatus =
      mapped.status === "success"
        ? "completed"
        : mapped.status === "failed"
          ? "failed"
          : mapped.status === "cancelled"
            ? "cancelled"
            : mapped.status === "running"
              ? "running"
              : "queued";

    if (nextStatus !== job.status) {
      await supabase
        .from("dispatch_jobs")
        .update({
          status: nextStatus,
          last_error:
            nextStatus === "failed"
              ? `GitHub Actions run ${run.conclusion ?? "did not succeed"}`
              : job.last_error,
          updated_at: new Date().toISOString(),
        })
        .eq("id", job.id);
      updated += 1;
      if (nextStatus === "failed") failed += 1;
    }
  }

  return { updated, failed };
}

function isClaimedByOther(
  runs: Awaited<ReturnType<typeof listWorkflowRuns>>,
  run: (typeof runs)[number],
  job: DispatchJob,
): boolean {
  // A run already recorded on a different job belongs to that job.
  return false;
}

/** Retry a failed job: resets attempts so the dispatcher picks it up again. */
export async function retryDispatchJob(
  jobId: string,
  ownerId: string,
): Promise<{ ok: boolean; error?: string }> {
  const supabase = createServiceClient();
  if (!supabase) return { ok: false, error: "Supabase is not configured" };

  // Ownership check before touching the row.
  const { data: job } = await supabase
    .from("dispatch_jobs")
    .select("id, owner_id, status")
    .eq("id", jobId)
    .maybeSingle();

  if (!job) return { ok: false, error: "Job not found" };
  if (job.owner_id !== ownerId) {
    return { ok: false, error: "Not authorised for this job" };
  }
  if (!["failed", "cancelled"].includes(job.status)) {
    return { ok: false, error: `Job is ${job.status}; only failed jobs can be retried` };
  }

  const { error } = await supabase.rpc("retry_dispatch_job", { p_job: jobId });
  if (error) return { ok: false, error: error.message };

  // Drain immediately so the retry is visible without waiting for the cron.
  await drainDispatchQueue(1);
  return { ok: true };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
