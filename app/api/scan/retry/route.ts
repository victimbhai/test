import { NextResponse } from "next/server";

import { retryDispatchJob } from "@/lib/monitoring/dispatcher";
import { jsonError, requireAuth, withErrorHandling } from "@/lib/api/helpers";

/**
 * POST /api/scan/retry — retry a failed dispatch.
 *
 * A target is never discarded when a dispatch fails: the job stays in the
 * outbox with its error, and this endpoint resets it so the dispatcher
 * delivers it again.
 */

export async function POST(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return jsonError("Request body must be valid JSON", 400);
    }

    const jobId =
      typeof body === "object" && body !== null && "job_id" in body
        ? String((body as { job_id: unknown }).job_id)
        : new URL(request.url).searchParams.get("job_id");

    if (!jobId) return jsonError("job_id is required", 400);

    const result = await retryDispatchJob(jobId, auth.data.userId);
    if (!result.ok) {
      return jsonError(result.error ?? "Retry failed", 400);
    }

    return NextResponse.json({
      job_id: jobId,
      status: "pending",
      message: "Scan re-queued. GitHub dispatch will be attempted immediately.",
    });
  });
}
