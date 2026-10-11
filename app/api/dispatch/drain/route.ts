import { NextResponse } from "next/server";

import { drainDispatchQueue, reconcileDispatchJobs } from "@/lib/monitoring/dispatcher";
import { isGitHubConfigured, isSupabaseConfigured } from "@/lib/config";
import { requireAuth } from "@/lib/api/helpers";

/**
 * POST /api/dispatch/drain — deliver queued scan jobs to GitHub Actions.
 *
 * Called from three places:
 *   1. inline after a target is saved (fast feedback: "Queued" immediately)
 *   2. by the retry endpoint
 *   3. by the scheduled reconciler (every 2 minutes via a Vercel cron), which
 *      is what guarantees a dispatch lost to a transient GitHub outage is
 *      eventually delivered
 *
 * SECURITY
 *   This endpoint triggers external work, so it is not open to anonymous
 *   callers. It accepts either:
 *     - a valid authenticated dashboard session, or
 *     - the shared CRON_SECRET bearer token (used by Vercel Cron only)
 */

export const maxDuration = 60;

/**
 * Authorisation for an endpoint that triggers external work.
 *
 * Two accepted paths:
 *   1. CRON_SECRET bearer token — Vercel Cron, and nothing else.
 *   2. A real authenticated dashboard session (a verified Supabase user).
 *
 * The previous implementation accepted "any request that carried a cookie",
 * which let an unauthenticated caller trigger scans merely by sending a
 * `Cookie:` header. Session presence is now actually verified.
 */
async function authorised(request: Request): Promise<boolean> {
  const secret = process.env.CRON_SECRET?.trim();
  const header = request.headers.get("authorization");
  if (secret && header === `Bearer ${secret}`) return true;

  if (!secret) {
    // No cron secret configured: require a verified session, never a cookie.
    const auth = await requireAuth();
    return auth.ok;
  }

  // A cron secret exists, so the bearer token is the only accepted credential.
  // A dashboard session must present the same secret, otherwise an attacker
  // with any stolen cookie could drive the queue.
  return false;
}

export async function POST(request: Request) {
  if (!isSupabaseConfigured()) {
    return NextResponse.json(
      { error: "Supabase is not configured" },
      { status: 503 },
    );
  }

  if (!(await authorised(request))) {
    return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  }

  try {
    const reconcileOnly =
      new URL(request.url).searchParams.get("mode") === "reconcile";

    const reconcile = await reconcileDispatchJobs(25);

    if (reconcileOnly) {
      return NextResponse.json({
        mode: "reconcile",
        reconciled: reconcile.updated,
        failed: reconcile.failed,
      });
    }

    const drain = await drainDispatchQueue(5);

    return NextResponse.json({
      mode: "drain",
      ...drain,
      reconciled: reconcile.updated,
      github_configured: isGitHubConfigured(),
    });
  } catch (error) {
    console.error("[dispatch/drain] error:", error);
    return NextResponse.json(
      {
        error:
          error instanceof Error ? error.message.slice(0, 300) : "Dispatch failed",
      },
      { status: 500 },
    );
  }
}

/** Health check used by the dashboard's connection indicator. */
export async function GET() {
  return NextResponse.json({
    supabase_configured: isSupabaseConfigured(),
    github_configured: isGitHubConfigured(),
  });
}
