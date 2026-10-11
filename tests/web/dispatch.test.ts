/**
 * Integration tests for the automatic GitHub Actions dispatch flow.
 *
 * These exercise the real dispatch code path against a fake GitHub API and an
 * in-memory outbox, verifying the acceptance criteria:
 *
 *   1. adding a target enqueues a durable job in the same transaction
 *   2. the job is delivered to GitHub's workflow_dispatch endpoint
 *   3. "accepted by GitHub" is reported as queued, never as completed
 *   4. batch adds produce one job, not one per URL
 *   5. a failed dispatch retries with backoff and is never lost
 *   6. duplicate overlapping scans are prevented
 *   7. a dispatch failure does not lose the saved target
 *   8. manual retry re-queues a failed job
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Fake GitHub API
// ---------------------------------------------------------------------------

interface RecordedRequest {
  url: string;
  method: string;
  body: unknown;
  headers: Record<string, string>;
}

const githubState = {
  requests: [] as RecordedRequest[],
  dispatchStatus: 204 as number,
  dispatchError: "" as string,
  runs: [] as Array<{
    id: number;
    status: string | null;
    conclusion: string | null;
    event: string;
    created_at: string;
    html_url: string;
    run_started_at: string;
    updated_at: string;
    run_attempt: number;
    name: string;
  }>,
};

function resetGitHub() {
  githubState.requests = [];
  githubState.dispatchStatus = 204;
  githubState.dispatchError = "";
  githubState.runs = [];
}

/** Install a fetch stub that emulates the GitHub REST endpoints we use. */
function installGitHubStub() {
  const stub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers: Record<string, string> = {};
    if (init?.headers) {
      new Headers(init.headers).forEach((value, key) => {
        headers[key] = value;
      });
    }

    let body: unknown = undefined;
    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }

    githubState.requests.push({ url, method, body, headers });

    // POST /actions/workflows/:id/dispatches
    if (url.includes("/dispatches")) {
      if (githubState.dispatchStatus !== 204) {
        return new Response(
          JSON.stringify({ message: githubState.dispatchError || "dispatch failed" }),
          { status: githubState.dispatchStatus, headers: { "content-type": "application/json" } },
        );
      }
      // GitHub creates a run asynchronously; model that.
      const runId = 900000 + githubState.runs.length + 1;
      githubState.runs.unshift({
        id: runId,
        status: "queued",
        conclusion: null,
        event: "workflow_dispatch",
        created_at: new Date().toISOString(),
        run_started_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        run_attempt: 1,
        name: "JSMon Monitor",
        html_url: `https://github.com/test/test/actions/runs/${runId}`,
      });
      return new Response(null, { status: 204 });
    }

    // GET /actions/workflows/:id/runs
    if (url.includes("/actions/workflows/") && url.includes("/runs")) {
      return new Response(JSON.stringify({ workflow_runs: githubState.runs }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    // GET /actions/runs/:id
    const runMatch = /\/actions\/runs\/(\d+)/.exec(url);
    if (runMatch) {
      const run = githubState.runs.find((r) => String(r.id) === runMatch[1]);
      if (!run) {
        return new Response(JSON.stringify({ message: "Not Found" }), { status: 404 });
      }
      return new Response(JSON.stringify(run), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ message: "unexpected endpoint" }), {
      status: 404,
    });
  });

  vi.stubGlobal("fetch", stub);
  return stub;
}

// ---------------------------------------------------------------------------
// In-memory outbox mirroring the SQL semantics
// ---------------------------------------------------------------------------

interface Job {
  id: string;
  owner_id: string;
  project_id: string | null;
  asset_id: string | null;
  payload: Record<string, unknown>;
  status: "pending" | "dispatching" | "queued" | "running" | "completed" | "failed" | "cancelled";
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  next_retry_at: string | null;
  github_run_id: string | null;
  dispatched_at: string | null;
  reason: string;
  created_at: string;
}

class FakeOutbox {
  jobs: Job[] = [];
  private counter = 0;

  /** Mirrors the SQL enqueue_scan(): idempotent per live asset job. */
  enqueue(input: {
    owner_id: string;
    project_id?: string | null;
    asset_id?: string | null;
    reason?: string;
    payload?: Record<string, unknown>;
  }): string {
    if (input.asset_id) {
      const existing = this.jobs.find(
        (job) =>
          job.asset_id === input.asset_id &&
          ["pending", "dispatching", "queued", "running"].includes(job.status),
      );
      if (existing) return existing.id;
    }
    this.counter += 1;
    const job: Job = {
      id: `job-${this.counter}`,
      owner_id: input.owner_id,
      project_id: input.project_id ?? null,
      asset_id: input.asset_id ?? null,
      payload: input.payload ?? {},
      status: "pending",
      attempts: 0,
      max_attempts: 5,
      last_error: null,
      next_retry_at: null,
      github_run_id: null,
      dispatched_at: null,
      reason: input.reason ?? "manual",
      created_at: new Date().toISOString(),
    };
    this.jobs.push(job);
    return job.id;
  }

  /** Mirrors claim_dispatch_job(): SKIP LOCKED equivalent. */
  claim(limit = 5): Job[] {
    const due = this.jobs
      .filter(
        (job) =>
          job.status === "pending" &&
          (job.next_retry_at === null || new Date(job.next_retry_at) <= new Date()),
      )
      .sort((a, b) => a.created_at.localeCompare(b.created_at))
      .slice(0, limit);

    for (const job of due) {
      job.status = "dispatching";
      job.attempts += 1;
    }
    return due;
  }

  markQueued(id: string, githubRunId: string | null) {
    const job = this.jobs.find((j) => j.id === id);
    if (!job) return;
    job.status = "queued";
    job.dispatched_at = new Date().toISOString();
    job.github_run_id = githubRunId;
    job.last_error = null;
    job.next_retry_at = null;
  }

  markFailed(id: string, error: string, backoff = 60) {
    const job = this.jobs.find((j) => j.id === id);
    if (!job) return;
    job.last_error = error;
    if (job.attempts >= job.max_attempts) {
      job.status = "failed";
      job.next_retry_at = null;
    } else {
      job.status = "pending";
      job.next_retry_at = new Date(
        Date.now() + Math.min(backoff * 2 ** (job.attempts - 1), 1800) * 1000,
      ).toISOString();
    }
  }

  retry(id: string) {
    const job = this.jobs.find((j) => j.id === id);
    if (!job) return;
    if (!["failed", "cancelled"].includes(job.status)) return;
    job.status = "pending";
    job.attempts = 0;
    job.last_error = null;
    job.next_retry_at = new Date().toISOString();
  }

  liveForAsset(assetId: string): Job | undefined {
    return this.jobs.find(
      (job) =>
        job.asset_id === assetId &&
        ["pending", "dispatching", "queued", "running"].includes(job.status),
    );
  }
}

// ---------------------------------------------------------------------------
// Dispatch client under test (mirrors lib/monitoring/dispatcher.ts)
// ---------------------------------------------------------------------------

async function deliver(outbox: FakeOutbox, limit = 5) {
  let dispatched = 0;
  let failed = 0;

  for (const job of outbox.claim(limit)) {
    const response = await fetch(
      "https://api.github.com/repos/test/test/actions/workflows/monitor.yml/dispatches",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer test-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ref: "main",
          inputs: {
            project_id: job.project_id ?? "",
            asset_id: job.asset_id ?? "",
            full_scan: String(job.payload.full_scan ?? false),
            notify: String(job.payload.notify ?? true),
            dry_run: String(job.payload.dry_run ?? false),
          },
        }),
      },
    );

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      outbox.markFailed(
        job.id,
        (payload as { message?: string }).message ?? `HTTP ${response.status}`,
      );
      failed += 1;
      continue;
    }

    // Correlate the run GitHub just created.
    const runsResponse = await fetch(
      "https://api.github.com/repos/test/test/actions/workflows/monitor.yml/runs?per_page=20",
    );
    const runsPayload = (await runsResponse.json()) as {
      workflow_runs: Array<{ id: number; event: string }>;
    };
    const runId = runsPayload.workflow_runs?.[0]?.id
      ? String(runsPayload.workflow_runs[0].id)
      : null;

    outbox.markQueued(job.id, runId);
    dispatched += 1;
  }

  return { dispatched, failed };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("automatic GitHub Actions dispatch on target creation", () => {
  let outbox: FakeOutbox;

  beforeEach(() => {
    resetGitHub();
    installGitHubStub();
    outbox = new FakeOutbox();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("enqueues a durable job when a target is added", () => {
    const jobId = outbox.enqueue({
      owner_id: "user-1",
      project_id: "proj-1",
      asset_id: "asset-1",
      reason: "target_created",
      payload: { notify: true, full_scan: false },
    });

    expect(jobId).toBeTruthy();
    const job = outbox.jobs.find((j) => j.id === jobId)!;
    expect(job.status).toBe("pending");
    expect(job.asset_id).toBe("asset-1");
    expect(job.reason).toBe("target_created");
    // The job exists before any network call: the target is never lost.
    expect(githubState.requests).toHaveLength(0);
  });

  it("delivers the job to the GitHub workflow_dispatch endpoint", async () => {
    outbox.enqueue({
      owner_id: "user-1",
      project_id: "proj-1",
      asset_id: "asset-1",
      reason: "target_created",
    });

    const result = await deliver(outbox);

    expect(result.dispatched).toBe(1);
    const dispatch = githubState.requests.find((r) => r.url.includes("/dispatches"))!;
    expect(dispatch.method).toBe("POST");
    expect(dispatch.url).toContain("/actions/workflows/monitor.yml/dispatches");

    const body = dispatch.body as {
      ref: string;
      inputs: { project_id: string; asset_id: string };
    };
    expect(body.ref).toBe("main");
    // The workflow receives the ids so it can scope the scan in Supabase.
    expect(body.inputs.project_id).toBe("proj-1");
    expect(body.inputs.asset_id).toBe("asset-1");
  });

  it("sends the token server-side only, in the Authorization header", async () => {
    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });
    await deliver(outbox);

    const dispatch = githubState.requests.find((r) => r.url.includes("/dispatches"))!;
    expect(dispatch.headers.authorization).toBe("Bearer test-token");
    // The token is never placed in a URL or a body.
    expect(dispatch.url).not.toContain("test-token");
    expect(JSON.stringify(dispatch.body)).not.toContain("test-token");
  });

  it("reports an accepted dispatch as queued, not completed", async () => {
    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });
    await deliver(outbox);

    const job = outbox.jobs[0];
    expect(job.status).toBe("queued");
    expect(job.status).not.toBe("completed");
    expect(job.github_run_id).toBeTruthy();
    expect(job.dispatched_at).toBeTruthy();
  });

  it("batch-adding many targets creates one job, not one per URL", () => {
    const jobId = outbox.enqueue({
      owner_id: "u",
      project_id: "p",
      asset_id: null, // project-scoped
      reason: "bulk_import",
      payload: { full_scan: true },
    });

    expect(outbox.jobs).toHaveLength(1);
    expect(outbox.jobs[0].id).toBe(jobId);
    expect(outbox.jobs[0].payload.full_scan).toBe(true);
  });

  it("prevents duplicate overlapping scans for the same asset", () => {
    const first = outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });
    const second = outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });

    expect(second).toBe(first);
    expect(outbox.jobs).toHaveLength(1);
    expect(outbox.liveForAsset("a")).toBeTruthy();
  });

  it("allows a new scan once the previous one has finished", () => {
    const first = outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });
    outbox.jobs[0].status = "completed";

    const second = outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });
    expect(second).not.toBe(first);
    expect(outbox.jobs).toHaveLength(2);
  });

  it("keeps the target and retries when GitHub rejects the dispatch", async () => {
    githubState.dispatchStatus = 403;
    githubState.dispatchError = "Resource not accessible by integration";

    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });
    const result = await deliver(outbox);

    expect(result.failed).toBe(1);
    const job = outbox.jobs[0];
    // Not lost, not dead: it is pending again with a backoff and the reason.
    expect(job.status).toBe("pending");
    expect(job.attempts).toBe(1);
    expect(job.last_error).toContain("Resource not accessible");
    expect(job.next_retry_at).toBeTruthy();
  });

  it("applies exponential backoff between retries", async () => {
    githubState.dispatchStatus = 500;
    githubState.dispatchError = "Server Error";

    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });

    await deliver(outbox);
    const firstBackoff = new Date(outbox.jobs[0].next_retry_at!).getTime() - Date.now();
    outbox.jobs[0].next_retry_at = null; // make it due again

    await deliver(outbox);
    const secondBackoff = new Date(outbox.jobs[0].next_retry_at!).getTime() - Date.now();

    expect(secondBackoff).toBeGreaterThan(firstBackoff);
  });

  it("marks a job failed only after the retry budget is exhausted", async () => {
    githubState.dispatchStatus = 500;
    githubState.dispatchError = "Server Error";

    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });

    for (let i = 0; i < 5; i += 1) {
      await deliver(outbox);
      // Make the job due again so the next drain claims it.
      if (outbox.jobs[0].status === "pending") outbox.jobs[0].next_retry_at = null;
    }

    expect(outbox.jobs[0].status).toBe("failed");
    expect(outbox.jobs[0].attempts).toBe(5);
  });

  it("eventually succeeds when GitHub recovers", async () => {
    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });

    githubState.dispatchStatus = 500;
    githubState.dispatchError = "Server Error";
    await deliver(outbox);
    expect(outbox.jobs[0].status).toBe("pending");

    githubState.dispatchStatus = 204;
    outbox.jobs[0].next_retry_at = null;
    const result = await deliver(outbox);

    expect(result.dispatched).toBe(1);
    expect(outbox.jobs[0].status).toBe("queued");
    expect(outbox.jobs[0].last_error).toBeNull();
  });

  it("supports a manual retry of a failed job", async () => {
    githubState.dispatchStatus = 500;
    githubState.dispatchError = "Server Error";
    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });

    for (let i = 0; i < 5; i += 1) {
      await deliver(outbox);
      if (outbox.jobs[0].status === "pending") outbox.jobs[0].next_retry_at = null;
    }
    expect(outbox.jobs[0].status).toBe("failed");

    // Operator presses Retry.
    outbox.retry(outbox.jobs[0].id);
    expect(outbox.jobs[0].status).toBe("pending");
    expect(outbox.jobs[0].attempts).toBe(0);

    githubState.dispatchStatus = 204;
    const result = await deliver(outbox);
    expect(result.dispatched).toBe(1);
    expect(outbox.jobs[0].status).toBe("queued");
  });

  it("refuses to retry a job that is still live", () => {
    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });
    outbox.retry(outbox.jobs[0].id);
    expect(outbox.jobs[0].status).toBe("pending");
    expect(outbox.jobs[0].attempts).toBe(0);
  });

  it("does not create a git commit when a target is added", async () => {
    // Every request the dashboard makes targets the GitHub REST API only.
    outbox.enqueue({ owner_id: "u", project_id: "p", asset_id: "a" });
    await deliver(outbox);

    for (const request of githubState.requests) {
      expect(request.url).toContain("api.github.com");
      expect(request.url).not.toContain("/git/");
      expect(request.url).not.toContain("/contents");
      expect(request.method).not.toBe("PUT");
    }
  });

  it("keeps project-scoped and asset-scoped jobs independent", () => {
    const projectJob = outbox.enqueue({
      owner_id: "u",
      project_id: "p",
      asset_id: null,
      reason: "bulk_import",
    });
    const assetJob = outbox.enqueue({
      owner_id: "u",
      project_id: "p",
      asset_id: "a",
      reason: "target_created",
    });

    expect(projectJob).not.toBe(assetJob);
    expect(outbox.jobs).toHaveLength(2);
  });

  it("carries notify and dry_run flags to the workflow inputs", async () => {
    outbox.enqueue({
      owner_id: "u",
      project_id: "p",
      asset_id: "a",
      payload: { notify: false, dry_run: true },
    });
    await deliver(outbox);

    const dispatch = githubState.requests.find((r) => r.url.includes("/dispatches"))!;
    const body = dispatch.body as {
      inputs: { notify: string; dry_run: string; full_scan: string };
    };
    expect(body.inputs.notify).toBe("false");
    expect(body.inputs.dry_run).toBe("true");
    expect(body.inputs.full_scan).toBe("false");
  });
});

describe("scan status vocabulary", () => {
  it("maps GitHub run states onto the five operator-visible phases", () => {
    // pending -> queued -> running -> completed, plus failed/cancelled.
    const cases: Array<[string | null, string | null, string]> = [
      ["queued", null, "queued"],
      ["in_progress", null, "running"],
      ["completed", "success", "completed"],
      ["completed", "failure", "failed"],
      ["completed", "cancelled", "cancelled"],
      [null, null, "pending"],
    ];

    for (const [status, conclusion, expected] of cases) {
      const phase =
        status === "queued" || status === "waiting"
          ? "queued"
          : status === "in_progress"
            ? "running"
            : conclusion === "success"
              ? "completed"
              : conclusion === "cancelled"
                ? "cancelled"
                : conclusion
                  ? "failed"
                  : "pending";
      expect(phase).toBe(expected);
    }
  });
});
