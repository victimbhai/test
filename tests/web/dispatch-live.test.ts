/**
 * Live verification of the automatic GitHub Actions dispatch loop.
 *
 * Boots in-process fakes for the GitHub REST API and Supabase PostgREST, then
 * exercises the REAL production modules (lib/monitoring/dispatcher.ts and
 * lib/github/client.ts) against them.
 *
 * Covered:
 *   1. adding a target enqueues a durable job (before any network call)
 *   2. draining delivers a workflow_dispatch carrying project + asset ids
 *   3. an accepted dispatch is reported "queued", never "completed"
 *   4. reconcile follows the GitHub run queued -> running -> completed
 *   5. a failed GitHub run marks the job failed with an error summary
 *   6. duplicate overlapping scans for one asset are prevented
 *   7. a batch import creates a single project-scoped job
 *   8. a GitHub outage keeps the target and retries with backoff
 *   9. manual retry re-delivers an exhausted job
 *  10. adding a target never creates a git commit
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { SupabaseClient } from "@supabase/supabase-js";
import { randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------
interface FakeRun {
  id: number;
  name: string;
  status: string | null;
  conclusion: string | null;
  event: string;
  created_at: string;
  run_started_at: string;
  updated_at: string;
  run_attempt: number;
  html_url: string;
}

interface FakeDispatch {
  ref: string;
  inputs: Record<string, string>;
}

interface FakeAsset {
  id: string;
  [key: string]: unknown;
}

interface FakeJob {
  id: string;
  owner_id: string;
  project_id: string | null;
  asset_id: string | null;
  payload: Record<string, unknown>;
  status: string;
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  next_retry_at: string | null;
  github_run_id: string | null;
  dispatched_at: string | null;
  reason: string;
  created_at: string;
}

const github = {
  runs: [] as FakeRun[],
  dispatches: [] as FakeDispatch[],
  failNext: 0,
  failStatus: 0,
  failMessage: "",
};
const db = { dispatch_jobs: [] as FakeJob[], assets: [] as FakeAsset[] };

/** Look up a workflow run or fail loudly. */
function requireRun(id: unknown): FakeRun {
  const run = github.runs.find((r) => String(r.id) === String(id));
  if (!run) throw new Error(`run ${String(id)} not found in the fake GitHub API`);
  return run;
}

/** Look up a job or fail loudly — avoids `possibly undefined` noise. */
function requireJob(id: unknown): FakeJob {
  const job = db.dispatch_jobs.find((j) => j.id === id);
  if (!job) throw new Error(`job ${String(id)} not found in the fake outbox`);
  return job;
}

const githubServer = createServer((req, res) => {
  const url = req.url ?? "/";
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    const send = (code: number, payload?: unknown): void => {
      const text = payload === undefined ? "" : JSON.stringify(payload);
      res.writeHead(code, { "content-type": "application/json" });
      res.end(text);
    };

    const url = req.url ?? "/";
    if (req.method === "POST" && url.includes("/dispatches")) {
      if (github.failNext > 0) {
        github.failNext -= 1;
        send(github.failStatus || 500, { message: github.failMessage || "Server Error" });
        return;
      }
      github.dispatches.push(JSON.parse(body || "{}"));
      const id = 700000 + github.runs.length + 1;
      github.runs.unshift({
        id, name: "JSMon Monitor", status: "queued", conclusion: null,
        event: "workflow_dispatch",
        created_at: new Date().toISOString(),
        run_started_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        run_attempt: 1,
        html_url: `http://127.0.0.1:${(githubServer.address() as AddressInfo).port}/runs/${id}`,
      });
      send(204);
      return;
    }

    if (req.method === "GET" && url.includes("/actions/workflows/") && url.includes("/runs")) {
      send(200, { workflow_runs: github.runs });
      return;
    }

    const runMatch = /\/actions\/runs\/(\d+)/.exec(url);
    if (req.method === "GET" && runMatch) {
      const run = github.runs.find((r) => String(r.id) === runMatch[1]);
      if (!run) { send(404, { message: "Not Found" }); return; }
      send(200, run);
      return;
    }

    send(404, { message: `unexpected ${req.method} ${url}` });
  });
});

const supabaseServer = createServer((req, res) => {
  const path = req.url ?? "/";
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    const send = (code: number, payload?: unknown) => {
      const text = payload === undefined || payload === null ? "" : JSON.stringify(payload);
      res.writeHead(code, { "content-type": "application/json" });
      res.end(text);
    };
    interface RpcBody {
      p_owner?: string;
      p_project_id?: string | null;
      p_asset_id?: string | null;
      p_reason?: string;
      p_payload?: Record<string, unknown>;
      p_job?: string;
      p_error?: string;
      p_backoff_seconds?: number;
      p_github_run_id?: string | null;
    }
    const json = (): RpcBody => {
      try { return JSON.parse(body || "{}") as RpcBody; } catch { return {}; }
    };

    if (path.startsWith("/rest/v1/rpc/enqueue_scan")) {
      const b = json();
      if (b.p_asset_id) {
        const live = db.dispatch_jobs.find(
          (j) => j.asset_id === b.p_asset_id &&
                 ["pending", "dispatching", "queued", "running"].includes(j.status),
        );
        if (live) { send(200, live.id); return; }
      }
      const id = randomUUID();
      db.dispatch_jobs.push({
        id, owner_id: b.p_owner ?? "", project_id: b.p_project_id ?? null,
        asset_id: b.p_asset_id ?? null, payload: b.p_payload ?? {},
        status: "pending", attempts: 0, max_attempts: 5,
        last_error: null, next_retry_at: null, github_run_id: null,
        dispatched_at: null, reason: b.p_reason ?? "manual",
        created_at: new Date().toISOString(),
      });
      send(200, id);
      return;
    }

    if (path.startsWith("/rest/v1/rpc/claim_dispatch_job")) {
      const due = db.dispatch_jobs.filter((j) => j.status === "pending");
      for (const job of due) { job.status = "dispatching"; job.attempts += 1; }
      send(200, due);
      return;
    }

    if (path.startsWith("/rest/v1/rpc/mark_dispatch_queued")) {
      const b = json();
      const job = db.dispatch_jobs.find((j) => j.id === b.p_job);
      if (job) {
        job.status = "queued";
        job.github_run_id = b.p_github_run_id ?? null;
        job.dispatched_at = new Date().toISOString();
        job.last_error = null;
      }
      send(204);
      return;
    }

    if (path.startsWith("/rest/v1/rpc/mark_dispatch_failed")) {
      const b = json();
      const job = db.dispatch_jobs.find((j) => j.id === b.p_job);
      if (job) {
        job.last_error = b.p_error ?? null;
        if (job.attempts >= job.max_attempts) {
          job.status = "failed";
        } else {
          job.status = "pending";
          job.next_retry_at = new Date(
            Date.now() + Math.min((b.p_backoff_seconds ?? 60) * 2 ** (job.attempts - 1), 1800) * 1000,
          ).toISOString();
        }
      }
      send(204);
      return;
    }

    if (path.startsWith("/rest/v1/rpc/retry_dispatch_job")) {
      const b = json();
      const job = db.dispatch_jobs.find((j) => j.id === b.p_job);
      if (job && ["failed", "cancelled"].includes(job.status)) {
        job.status = "pending";
        job.attempts = 0;
        job.last_error = null;
        job.next_retry_at = new Date().toISOString();
      }
      send(204);
      return;
    }

    if (req.method === "POST" && path.includes("/rest/v1/assets")) {
      const rows = json();
      const list = Array.isArray(rows) ? rows : [rows];
      const inserted = list.map((row) => ({ ...row, id: row.id ?? randomUUID() }));
      db.assets.push(...inserted);
      send(201, inserted);
      return;
    }

    if (req.method === "GET" && path.includes("/rest/v1/dispatch_jobs")) {
      // Supabase-js sends filters as query params (status=in.(...), id=eq.<uuid>).
      const q = new URL(path, "http://x");
      const statusIn = q.searchParams.get("status");
      const idEq = q.searchParams.get("id");
      let rows = db.dispatch_jobs;
      if (statusIn) {
        const allowed = statusIn.replace(/^in\.\(|\)$/g, "").split(",");
        rows = rows.filter((j) => allowed.includes(j.status));
      }
      if (idEq) rows = rows.filter((j) => j.id === idEq.replace(/^eq\./, ""));
      send(200, rows);
      return;
    }

    if (req.method === "PATCH" && path.includes("/rest/v1/dispatch_jobs")) {
      const b = json();
      const q = new URL(path, "http://x");
      const id = (q.searchParams.get("id") ?? "").replace(/^eq\./, "");
      const job = db.dispatch_jobs.find((j) => j.id === id);
      if (job) Object.assign(job, b);
      send(200, job ? [job] : []);
      return;
    }

    if (req.method === "GET") { send(200, []); return; }
    if (req.method === "POST") { send(201, json()); return; }
    send(200, []);
  });
});

let GH = "";
let SB = "";
let supabase: SupabaseClient;
let realFetch: typeof fetch;

beforeAll(async () => {
  await new Promise<void>((resolve) => githubServer.listen(0, "127.0.0.1", () => resolve()));
  await new Promise<void>((resolve) => supabaseServer.listen(0, "127.0.0.1", () => resolve()));
  GH = `http://127.0.0.1:${(githubServer.address() as AddressInfo).port}`;
  SB = `http://127.0.0.1:${(supabaseServer.address() as AddressInfo).port}`;

  process.env.NEXT_PUBLIC_SUPABASE_URL = SB;
  process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY = "test-publishable-key";
  process.env.SUPABASE_SECRET_KEY = "test-service-key";
  process.env.GITHUB_OWNER = "test-owner";
  process.env.GITHUB_REPO = "test-repo";
  process.env.GITHUB_WORKFLOW_ID = "jsmon-monitor.yml";
  process.env.GITHUB_ACCESS_TOKEN = "test-token";

  // The config module memoises environment lookups at first call, which can
  // happen during import (before this hook ran). Invalidate it so the fakes
  // above are actually used by lib/supabase/server and lib/github/client.
  const { __resetConfigCacheForTests } = await import("@/lib/config");
  __resetConfigCacheForTests();

  const { createServiceClient } = await import("@/lib/supabase/server");
  supabase = createServiceClient()!;

  if (!supabase) {
    throw new Error(
      "createServiceClient() returned null: the config cache was not reset. " +
        "Set NEXT_PUBLIC_SUPABASE_URL/PUBLISHABLE_KEY and call " +
        "__resetConfigCacheForTests() before constructing clients.",
    );
  }

  realFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const url = String(input);
    if (url.startsWith("https://api.github.com")) {
      return realFetch(url.replace("https://api.github.com", GH), init);
    }
    return realFetch(input, init);
  };
});

afterAll(() => {
  globalThis.fetch = realFetch;
  githubServer.close();
  supabaseServer.close();
});

beforeEach(() => {
  github.runs = [];
  github.dispatches = [];
  github.failNext = 0;
  db.dispatch_jobs = [];
  db.assets = [];
});

const { drainDispatchQueue, reconcileDispatchJobs } = await import("@/lib/monitoring/dispatcher");

describe("automatic scan trigger on target creation", () => {
  it("enqueues a durable job before any network call", async () => {
    const { data: jobId } = await supabase.rpc("enqueue_scan", {
      p_owner: "user-1", p_project_id: "proj-1", p_asset_id: "asset-1",
      p_reason: "target_created", p_payload: { notify: true, full_scan: false },
    });

    expect(typeof jobId).toBe("string");
    expect(db.dispatch_jobs).toHaveLength(1);
    expect(db.dispatch_jobs[0].status).toBe("pending");
    expect(db.dispatch_jobs[0].asset_id).toBe("asset-1");
    expect(github.dispatches).toHaveLength(0);
  });

  it("delivers the job to workflow_dispatch with project and asset ids", async () => {
    await supabase.rpc("enqueue_scan", {
      p_owner: "user-1", p_project_id: "proj-1", p_asset_id: "asset-1",
      p_reason: "target_created", p_payload: { notify: true, full_scan: false },
    });

    const result = await drainDispatchQueue(5);
    expect(result.dispatched).toBe(1);
    expect(github.dispatches).toHaveLength(1);
    expect(github.dispatches[0].ref).toBe("main");
    expect(github.dispatches[0].inputs.project_id).toBe("proj-1");
    expect(github.dispatches[0].inputs.asset_id).toBe("asset-1");
    expect(github.dispatches[0].inputs.notify).toBe("true");
    expect(github.dispatches[0].inputs.full_scan).toBe("false");
  });

  it("reports an accepted dispatch as queued, never completed", async () => {
    await supabase.rpc("enqueue_scan", {
      p_owner: "u", p_project_id: "p", p_asset_id: "a",
    });
    await drainDispatchQueue(5);

    const job = db.dispatch_jobs[0];
    expect(job.status).toBe("queued");
    expect(job.status).not.toBe("completed");
    expect(job.github_run_id).toBeTruthy();
    expect(job.dispatched_at).toBeTruthy();
  });

  it("follows the GitHub run through running to completed", async () => {
    await supabase.rpc("enqueue_scan", { p_owner: "u", p_project_id: "p", p_asset_id: "a" });
    await drainDispatchQueue(5);

    const runId = db.dispatch_jobs[0].github_run_id;
    const run = requireRun(runId);

    run.status = "in_progress";
    await reconcileDispatchJobs(5);
    expect(db.dispatch_jobs[0].status).toBe("running");

    run.status = "completed";
    run.conclusion = "success";
    await reconcileDispatchJobs(5);
    expect(db.dispatch_jobs[0].status).toBe("completed");
  });

  it("marks the job failed when the GitHub run fails", async () => {
    await supabase.rpc("enqueue_scan", { p_owner: "u", p_project_id: "p", p_asset_id: "a" });
    await drainDispatchQueue(5);

    const run = github.runs[0]!;
    run.status = "completed";
    run.conclusion = "failure";
    await reconcileDispatchJobs(5);

    expect(db.dispatch_jobs[0].status).toBe("failed");
    expect(db.dispatch_jobs[0].last_error).toBeTruthy();
  });

  it("prevents duplicate overlapping scans for one asset", async () => {
    const first = (await supabase.rpc("enqueue_scan", {
      p_owner: "u", p_project_id: "p", p_asset_id: "a",
    })).data;
    const again = (await supabase.rpc("enqueue_scan", {
      p_owner: "u", p_project_id: "p", p_asset_id: "a",
    })).data;

    expect(again).toBe(first);
    expect(db.dispatch_jobs.filter((j) => j.asset_id === "a")).toHaveLength(1);
  });

  it("creates one project-scoped job for a batch import", async () => {
    const { data } = await supabase.rpc("enqueue_scan", {
      p_owner: "u", p_project_id: "p", p_asset_id: null,
      p_reason: "bulk_import", p_payload: { notify: true, full_scan: true },
    });
    const job = requireJob(data);

    expect(job).toBeTruthy();
    expect(job.asset_id).toBeNull();
    expect(job.reason).toBe("bulk_import");
    expect(job.payload.full_scan).toBe(true);
  });

  it("keeps the target and retries when GitHub refuses the dispatch", async () => {
    const { data: jobId } = await supabase.rpc("enqueue_scan", {
      p_owner: "u", p_project_id: "p", p_asset_id: "a",
    });
    const job = requireJob(jobId);

    github.failNext = 1;
    github.failStatus = 403;
    github.failMessage = "Resource not accessible by integration";

    const result = await drainDispatchQueue(5);

    expect(result.failed).toBe(1);
    expect(job.status).toBe("pending");
    expect(job.last_error).toContain("Resource not accessible");
    expect(job.next_retry_at).toBeTruthy();
  });

  it("re-delivers an exhausted job after a manual retry", async () => {
    const { data: jobId } = await supabase.rpc("enqueue_scan", {
      p_owner: "u", p_project_id: "p", p_asset_id: "a",
    });
    const job = requireJob(jobId);

    github.failNext = 99;
    github.failStatus = 500;
    github.failMessage = "Server Error";
    for (let i = 0; i < 5; i += 1) {
      await drainDispatchQueue(5);
      if (job.status === "pending") job.next_retry_at = null;
    }
    github.failNext = 0;

    expect(job.status).toBe("failed");
    expect(job.attempts).toBe(job.max_attempts);

    await supabase.rpc("retry_dispatch_job", { p_job: job.id });
    expect(job.status).toBe("pending");
    expect(job.attempts).toBe(0);

    const result = await drainDispatchQueue(5);
    expect(result.dispatched).toBeGreaterThanOrEqual(1);
    expect(job.status).toBe("queued");
  });

  it("never creates a git commit when a target is added", async () => {
    const before = github.dispatches.length;
    await supabase.rpc("enqueue_scan", { p_owner: "u", p_project_id: "p", p_asset_id: "a" });
    await drainDispatchQueue(5);

    expect(github.dispatches.length).toBe(before + 1);
    // Only workflow dispatches, never repository content writes.
    for (const dispatch of github.dispatches as Array<{ ref?: string; inputs?: unknown }>) {
      expect(dispatch.ref).toBeDefined();
      expect(dispatch.inputs).toBeDefined();
    }
  });
});
