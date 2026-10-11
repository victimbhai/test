import { getGitHubConfig } from "@/lib/config";

/**
 * Minimal GitHub REST client for workflow dispatch and run tracking.
 *
 * The access token is read from the server environment and never leaves the
 * server: no value from this module is returned to a client component.
 *
 * A fine-grained token needs:
 *   - repository: this repository only
 *   - permission "Actions": write (dispatch) + read (poll runs)
 */

export interface DispatchResult {
  dispatched: boolean;
  reason?: string;
}

export interface WorkflowRun {
  id: number;
  name: string;
  status: string | null;
  conclusion: string | null;
  event: string;
  created_at: string;
  run_started_at: string;
  updated_at: string;
  html_url: string;
  run_attempt: number;
}

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: string,
  ) {
    super(message);
    this.name = "GitHubError";
  }
}

async function githubFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<{ data: T; status: number }> {
  const config = getGitHubConfig();
  if (!config) {
    throw new GitHubError(
      "GitHub integration is not configured (GITHUB_OWNER/GITHUB_REPO/" +
        "GITHUB_WORKFLOW_ID/GITHUB_ACCESS_TOKEN)",
      503,
    );
  }

  const url = `https://api.github.com/repos/${config.owner}/${config.repo}${path}`;
  const response = await fetch(url, {
    ...init,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${config.token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
      "User-Agent": "jsmon-dashboard",
      ...(init.headers ?? {}),
    },
    cache: "no-store",
  });

  const text = await response.text();
  let parsed: unknown = undefined;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }

  if (!response.ok) {
    const message =
      (parsed as { message?: string } | undefined)?.message ??
      `GitHub API error ${response.status}`;
    throw new GitHubError(message, response.status, text.slice(0, 500));
  }

  return { data: parsed as T, status: response.status };
}

/**
 * Trigger the monitoring workflow.
 *
 * Returns a dispatch receipt only. GitHub accepts the request asynchronously,
 * so a successful dispatch is NOT evidence that a scan ran — callers must poll
 * the run status before reporting completion to the user.
 */
export async function dispatchMonitoringWorkflow(inputs: {
  project_id?: string | null;
  asset_id?: string | null;
  full_scan?: boolean;
  notify?: boolean;
  dry_run?: boolean;
}): Promise<DispatchResult> {
  const config = getGitHubConfig();
  if (!config) {
    return {
      dispatched: false,
      reason:
        "GitHub integration is not configured. Set GITHUB_OWNER, GITHUB_REPO, " +
        "GITHUB_WORKFLOW_ID and GITHUB_ACCESS_TOKEN.",
    };
  }

  const ref = config.ref;
  const payload = {
    ref,
    inputs: {
      project_id: inputs.project_id ?? "",
      asset_id: inputs.asset_id ?? "",
      full_scan: String(inputs.full_scan ?? true),
      notify: String(inputs.notify ?? true),
      dry_run: String(inputs.dry_run ?? false),
    },
  };

  try {
    await githubFetch(`/actions/workflows/${config.workflowId}/dispatches`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return { dispatched: true };
  } catch (error) {
    // 404 here almost always means the workflow file is not on the ref.
    const message =
      error instanceof GitHubError
        ? `${error.message}${error.status === 404 ? " (is the workflow file present on the configured branch?)" : ""}`
        : error instanceof Error
          ? error.message
          : "Unknown error";
    return { dispatched: false, reason: message };
  }
}

/** List the most recent runs of the monitoring workflow. */
export async function listWorkflowRuns(limit = 20): Promise<WorkflowRun[]> {
  const config = getGitHubConfig();
  if (!config) return [];

  try {
    const { data } = await githubFetch<{ workflow_runs?: WorkflowRun[] }>(
      `/actions/workflows/${config.workflowId}/runs?per_page=${limit}`,
    );
    return data.workflow_runs ?? [];
  } catch {
    return [];
  }
}

/** Fetch a single workflow run by id. */
export async function getWorkflowRun(runId: number): Promise<WorkflowRun | null> {
  const config = getGitHubConfig();
  if (!config) return null;

  try {
    const { data } = await githubFetch<WorkflowRun>(`/actions/runs/${runId}`);
    return data;
  } catch {
    return null;
  }
}

/**
 * Map a GitHub run onto our scan status vocabulary.
 *
 * queued/in_progress -> running; success -> success; anything else -> failed.
 * A run that never started (e.g. cancelled) is reported as cancelled.
 */
export function mapRunToScanStatus(run: WorkflowRun): {
  status: "queued" | "running" | "success" | "partial" | "failed" | "cancelled";
  label: string;
} {
  if (run.status === "queued" || run.status === "waiting") {
    return { status: "queued", label: "Queued" };
  }
  if (run.status === "in_progress") {
    return { status: "running", label: "Running" };
  }
  if (run.conclusion === "success") {
    return { status: "success", label: "Successful" };
  }
  if (run.conclusion === "cancelled") {
    return { status: "cancelled", label: "Cancelled" };
  }
  return { status: "failed", label: "Failed" };
}
