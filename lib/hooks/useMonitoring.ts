"use client";

import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { toast } from "sonner";

/**
 * Data layer for the dashboard.
 *
 * Every mutation that can trigger a scan invalidates the affected queries, so
 * the moment the engine writes results to Supabase the visible state updates —
 * no page reload, and no redeploy.
 */

async function apiFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      (payload as { error?: string }).error ?? `Request failed (${response.status})`;
    throw new Error(message);
  }

  return payload as T;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Project {
  id: string;
  name: string;
  primary_domain: string | null;
  description: string | null;
  tags: string[];
  enabled: boolean;
  interval_minutes: number;
  scope_notes: string | null;
  allowed_hosts: string[];
  created_at: string;
  updated_at: string;
}

export interface Asset {
  id: string;
  project_id: string;
  url: string;
  enabled: boolean;
  latest_hash: string | null;
  latest_version_id: string | null;
  last_checked_at: string | null;
  last_changed_at: string | null;
  last_http_status: number | null;
  etag: string | null;
  file_size: number | null;
  discovery_source: string;
  created_at: string;
}

export interface DispatchJob {
  id: string;
  project_id: string | null;
  asset_id: string | null;
  status: string;
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  github_run_id: string | null;
  reason: string;
  created_at: string;
}

export interface RecentChange {
  id: string;
  asset_id: string;
  asset_url: string;
  project_id: string;
  project_name: string;
  detected_at: string;
  size_difference: number;
  previous_size: number | null;
  current_size: number;
  previous_hash: string | null;
  current_hash: string;
  change_metadata: {
    added_lines?: number;
    removed_lines?: number;
    size_delta_percent?: number;
    indicator_summary?: { total: number };
  };
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

export function useProjects() {
  return useQuery({
    queryKey: ["projects"],
    queryFn: () => apiFetch<{ projects: Project[] }>("/api/projects"),
  });
}

export function useCreateProject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: Record<string, unknown>) =>
      apiFetch<{ project: Project }>("/api/projects", {
        method: "POST",
        body: JSON.stringify(input),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      toast.success("Project created");
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

export function useAssets(projectId: string | null) {
  return useQuery({
    queryKey: ["assets", projectId],
    queryFn: () =>
      apiFetch<{ assets: Asset[] }>(
        `/api/assets?project_id=${encodeURIComponent(projectId!)}`,
      ),
    enabled: !!projectId,
  });
}

/**
 * Add targets. The server enqueues the first scan in the same transaction, so
 * a successful add means the scan is queued — not finished.
 */
export function useAddAssets() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { project_id: string; urls: string[] }) =>
      apiFetch<{
        assets: Asset[];
        enqueued: Array<{ job_id: string; scope: string }>;
        added: number;
        warning?: string;
      }>("/api/assets", { method: "POST", body: JSON.stringify(input) }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      queryClient.invalidateQueries({ queryKey: ["dispatch-jobs"] });
      if (data.enqueued.length > 0) {
        toast.success(
          `${data.added} target${data.added === 1 ? "" : "s"} added — first scan queued`,
        );
      } else if (data.warning) {
        toast.warning(data.warning);
      } else {
        toast.success(`${data.added} target${data.added === 1 ? "" : "s"} added`);
      }
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

export function useBulkImport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { project_id: string; text: string }) =>
      apiFetch<{
        added: number;
        duplicates: number;
        invalid: Array<{ line: string; reason: string }>;
        enqueued: Array<{ job_id: string; scope: string }>;
      }>("/api/assets", { method: "PUT", body: JSON.stringify(input) }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      queryClient.invalidateQueries({ queryKey: ["dispatch-jobs"] });
      const parts = [`Imported ${data.added} target${data.added === 1 ? "" : "s"}`];
      if (data.duplicates) parts.push(`${data.duplicates} duplicate(s) skipped`);
      if (data.invalid.length) parts.push(`${data.invalid.length} rejected`);
      toast.success(parts.join(" · "));
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

// ---------------------------------------------------------------------------
// Scan control
// ---------------------------------------------------------------------------

export function useDispatchJobs(projectId?: string | null) {
  const suffix = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return useQuery({
    queryKey: ["dispatch-jobs", projectId ?? "all"],
    queryFn: () => apiFetch<{ jobs: DispatchJob[] }>(`/api/scan/trigger${suffix}`),
    // Poll while anything is live so the status pills advance on their own.
    refetchInterval: (query) => {
      const jobs = query.state.data?.jobs ?? [];
      const live = jobs.some((j) =>
        ["pending", "dispatching", "queued", "running"].includes(j.status),
      );
      return live ? 5000 : 20_000;
    },
  });
}

/** "Run Scan Now" — enqueues a job and asks the server to drain immediately. */
export function useTriggerScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: {
      project_id?: string;
      asset_id?: string;
      full_scan?: boolean;
      notify?: boolean;
    }) =>
      apiFetch<{ job_id: string; status: string; message: string }>(
        "/api/scan/trigger",
        { method: "POST", body: JSON.stringify(input) },
      ),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["dispatch-jobs"] });
      toast.success(data.message);
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

/** Retry a failed dispatch without losing the target. */
export function useRetryScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (jobId: string) =>
      apiFetch<{ status: string; message: string }>("/api/scan/retry", {
        method: "POST",
        body: JSON.stringify({ job_id: jobId }),
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["dispatch-jobs"] });
      toast.success(data.message);
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

// ---------------------------------------------------------------------------
// Changes and stats
// ---------------------------------------------------------------------------

export function useChanges(projectId?: string | null) {
  const suffix = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return useQuery({
    queryKey: ["changes", projectId ?? "all"],
    queryFn: () => apiFetch<{ changes: RecentChange[]; total: number }>(
      `/api/changes${suffix}`,
    ),
  });
}

export function useStats() {
  return useQuery({
    queryKey: ["stats"],
    queryFn: () =>
      apiFetch<{
        stats: {
          projects: number;
          assets: number;
          active_assets: number;
          changes_24h: number;
          changes_7d: number;
          failed_checks: number;
          last_successful_scan: string | null;
        };
      }>("/api/stats"),
    refetchInterval: 30_000,
  });
}

export function useDiff(changeId: string | null) {
  return useQuery({
    queryKey: ["diff", changeId],
    queryFn: () =>
      apiFetch<{
        diff: {
          unified: string;
          hunks: Array<{
            old_start: number;
            old_lines: string[];
            new_start: number;
            new_lines: string[];
          }>;
          added_lines: number;
          removed_lines: number;
          old_lines: number;
          new_lines: number;
          truncated: boolean;
          context_lines: number;
          indicators: Array<{
            category: string;
            label: string;
            severity: "high" | "medium" | "low";
            line_number: number;
            match: string;
            context: string;
          }>;
        };
        meta: {
          asset_url: string;
          from_version: {
            id: string;
            sha256: string;
            file_size: number;
            captured_at: string;
          } | null;
          to_version: {
            id: string;
            sha256: string;
            file_size: number;
            captured_at: string;
          };
          detected_at: string;
          size_difference: number;
        };
      }>(`/api/changes/${changeId}/diff`),
    enabled: !!changeId,
    // Snapshots are immutable, so a loaded diff never goes stale.
    staleTime: 5 * 60_000,
  });
}
