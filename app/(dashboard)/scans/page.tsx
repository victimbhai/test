"use client";

import { useState } from "react";
import { CheckCircle2, Clock, History, XCircle } from "lucide-react";

import {
  useDispatchJobs,
  type DispatchJob,
} from "@/lib/hooks/useMonitoring";
import { formatDateTime, formatDuration } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EmptyState } from "@/components/dashboard/shell";
import { ScanStatusPill } from "@/components/dashboard/ScanStatusPill";

/**
 * Scan history.
 *
 * Two sources are shown together:
 *   - dispatch jobs (what the dashboard asked GitHub to run)
 *   - scan_runs rows (what the engine actually recorded in Supabase)
 *
 * The second is the source of truth for "did a scan complete"; the first
 * explains queueing and retries.
 */
export default function ScansPage() {
  const { data, isLoading } = useDispatchJobs();
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const jobs = (data?.jobs ?? []) as DispatchJob[];

  const counts = {
    all: jobs.length,
    completed: jobs.filter((job) => job.status === "completed").length,
    failed: jobs.filter((job) => job.status === "failed").length,
    live: jobs.filter((job) =>
      ["pending", "dispatching", "queued", "running"].includes(job.status),
    ).length,
  };

  const filtered =
    statusFilter === "all"
      ? jobs
      : statusFilter === "live"
        ? jobs.filter((job) =>
            ["pending", "dispatching", "queued", "running"].includes(job.status),
          )
        : jobs.filter((job) => job.status === statusFilter);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Scan History</h1>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Every monitoring run, its trigger, and its outcome.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-4">
        <HistoryStat icon={History} label="Total runs" value={counts.all} />
        <HistoryStat icon={CheckCircle2} label="Completed" value={counts.completed} tone="ok" />
        <HistoryStat icon={Clock} label="In progress" value={counts.live} tone="accent" />
        <HistoryStat icon={XCircle} label="Failed" value={counts.failed} tone="bad" />
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Runs</CardTitle>
            <CardDescription>Newest first</CardDescription>
          </div>
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="h-9 rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] px-3 text-sm"
          >
            <option value="all">All statuses</option>
            <option value="live">In progress</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </CardHeader>
        <CardContent className="px-0">
          {isLoading ? (
            <div className="space-y-2 px-5 py-3">
              {Array.from({ length: 6 }).map((_, index) => (
                <div key={index} className="skeleton h-11 rounded" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <div className="px-5 pb-5">
              <EmptyState
                icon={History}
                title="No scan runs"
                description="Runs appear once a scan has been triggered, either on schedule or manually."
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--muted)]">
                    <th className="px-5 py-2 font-medium">Run</th>
                    <th className="px-5 py-2 font-medium">Status</th>
                    <th className="px-5 py-2 font-medium">Trigger</th>
                    <th className="px-5 py-2 font-medium">Started</th>
                    <th className="px-5 py-2 font-medium">Attempts</th>
                    <th className="px-5 py-2 font-medium">Workflow</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((job) => (
                    <tr
                      key={job.id}
                      className="border-b border-[var(--border)]/60 last:border-0"
                    >
                      <td className="px-5 py-2.5 font-mono text-xs">
                        {job.id.slice(0, 8)}
                      </td>
                      <td className="px-5 py-2.5">
                        <ScanStatusPill status={job.status as never} />
                      </td>
                      <td className="px-5 py-2.5">
                        <Badge variant="neutral">
                          {job.reason.replace(/_/g, " ")}
                        </Badge>
                      </td>
                      <td className="px-5 py-2.5 text-xs text-[var(--muted)]">
                        {formatDateTime(job.created_at)}
                      </td>
                      <td className="px-5 py-2.5 text-xs">
                        {job.attempts}/{job.max_attempts}
                      </td>
                      <td className="px-5 py-2.5 text-xs">
                        {job.github_run_id ? (
                          <a
                            href={`https://github.com/${process.env.NEXT_PUBLIC_GITHUB_OWNER ?? ""}/${process.env.NEXT_PUBLIC_GITHUB_REPO ?? ""}/actions/runs/${job.github_run_id}`}
                            target="_blank"
                            rel="noreferrer noopener"
                            className="text-accent-400 hover:underline"
                          >
                            #{job.github_run_id}
                          </a>
                        ) : (
                          <span className="text-[var(--muted)]">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function HistoryStat({
  icon: Icon,
  label,
  value,
  tone = "neutral",
}: {
  icon: typeof History;
  label: string;
  value: number;
  tone?: "neutral" | "ok" | "bad" | "accent";
}) {
  const toneClass =
    tone === "ok"
      ? "text-ok-400"
      : tone === "bad"
        ? "text-bad-400"
        : tone === "accent"
          ? "text-accent-400"
          : "text-[var(--muted)]";

  return (
    <Card>
      <CardContent className="flex items-center justify-between p-4">
        <div>
          <p className="text-xs text-[var(--muted)]">{label}</p>
          <p className={`mt-1 text-2xl font-semibold ${toneClass}`}>{value}</p>
        </div>
        <Icon className={`h-4 w-4 ${toneClass}`} />
      </CardContent>
    </Card>
  );
}
