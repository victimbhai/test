"use client";

import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  ExternalLink,
  History,
  RefreshCw,
  XCircle,
} from "lucide-react";

import {
  useDispatchJobs,
  useRetryScan,
  type DispatchJob,
} from "@/lib/hooks/useMonitoring";
import { formatDateTime, formatRelativeTime } from "@/lib/format";
import { Badge, StatusDot } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EmptyState } from "@/components/dashboard/shell";
import { ScanStatusPill } from "@/components/dashboard/ScanStatusPill";
import { isGitHubConfigured } from "@/lib/config";

/**
 * GitHub Actions page.
 *
 * Shows the dispatch queue: what was enqueued, whether GitHub accepted it, the
 * linked workflow run, and a retry path when delivery failed.
 *
 * The important distinction this page makes visible: "Queued" means GitHub
 * accepted our dispatch, "Completed" means the engine ran and wrote results.
 */
export default function ActionsPage() {
  const { data, isLoading } = useDispatchJobs();
  const retryScan = useRetryScan();
  const [filter, setFilter] = useState<"all" | "live" | "failed">("all");

  const jobs = (data?.jobs ?? []) as DispatchJob[];

  const filtered = jobs.filter((job) => {
    if (filter === "live") {
      return ["pending", "dispatching", "queued", "running"].includes(job.status);
    }
    if (filter === "failed") return job.status === "failed";
    return true;
  });

  const liveCount = jobs.filter((job) =>
    ["pending", "dispatching", "queued", "running"].includes(job.status),
  ).length;
  const failedCount = jobs.filter((job) => job.status === "failed").length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">GitHub Actions</h1>
          <p className="mt-1 text-sm text-[var(--muted)]">
            The Python monitoring engine runs here. The dashboard only triggers
            and observes it.
          </p>
        </div>
        {!isGitHubConfigured() && (
          <Badge variant="warn">
            <AlertTriangle className="h-3 w-3" />
            Not configured
          </Badge>
        )}
      </div>

      {!isGitHubConfigured() && (
        <Card className="border-warn-500/40">
          <CardContent className="p-4">
            <p className="text-sm font-medium text-warn-400">
              GitHub integration is not configured
            </p>
            <p className="mt-1 text-xs leading-relaxed text-[var(--muted)]">
              Targets can still be saved, but scans will stay queued. Set{" "}
              <code className="font-mono">GITHUB_OWNER</code>,{" "}
              <code className="font-mono">GITHUB_REPO</code>,{" "}
              <code className="font-mono">GITHUB_WORKFLOW_ID</code> and{" "}
              <code className="font-mono">GITHUB_ACCESS_TOKEN</code> as
              server-side Vercel environment variables.
            </p>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        <SummaryCard
          icon={Clock}
          label="Live scans"
          value={liveCount}
          tone={liveCount > 0 ? "accent" : "neutral"}
        />
        <SummaryCard
          icon={CheckCircle2}
          label="Completed"
          value={jobs.filter((job) => job.status === "completed").length}
          tone="ok"
        />
        <SummaryCard
          icon={XCircle}
          label="Failed dispatches"
          value={failedCount}
          tone={failedCount > 0 ? "bad" : "ok"}
        />
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Dispatch queue</CardTitle>
            <CardDescription>
              Durable job records — a failed dispatch is retried, never lost
            </CardDescription>
          </div>
          <div className="flex gap-1 rounded-md bg-[var(--surface-raised)] p-0.5">
            {(["all", "live", "failed"] as const).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => setFilter(key)}
                className={`rounded px-2.5 py-1 text-xs font-medium capitalize ${
                  filter === key
                    ? "bg-accent-500/20 text-accent-300"
                    : "text-[var(--muted)] hover:text-[var(--foreground)]"
                }`}
              >
                {key}
              </button>
            ))}
          </div>
        </CardHeader>
        <CardContent className="px-0">
          {isLoading ? (
            <div className="space-y-2 px-5 py-3">
              {Array.from({ length: 4 }).map((_, index) => (
                <div key={index} className="skeleton h-12 rounded" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <div className="px-5 pb-5">
              <EmptyState
                icon={History}
                title="No dispatch jobs"
                description="Add a target or press Run Scan Now and the job will appear here with its live status."
              />
            </div>
          ) : (
            <div className="divide-y divide-[var(--border)]">
              {filtered.map((job) => (
                <div
                  key={job.id}
                  className="flex flex-wrap items-center gap-3 px-5 py-3"
                >
                  <ScanStatusPill status={job.status as never} />

                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm">
                      <span className="text-[var(--muted)]">Job</span>{" "}
                      <span className="font-mono text-xs">{job.id.slice(0, 8)}</span>
                      <Badge variant="neutral" className="ml-2">
                        {job.reason.replace(/_/g, " ")}
                      </Badge>
                    </p>
                    <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                      Queued {formatRelativeTime(job.created_at)} · attempt{" "}
                      {job.attempts}/{job.max_attempts}
                      {job.github_run_id && ` · run #${job.github_run_id}`}
                    </p>
                    {job.last_error && (
                      <p className="mt-1 max-w-xl truncate text-[11px] text-bad-400" title={job.last_error}>
                        {job.last_error}
                      </p>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5">
                    {job.status === "failed" && (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => retryScan.mutate(job.id)}
                        disabled={retryScan.isPending}
                      >
                        <RefreshCw className="h-3.5 w-3.5" />
                        Retry
                      </Button>
                    )}
                    {job.github_run_id && (
                      <a
                        href={`https://github.com/${process.env.NEXT_PUBLIC_GITHUB_OWNER ?? ""}/${process.env.NEXT_PUBLIC_GITHUB_REPO ?? ""}/actions/runs/${job.github_run_id}`}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-[var(--border)] px-2.5 text-xs hover:bg-[var(--surface-raised)]"
                      >
                        <ExternalLink className="h-3 w-3" />
                        View run
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Clock;
  label: string;
  value: number;
  tone: "neutral" | "accent" | "ok" | "bad";
}) {
  const toneClass =
    tone === "accent"
      ? "text-accent-400"
      : tone === "ok"
        ? "text-ok-400"
        : tone === "bad"
          ? "text-bad-400"
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
