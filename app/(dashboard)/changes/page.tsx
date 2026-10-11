"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Activity, AlertTriangle, ArrowLeft, Loader2 } from "lucide-react";

import { useChanges, useDiff, useProjects, type RecentChange } from "@/lib/hooks/useMonitoring";
import {
  formatBytes,
  formatDateTime,
  formatSignedBytes,
  shortHash,
  urlFilename,
} from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import DiffViewer from "@/components/diff-viewer/DiffViewer";
import { EmptyState } from "@/components/dashboard/shell";

export default function ChangesPage() {
  const params = useSearchParams();
  const initialChange = params.get("id");
  const assetFilter = params.get("asset");

  const { data: projectsData } = useProjects();
  const [projectId, setProjectId] = useState<string | null>(
    params.get("project"),
  );
  const { data, isLoading } = useChanges(projectId);
  // The selection is derived, not synced: arriving with ?id= opens that diff
  // directly, and local navigation overrides it. This avoids a cascading
  // render that an effect-driven setState would cause.
  const [manualSelection, setManualSelection] = useState<string | null>(null);
  const selectedId = manualSelection ?? initialChange;

  const changes = (data?.changes ?? []) as RecentChange[];
  const projects = projectsData?.projects ?? [];

  const visible = assetFilter
    ? changes.filter((change) => change.asset_id === assetFilter)
    : changes;

  if (selectedId) {
    return <ChangeDetail id={selectedId} onBack={() => setManualSelection(null)} />;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Detected Changes</h1>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Every genuine content change, with a diff you can inspect.
          </p>
        </div>
        <select
          value={projectId ?? ""}
          onChange={(event) => setProjectId(event.target.value || null)}
          className="h-9 rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] px-3 text-sm"
        >
          <option value="">All projects</option>
          {projects.map((project) => (
            <option key={project.id} value={project.id}>
              {project.name}
            </option>
          ))}
        </select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Change events</CardTitle>
          <CardDescription>
            {visible.length} change{visible.length === 1 ? "" : "s"} recorded
          </CardDescription>
        </CardHeader>
        <CardContent className="px-0">
          {isLoading ? (
            <div className="space-y-2 px-5 py-3">
              {Array.from({ length: 5 }).map((_, index) => (
                <div key={index} className="skeleton h-12 rounded" />
              ))}
            </div>
          ) : visible.length === 0 ? (
            <div className="px-5 pb-5">
              <EmptyState
                icon={Activity}
                title="No changes yet"
                description="Changes appear here once a target's content actually differs from its stored baseline."
              />
            </div>
          ) : (
            <div className="divide-y divide-[var(--border)]">
              {visible.map((change) => (
                <ChangeRow
                  key={change.id}
                  change={change}
                  onOpen={() => setManualSelection(change.id)}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ChangeRow({
  change,
  onOpen,
}: {
  change: RecentChange;
  onOpen: () => void;
}) {
  const indicators = change.change_metadata?.indicator_summary?.total ?? 0;

  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex w-full items-center gap-4 px-5 py-3 text-left transition-colors hover:bg-[var(--surface-raised)]/50"
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium">
            {urlFilename(change.asset_url)}
          </span>
          <Badge variant="neutral">{change.project_name}</Badge>
          {indicators > 0 && (
            <Badge variant="warn">
              <AlertTriangle className="h-3 w-3" />
              {indicators}
            </Badge>
          )}
        </div>
        <p className="mt-0.5 truncate font-mono text-[11px] text-[var(--muted)]">
          {shortHash(change.previous_hash, 12)} → {shortHash(change.current_hash, 12)}
        </p>
      </div>

      <div className="hidden shrink-0 text-right text-xs sm:block">
        <p className="font-medium">
          {formatSignedBytes(change.size_difference)}
        </p>
        <p className="text-[var(--muted)]">
          {formatBytes(change.previous_size ?? 0)} → {formatBytes(change.current_size)}
        </p>
      </div>

      <div className="hidden shrink-0 text-right text-xs text-[var(--muted)] md:block">
        +{change.change_metadata?.added_lines ?? 0} / −
        {change.change_metadata?.removed_lines ?? 0}
      </div>

      <div className="w-28 shrink-0 text-right text-xs text-[var(--muted)]">
        {formatDateTime(change.detected_at)}
      </div>
    </button>
  );
}

function ChangeDetail({
  id,
  onBack,
}: {
  id: string;
  onBack: () => void;
}) {
  const { data, isLoading, error } = useDiff(id);

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-accent-400" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title="Could not load this change"
        description={
          error instanceof Error ? error.message : "The diff is unavailable."
        }
        action={
          <Button size="sm" variant="secondary" onClick={onBack}>
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to changes
          </Button>
        }
      />
    );
  }

  const { diff, meta } = data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeft className="h-3.5 w-3.5" />
          Back
        </Button>
        <div className="min-w-0">
          <h1 className="truncate text-lg font-semibold">
            {urlFilename(meta.asset_url)}
          </h1>
          <p className="truncate text-xs text-[var(--muted)]">{meta.asset_url}</p>
        </div>
      </div>

      <Card>
        <CardContent className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
          <Meta label="Detected" value={formatDateTime(meta.detected_at)} />
          <Meta
            label="Size change"
            value={`${formatBytes(meta.from_version?.file_size ?? 0)} → ${formatBytes(
              meta.to_version.file_size,
            )} (${formatSignedBytes(meta.size_difference)})`}
          />
          <Meta
            label="Previous hash"
            value={shortHash(meta.from_version?.sha256, 20)}
            mono
          />
          <Meta label="Current hash" value={shortHash(meta.to_version.sha256, 20)} mono />
        </CardContent>
      </Card>

      <DiffViewer
        diff={diff}
        filename={urlFilename(meta.asset_url)}
        oldSource={hunksToSource(diff.hunks, "old")}
        newSource={hunksToSource(diff.hunks, "new")}
      />
    </div>
  );
}

function Meta({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] uppercase tracking-wider text-[var(--muted)]">
        {label}
      </p>
      <p className={`mt-0.5 truncate text-xs ${mono ? "font-mono" : ""}`} title={value}>
        {value}
      </p>
    </div>
  );
}

/**
 * The diff endpoint returns hunks rather than full files (a minified bundle
 * can be megabytes). Reconstruct a readable pair from the hunk line arrays so
 * Monaco has real content to render.
 */
function hunksToSource(
  hunks: Array<{ old_lines: string[]; new_lines: string[] }>,
  side: "old" | "new",
): string {
  return hunks
    .map((hunk) => (side === "old" ? hunk.old_lines : hunk.new_lines).join("\n"))
    .filter(Boolean)
    .join("\n…\n");
}
