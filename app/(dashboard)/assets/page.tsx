"use client";

import { useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  FileJson,
  Globe,
  Link2,
  Loader2,
  PlayCircle,
  Plus,
  RefreshCw,
  Search,
  Upload,
  XCircle,
} from "lucide-react";

import {
  useAddAssets,
  useAssets,
  useBulkImport,
  useDispatchJobs,
  useProjects,
  useRetryScan,
  useTriggerScan,
  type Asset,
} from "@/lib/hooks/useMonitoring";
import {
  formatBytes,
  formatRelativeTime,
  shortHash,
  urlFilename,
  urlHost,
} from "@/lib/format";
import { looksLikeJavaScript, parseUrlList } from "@/lib/validation/schemas";
import { Badge, StatusDot } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Label, Textarea } from "@/components/ui/input";
import { EmptyState, RunScanButton } from "@/components/dashboard/shell";
import { ScanStatusPill } from "@/components/dashboard/ScanStatusPill";
import Link from "next/link";

export default function AssetsPage() {
  const params = useSearchParams();
  const initialProject = params.get("project");

  const { data: projectsData, isLoading: projectsLoading } = useProjects();
  const [projectId, setProjectId] = useState<string | null>(initialProject);
  const { data: assetsData, isLoading: assetsLoading } = useAssets(projectId);
  const { data: jobsData } = useDispatchJobs(projectId);
  const [search, setSearch] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);

  const projects = projectsData?.projects ?? [];
  const assets = assetsData?.assets ?? [];
  const jobs = jobsData?.jobs ?? [];

  // Prefer the project from the query string once projects load.
  const activeProjectId = projectId ?? projects[0]?.id ?? null;
  const activeProject = projects.find((p) => p.id === activeProjectId);

  const filtered = useMemo(() => {
    if (!search.trim()) return assets;
    const needle = search.toLowerCase();
    return assets.filter(
      (asset) =>
        asset.url.toLowerCase().includes(needle) ||
        (asset.latest_hash ?? "").toLowerCase().includes(needle),
    );
  }, [assets, search]);

  const jobsByAsset = useMemo(() => {
    const map = new Map<string, typeof jobs[number]>();
    for (const job of jobs) {
      if (!job.asset_id) continue;
      const existing = map.get(job.asset_id);
      if (!existing || job.created_at > existing.created_at) {
        map.set(job.asset_id, job);
      }
    }
    return map;
  }, [jobs]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            JavaScript Assets
          </h1>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Add an authorized target and its first scan is queued automatically.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setImportOpen(true)}
            disabled={!activeProjectId}
          >
            <Upload className="h-3.5 w-3.5" />
            Bulk import
          </Button>
          <Button size="sm" onClick={() => setAddOpen(true)} disabled={!activeProjectId}>
            <Link2 className="h-3.5 w-3.5" />
            Add Target
          </Button>
        </div>
      </div>

      {/* Project selector */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-4">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-[var(--muted)]" />
            <Label htmlFor="project" className="text-xs text-[var(--muted)]">
              Project
            </Label>
          </div>
          <select
            id="project"
            value={activeProjectId ?? ""}
            onChange={(event) => setProjectId(event.target.value || null)}
            className="h-9 min-w-[220px] rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] px-3 text-sm"
            disabled={projectsLoading || projects.length === 0}
          >
            {projects.length === 0 && <option value="">No projects</option>}
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>

          {activeProject && (
            <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
              <span>
                Scope:{" "}
                <span className="font-mono">
                  {activeProject.allowed_hosts.length
                    ? activeProject.allowed_hosts.join(", ")
                    : "unrestricted"}
                </span>
              </span>
            </div>
          )}

          <div className="ml-auto flex items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
              <Input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Filter targets…"
                className="h-9 w-56 pl-8"
              />
            </div>
            <ProjectScanButton projectId={activeProjectId} />
          </div>
        </CardContent>
      </Card>

      {/* Target table */}
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Tracked JavaScript files</CardTitle>
            <CardDescription>
              {filtered.length} target{filtered.length === 1 ? "" : "s"}
              {search && ` matching “${search}”`}
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="px-0">
          {!activeProjectId ? (
            <div className="px-5 pb-5">
              <EmptyState
                icon={FileJson}
                title="No project selected"
                description="Create a project first, then add the JavaScript URLs you are authorized to monitor."
                action={
                  <Button asChild size="sm" variant="secondary">
                    <Link href="/projects">Go to projects</Link>
                  </Button>
                }
              />
            </div>
          ) : assetsLoading ? (
            <div className="space-y-2 px-5 py-3">
              {Array.from({ length: 4 }).map((_, index) => (
                <div key={index} className="skeleton h-12 rounded" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <div className="px-5 pb-5">
              <EmptyState
                icon={Link2}
                title={search ? "No matches" : "No targets yet"}
                description={
                  search
                    ? "No target matches that filter."
                    : "Add a JavaScript URL. The first scan creates a baseline automatically."
                }
                action={
                  !search && (
                    <Button size="sm" onClick={() => setAddOpen(true)}>
                      <Plus className="h-3.5 w-3.5" />
                      Add Target
                    </Button>
                  )
                }
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--muted)]">
                    <th className="px-5 py-2 font-medium">JavaScript file</th>
                    <th className="px-5 py-2 font-medium">Status</th>
                    <th className="px-5 py-2 font-medium">Hash</th>
                    <th className="px-5 py-2 font-medium">Size</th>
                    <th className="px-5 py-2 font-medium">HTTP</th>
                    <th className="px-5 py-2 font-medium">Last checked</th>
                    <th className="px-5 py-2 font-medium">Last change</th>
                    <th className="px-5 py-2 font-medium" />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((asset) => {
                    const job = jobsByAsset.get(asset.id);
                    return (
                      <AssetRow
                        key={asset.id}
                        asset={asset}
                        job={job}
                        projectId={activeProjectId!}
                      />
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <AddTargetDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        projectId={activeProjectId}
        allowedHosts={activeProject?.allowed_hosts ?? []}
      />
      <BulkImportDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        projectId={activeProjectId}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

/** Scan button bound to the currently selected project. */
function ProjectScanButton({ projectId }: { projectId: string | null }) {
  const triggerScan = useTriggerScan();

  if (!projectId) return null;

  return (
    <Button
      size="sm"
      onClick={() => triggerScan.mutate({ project_id: projectId, full_scan: true })}
      disabled={triggerScan.isPending}
      title="Run a full scan of every enabled target in this project"
    >
      {triggerScan.isPending ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      ) : (
        <PlayCircle className="h-3.5 w-3.5" />
      )}
      Run Scan Now
    </Button>
  );
}

function AssetRow({
  asset,
  job,
  projectId,
}: {
  asset: Asset;
  job?: {
    id: string;
    status: string;
    last_error: string | null;
    attempts: number;
  };
  projectId: string;
}) {
  const triggerScan = useTriggerScan();
  const retryScan = useRetryScan();

  const status = asset.last_http_status;
  const httpTone =
    status === null
      ? "neutral"
      : status >= 200 && status < 300
        ? "ok"
        : status >= 400
          ? "bad"
          : "warn";

  return (
    <tr className="border-b border-[var(--border)]/60 last:border-0 hover:bg-[var(--surface-raised)]/40">
      <td className="max-w-[280px] px-5 py-2.5">
        <a
          href={asset.url}
          target="_blank"
          rel="noreferrer noopener"
          className="block truncate font-mono text-xs text-accent-400 hover:underline"
          title={asset.url}
        >
          {urlFilename(asset.url)}
        </a>
        <span className="text-[11px] text-[var(--muted)]">{urlHost(asset.url)}</span>
      </td>

      <td className="px-5 py-2.5">
        {job ? (
          <ScanStatusPill status={job.status as never} />
        ) : asset.latest_hash ? (
          <Badge variant="ok">
            <StatusDot tone="ok" />
            Baseline
          </Badge>
        ) : (
          <Badge variant="neutral">Not scanned</Badge>
        )}
      </td>

      <td className="px-5 py-2.5 font-mono text-xs text-[var(--muted)]">
        {shortHash(asset.latest_hash, 10)}
      </td>

      <td className="px-5 py-2.5 text-xs">{formatBytes(asset.file_size)}</td>

      <td className="px-5 py-2.5">
        <Badge variant={httpTone as never}>{status ?? "—"}</Badge>
      </td>

      <td className="px-5 py-2.5 text-xs text-[var(--muted)]">
        {formatRelativeTime(asset.last_checked_at)}
      </td>

      <td className="px-5 py-2.5 text-xs text-[var(--muted)]">
        {formatRelativeTime(asset.last_changed_at)}
      </td>

      <td className="px-5 py-2.5">
        <div className="flex items-center justify-end gap-1">
          {job?.status === "failed" && (
            <Button
              variant="ghost"
              size="sm"
              title={job.last_error ?? "Retry failed scan"}
              onClick={() => retryScan.mutate(job.id)}
              disabled={retryScan.isPending}
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Retry
            </Button>
          )}
          <Button
            variant="ghost"
            size="icon-sm"
            title="Run scan now"
            onClick={() =>
              triggerScan.mutate({ project_id: projectId, asset_id: asset.id })
            }
            disabled={triggerScan.isPending}
          >
            <PlayCircle className="h-3.5 w-3.5" />
          </Button>
          <Button asChild variant="ghost" size="icon-sm" title="Change history">
            <Link href={`/changes?asset=${asset.id}`}>
              <FileJson className="h-3.5 w-3.5" />
            </Link>
          </Button>
        </div>
        {job?.status === "failed" && job.last_error && (
          <p className="mt-1 max-w-[200px] truncate text-[10px] text-bad-400" title={job.last_error}>
            {job.last_error}
          </p>
        )}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Add Target dialog
// ---------------------------------------------------------------------------

function AddTargetDialog({
  open,
  onOpenChange,
  projectId,
  allowedHosts,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string | null;
  allowedHosts: string[];
}) {
  const addAssets = useAddAssets();
  const [urls, setUrls] = useState("");
  const [validation, setValidation] = useState<{
    valid: string[];
    invalid: Array<{ line: string; reason: string }>;
    duplicates: number;
  } | null>(null);

  const lines = urls
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  function revalidate() {
    setValidation(parseUrlList(urls));
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!projectId) return;

    const parsed = validation ?? parseUrlList(urls);
    if (parsed.valid.length === 0) return;

    // Scope check against the project allowlist.
    const outOfScope = parsed.valid.filter((url) => {
      const host = urlHost(url);
      if (allowedHosts.length === 0) return false;
      return !allowedHosts.some((entry) => {
        const clean = entry.trim().toLowerCase().replace(/^\*?\./, "");
        return host === clean || host.endsWith(`.${clean}`);
      });
    });

    if (outOfScope.length > 0) {
      setValidation({
        ...parsed,
        invalid: [
          ...parsed.invalid,
          ...outOfScope.map((url) => ({
            line: url,
            reason: "Outside the project's allowed hostnames",
          })),
        ],
      });
      return;
    }

    await addAssets.mutateAsync({ project_id: projectId, urls: parsed.valid });
    setUrls("");
    setValidation(null);
    onOpenChange(false);
  }

  const canSubmit = projectId !== null && lines.length > 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add JavaScript target</DialogTitle>
        </DialogHeader>

        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="urls">JavaScript URL(s)</Label>
            <Textarea
              id="urls"
              value={urls}
              onChange={(event) => {
                setUrls(event.target.value);
                setValidation(null);
              }}
              onBlur={revalidate}
              placeholder={"https://example.com/static/main.js\nhttps://example.com/assets/app.js"}
              rows={5}
              className="font-mono text-xs"
            />
            <p className="text-[11px] text-[var(--muted)]">
              One URL per line, or paste a newline-separated list. Saving queues
              the first scan automatically.
            </p>
          </div>

          {validation && (
            <div className="space-y-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] p-3 text-xs">
              <p className="flex items-center gap-1.5 text-ok-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                {validation.valid.length} valid URL
                {validation.valid.length === 1 ? "" : "s"}
                {validation.duplicates > 0 && ` · ${validation.duplicates} duplicate(s) skipped`}
              </p>
              {validation.invalid.length > 0 && (
                <div className="space-y-1">
                  <p className="flex items-center gap-1.5 text-bad-400">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    {validation.invalid.length} rejected
                  </p>
                  <ul className="max-h-24 space-y-0.5 overflow-y-auto pl-5 text-[11px] text-[var(--muted)]">
                    {validation.invalid.slice(0, 10).map((item, index) => (
                      <li key={index} className="truncate">
                        <span className="font-mono">{item.line}</span> — {item.reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {allowedHosts.length > 0 && (
            <p className="rounded-lg border border-accent-500/30 bg-accent-500/8 p-2.5 text-[11px] text-[var(--muted)]">
              Scope restricted to:{" "}
              <span className="font-mono text-accent-300">
                {allowedHosts.join(", ")}
              </span>
              . Targets outside this list are rejected.
            </p>
          )}

          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={!canSubmit || addAssets.isPending}
              title="Validate, save, and queue the first scan"
            >
              {addAssets.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <PlayCircle className="h-3.5 w-3.5" />
              )}
              Save &amp; Start Monitoring
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Bulk import dialog
// ---------------------------------------------------------------------------

function BulkImportDialog({
  open,
  onOpenChange,
  projectId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string | null;
}) {
  const bulkImport = useBulkImport();
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<{
    valid: string[];
    invalid: Array<{ line: string; reason: string }>;
    duplicates: number;
  } | null>(null);

  const handleFile = async (file: File) => {
    const content = await file.text();
    setText(content);
    setPreview(parseUrlList(content));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Bulk import targets</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="file">Upload a .txt file</Label>
            <Input
              id="file"
              type="file"
              accept=".txt,text/plain"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) handleFile(file);
              }}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="bulk">Or paste URLs</Label>
            <Textarea
              id="bulk"
              value={text}
              onChange={(event) => {
                setText(event.target.value);
                setPreview(null);
              }}
              rows={8}
              className="font-mono text-xs"
              placeholder={"https://a.example.com/one.js\nhttps://b.example.com/two.js"}
            />
          </div>

          {preview && (
            <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] p-3 text-xs">
              <p className="text-ok-400">
                {preview.valid.length} valid · {preview.duplicates} duplicate ·{" "}
                {preview.invalid.length} rejected
              </p>
            </div>
          )}

          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setPreview(parseUrlList(text))}
            >
              Validate
            </Button>
            <Button
              disabled={!projectId || text.trim().length === 0 || bulkImport.isPending}
              onClick={async () => {
                if (!projectId) return;
                await bulkImport.mutateAsync({ project_id: projectId, text });
                setText("");
                setPreview(null);
                onOpenChange(false);
              }}
            >
              {bulkImport.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Import &amp; scan
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
