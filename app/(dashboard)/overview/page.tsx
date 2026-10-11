"use client";

import { Fragment, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  FileJson,
  FolderKanban,
  Gauge,
  Plus,
  XCircle,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  useChanges,
  useProjects,
  useStats,
  useTriggerScan,
  type RecentChange,
} from "@/lib/hooks/useMonitoring";
import {
  formatDateTime,
  formatRelativeTime,
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
import { EmptyState, RunScanButton } from "@/components/dashboard/shell";

export default function OverviewPage() {
  const { data: statsData, isLoading: statsLoading } = useStats();
  const { data: projectsData } = useProjects();
  const { data: changesData, isLoading: changesLoading } = useChanges();
  const triggerScan = useTriggerScan();
  const [expanded, setExpanded] = useState<string | null>(null);

  const stats = statsData?.stats;
  const projects = projectsData?.projects ?? [];
  const changes = (changesData?.changes ?? []) as RecentChange[];

  const chartData = useMemo(() => buildSeries(changes), [changes]);
  const projectBreakdown = useMemo(() => groupBy(changes, "project_name"), [changes]);
  const assetBreakdown = useMemo(
    () => groupBy(changes, "asset_url").slice(0, 6),
    [changes],
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Live monitoring state, refreshed automatically from Supabase.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="secondary" size="sm">
            <Link href="/assets">
              <Plus className="h-3.5 w-3.5" />
              Add JavaScript URL
            </Link>
          </Button>
          <RunScanButton
            loading={triggerScan.isPending}
            onClick={() =>
              triggerScan.mutate({ full_scan: true, notify: true })
            }
          />
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={FolderKanban}
          label="Monitored projects"
          value={stats?.projects ?? 0}
          loading={statsLoading}
        />
        <StatCard
          icon={FileJson}
          label="JavaScript assets"
          value={stats?.assets ?? 0}
          hint={`${stats?.active_assets ?? 0} active`}
          loading={statsLoading}
        />
        <StatCard
          icon={Activity}
          label="Changes (24h)"
          value={stats?.changes_24h ?? 0}
          hint={`${stats?.changes_7d ?? 0} in 7 days`}
          tone="accent"
          loading={statsLoading}
        />
        <StatCard
          icon={XCircle}
          label="Failed checks"
          value={stats?.failed_checks ?? 0}
          tone={(stats?.failed_checks ?? 0) > 0 ? "bad" : "ok"}
          loading={statsLoading}
        />
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={CheckCircle2}
          label="Last successful scan"
          value={formatRelativeTime(stats?.last_successful_scan)}
          compact
          loading={statsLoading}
        />
        <StatCard
          icon={Clock}
          label="Scheduled interval"
          value="Every 15 min"
          hint="GitHub Actions cron"
          compact
        />
        <StatCard
          icon={Gauge}
          label="Engine"
          value="Python 3.12"
          hint="jsmon runner"
          compact
        />
        <StatCard
          icon={AlertTriangle}
          label="Review indicators"
          value={
            changes.reduce(
              (sum, change) => sum + (change.change_metadata?.indicator_summary?.total ?? 0),
              0,
            )
          }
          hint="across recent changes"
          tone="warn"
          compact
        />
      </div>

      {/* Charts */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>JavaScript changes over time</CardTitle>
            <CardDescription>Daily change volume, last 30 days</CardDescription>
          </CardHeader>
          <CardContent>
            {chartData.length === 0 ? (
              <ChartEmpty />
            ) : (
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="fillChanges" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="date"
                      tick={{ fill: "var(--muted)", fontSize: 11 }}
                      stroke="var(--border)"
                      tickFormatter={(value: string) => value.slice(5)}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fill: "var(--muted)", fontSize: 11 }}
                      stroke="var(--border)"
                      width={32}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "var(--surface-raised)",
                        border: "1px solid var(--border)",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="changes"
                      stroke="#22d3ee"
                      strokeWidth={2}
                      fill="url(#fillChanges)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Changes grouped by project</CardTitle>
            <CardDescription>Where change activity is concentrated</CardDescription>
          </CardHeader>
          <CardContent>
            {projectBreakdown.length === 0 ? (
              <ChartEmpty />
            ) : (
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={projectBreakdown} layout="vertical">
                    <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" horizontal={false} />
                    <XAxis
                      type="number"
                      allowDecimals={false}
                      tick={{ fill: "var(--muted)", fontSize: 11 }}
                      stroke="var(--border)"
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={110}
                      tick={{ fill: "var(--muted)", fontSize: 11 }}
                      stroke="var(--border)"
                    />
                    <Tooltip
                      contentStyle={{
                        background: "var(--surface-raised)",
                        border: "1px solid var(--border)",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {projectBreakdown.map((entry, index) => (
                        <Cell
                          key={entry.name}
                          fill={index === 0 ? "#22d3ee" : "#0891b2"}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Most frequently modified files</CardTitle>
            <CardDescription>Top targets by change count</CardDescription>
          </CardHeader>
          <CardContent>
            {assetBreakdown.length === 0 ? (
              <ChartEmpty />
            ) : (
              <div className="space-y-2">
                {assetBreakdown.map((entry) => (
                  <div key={entry.name} className="space-y-1">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="truncate font-mono text-[var(--muted)]">
                        {urlFilename(entry.name)}
                      </span>
                      <span className="shrink-0 font-medium">{entry.count}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-[var(--surface-raised)]">
                      <div
                        className="h-full rounded-full bg-accent-500"
                        style={{
                          width: `${(entry.count / (assetBreakdown[0]?.count || 1)) * 100}%`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Change size distribution</CardTitle>
            <CardDescription>Byte delta per detected change</CardDescription>
          </CardHeader>
          <CardContent>
            {changes.length === 0 ? (
              <ChartEmpty />
            ) : (
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={sizeBuckets(changes)}
                      dataKey="count"
                      nameKey="label"
                      innerRadius={45}
                      outerRadius={75}
                      paddingAngle={2}
                    >
                      {sizeBuckets(changes).map((entry, index) => (
                        <Cell key={entry.label} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Legend
                      wrapperStyle={{ fontSize: 11, color: "var(--muted)" }}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "var(--surface-raised)",
                        border: "1px solid var(--border)",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent activity */}
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Recent activity</CardTitle>
            <CardDescription>
              Latest detected changes across all projects
            </CardDescription>
          </div>
          <Button asChild variant="ghost" size="sm">
            <Link href="/changes">View all</Link>
          </Button>
        </CardHeader>
        <CardContent className="px-0">
          {changesLoading ? (
            <TableSkeleton />
          ) : changes.length === 0 ? (
            <div className="px-5 pb-5">
              <EmptyState
                icon={Activity}
                title="No changes detected yet"
                description="Add an authorized JavaScript target and run a scan. The first scan creates a baseline; later changes appear here automatically."
                action={
                  <Button asChild size="sm" variant="secondary">
                    <Link href="/assets">Add a target</Link>
                  </Button>
                }
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--muted)]">
                    <th className="px-5 py-2 font-medium">Project</th>
                    <th className="px-5 py-2 font-medium">JavaScript file</th>
                    <th className="px-5 py-2 font-medium">Status</th>
                    <th className="px-5 py-2 font-medium">Size delta</th>
                    <th className="px-5 py-2 font-medium">Indicators</th>
                    <th className="px-5 py-2 font-medium">Detected</th>
                    <th className="px-5 py-2 font-medium" />
                  </tr>
                </thead>
                <tbody>
                  {changes.slice(0, 10).map((change) => {
                    const indicators = change.change_metadata?.indicator_summary?.total ?? 0;
                    const isOpen = expanded === change.id;
                    return (
                      <Fragment key={change.id}>
                        <tr
                          className="border-b border-[var(--border)]/60 last:border-0 hover:bg-[var(--surface-raised)]/50"
                        >
                          <td className="px-5 py-2.5">{change.project_name}</td>
                          <td className="max-w-[220px] truncate px-5 py-2.5 font-mono text-xs">
                            {urlFilename(change.asset_url)}
                          </td>
                          <td className="px-5 py-2.5">
                            <Badge variant="warn">Changed</Badge>
                          </td>
                          <td className="px-5 py-2.5">
                            <span className="inline-flex items-center gap-1 text-xs">
                              {change.size_difference > 0 ? (
                                <ArrowUpRight className="h-3 w-3 text-ok-400" />
                              ) : (
                                <ArrowDownRight className="h-3 w-3 text-bad-400" />
                              )}
                              {formatSignedBytes(change.size_difference)}
                            </span>
                          </td>
                          <td className="px-5 py-2.5">
                            {indicators > 0 ? (
                              <Badge variant="warn">{indicators}</Badge>
                            ) : (
                              <span className="text-xs text-[var(--muted)]">—</span>
                            )}
                          </td>
                          <td
                            className="px-5 py-2.5 text-xs text-[var(--muted)]"
                            title={formatDateTime(change.detected_at)}
                          >
                            {formatRelativeTime(change.detected_at)}
                          </td>
                          <td className="px-5 py-2.5 text-right">
                            <div className="flex items-center justify-end gap-1">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() =>
                                  setExpanded(isOpen ? null : change.id)
                                }
                              >
                                {isOpen ? "Hide" : "Details"}
                              </Button>
                              <Button asChild variant="ghost" size="sm">
                                <Link href={`/changes?id=${change.id}`}>
                                  Diff
                                </Link>
                              </Button>
                            </div>
                          </td>
                        </tr>
                        {isOpen && (
                          <tr className="bg-[var(--surface-raised)]/40">
                            <td colSpan={7} className="px-5 py-3">
                              <div className="grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
                                <Detail label="Asset URL" value={change.asset_url} mono />
                                <Detail
                                  label="Previous hash"
                                  value={shortHash(change.previous_hash, 16)}
                                  mono
                                />
                                <Detail
                                  label="Current hash"
                                  value={shortHash(change.current_hash, 16)}
                                  mono
                                />
                                <Detail
                                  label="Lines"
                                  value={`+${change.change_metadata?.added_lines ?? 0} / −${change.change_metadata?.removed_lines ?? 0}`}
                                  mono
                                />
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------

const PIE_COLORS = ["#22d3ee", "#0891b2", "#22c55e", "#f59e0b", "#ef4444"];

function StatCard({
  icon: Icon,
  label,
  value,
  hint,
  tone = "neutral",
  loading = false,
  compact = false,
}: {
  icon: typeof Activity;
  label: string;
  value: string | number;
  hint?: string;
  tone?: "neutral" | "accent" | "ok" | "warn" | "bad";
  loading?: boolean;
  compact?: boolean;
}) {
  const toneClass =
    tone === "accent"
      ? "text-accent-400"
      : tone === "ok"
        ? "text-ok-400"
        : tone === "warn"
          ? "text-warn-400"
          : tone === "bad"
            ? "text-bad-400"
            : "text-[var(--muted)]";

  return (
    <Card className={compact ? "p-4" : undefined}>
      <CardContent className={compact ? "p-0" : "p-5"}>
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="text-xs text-[var(--muted)]">{label}</p>
            {loading ? (
              <div className="skeleton mt-2 h-7 w-16 rounded" />
            ) : (
              <p
                className={`mt-1 font-semibold tracking-tight ${
                  compact ? "text-base" : "text-2xl"
                } ${toneClass}`}
              >
                {value}
              </p>
            )}
            {hint && (
              <p className="mt-0.5 text-[11px] text-[var(--muted)]">{hint}</p>
            )}
          </div>
          <Icon className={`h-4 w-4 shrink-0 ${toneClass}`} />
        </div>
      </CardContent>
    </Card>
  );
}

function Detail({
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
      <p
        className={`mt-0.5 truncate text-xs ${mono ? "font-mono" : ""}`}
        title={value}
      >
        {value}
      </p>
    </div>
  );
}

function ChartEmpty() {
  return (
    <div className="flex h-56 items-center justify-center text-xs text-[var(--muted)]">
      No data yet — run a scan to populate this chart.
    </div>
  );
}

function TableSkeleton() {
  return (
    <div className="space-y-2 px-5 py-3">
      {Array.from({ length: 5 }).map((_, index) => (
        <div key={index} className="skeleton h-9 rounded" />
      ))}
    </div>
  );
}

function buildSeries(changes: RecentChange[]) {
  const days = 30;
  const map = new Map<string, { date: string; changes: number }>();
  for (let i = days - 1; i >= 0; i -= 1) {
    const key = new Date(Date.now() - i * 864e5).toISOString().slice(0, 10);
    map.set(key, { date: key, changes: 0 });
  }
  for (const change of changes) {
    const key = change.detected_at.slice(0, 10);
    const entry = map.get(key);
    if (entry) entry.changes += 1;
  }
  return Array.from(map.values());
}

function groupBy(changes: RecentChange[], key: "project_name" | "asset_url") {
  const map = new Map<string, number>();
  for (const change of changes) {
    const value = change[key] ?? "unknown";
    map.set(value, (map.get(value) ?? 0) + 1);
  }
  return Array.from(map.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
}

function sizeBuckets(changes: RecentChange[]) {
  const buckets = [
    { label: "< 1 KB", count: 0 },
    { label: "1–10 KB", count: 0 },
    { label: "10–100 KB", count: 0 },
    { label: "> 100 KB", count: 0 },
  ];
  for (const change of changes) {
    const size = Math.abs(change.size_difference);
    if (size < 1024) buckets[0].count += 1;
    else if (size < 10 * 1024) buckets[1].count += 1;
    else if (size < 100 * 1024) buckets[2].count += 1;
    else buckets[3].count += 1;
  }
  return buckets;
}
