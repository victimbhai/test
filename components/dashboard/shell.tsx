"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Bell,
  ChevronLeft,
  FileJson,
  FolderKanban,
  GitBranch,
  History,
  LayoutDashboard,
  Moon,
  PlayCircle,
  RefreshCw,
  Search,
  Settings,
  Sun,
} from "lucide-react";
import { useTheme } from "next-themes";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

const NAV = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/projects", label: "Projects", icon: FolderKanban },
  { href: "/assets", label: "JavaScript Assets", icon: FileJson },
  { href: "/changes", label: "Detected Changes", icon: Activity },
  { href: "/scans", label: "Scan History", icon: History },
  { href: "/notifications", label: "Notifications", icon: Bell },
  { href: "/actions", label: "GitHub Actions", icon: GitBranch },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar({
  collapsed,
  onToggle,
}: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  const pathname = usePathname();

  return (
    <aside
      className={cn(
        "flex h-full flex-col border-r border-[var(--border)] bg-[var(--surface)] transition-[width] duration-200",
        collapsed ? "w-[68px]" : "w-60",
      )}
    >
      <div className="flex h-14 items-center gap-2 border-b border-[var(--border)] px-4">
        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-accent-500/15 text-accent-400">
          <FileJson className="h-4 w-4" />
        </div>
        {!collapsed && (
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">JSMon</p>
            <p className="truncate text-[10px] uppercase tracking-wider text-[var(--muted)]">
              Security Dashboard
            </p>
          </div>
        )}
        <button
          type="button"
          onClick={onToggle}
          className="rounded p-1 text-[var(--muted)] hover:bg-[var(--surface-raised)] hover:text-[var(--foreground)]"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <ChevronLeft
            className={cn("h-4 w-4 transition-transform", collapsed && "rotate-180")}
          />
        </button>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
        {NAV.map((item) => {
          const active = pathname?.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              className={cn(
                "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors",
                active
                  ? "bg-accent-500/12 text-accent-300 shadow-[inset_0_0_0_1px_rgba(34,211,238,0.18)]"
                  : "text-[var(--muted)] hover:bg-[var(--surface-raised)] hover:text-[var(--foreground)]",
              )}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      {!collapsed && (
        <div className="border-t border-[var(--border)] p-3">
          <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
            <p className="text-[11px] font-medium text-[var(--foreground)]">
              Monitoring loop
            </p>
            <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
              GitHub Actions runs the Python engine every 15 minutes and writes
              to Supabase. This dashboard reads those results live.
            </p>
          </div>
        </div>
      )}
    </aside>
  );
}

export function Topbar({
  lastSync,
  onRefresh,
  refreshing,
}: {
  lastSync: string | null;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  const { theme, setTheme } = useTheme();
  const [search, setSearch] = useState("");

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-[var(--border)] bg-[var(--surface)]/85 px-4 backdrop-blur">
      <div className="relative min-w-0 flex-1 max-w-md">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search targets, projects, hashes…"
          className="h-8 w-full rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] pl-8 pr-3 text-sm placeholder:text-[var(--muted)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-400/50"
        />
      </div>

      <div className="ml-auto flex items-center gap-2">
        {lastSync && (
          <span className="hidden text-xs text-[var(--muted)] sm:inline">
            Synced {lastSync}
          </span>
        )}

        <Button
          variant="ghost"
          size="icon-sm"
          onClick={onRefresh}
          title="Refresh now"
        >
          <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
        </Button>

        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          title="Toggle theme"
        >
          {theme === "dark" ? (
            <Sun className="h-4 w-4" />
          ) : (
            <Moon className="h-4 w-4" />
          )}
        </Button>

        <Badge variant="accent" className="hidden sm:inline-flex">
          <span className="h-1.5 w-1.5 rounded-full bg-ok-400" />
          Connected
        </Badge>
      </div>
    </header>
  );
}

/** Empty state with an optional call to action. */
export function EmptyState({
  icon: Icon = FileJson,
  title,
  description,
  action,
}: {
  icon?: typeof FileJson;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-[var(--border-strong)] bg-[var(--surface)] px-6 py-12 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[var(--surface-raised)] text-[var(--muted)]">
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <p className="text-sm font-medium text-[var(--foreground)]">{title}</p>
        <p className="mx-auto mt-1 max-w-sm text-xs leading-relaxed text-[var(--muted)]">
          {description}
        </p>
      </div>
      {action}
    </div>
  );
}

export function RunScanButton({
  onClick,
  loading,
  label = "Run Scan Now",
  size = "sm",
}: {
  onClick: () => void;
  loading?: boolean;
  label?: string;
  size?: "sm" | "default";
}) {
  return (
    <Button size={size} onClick={onClick} disabled={loading}>
      <PlayCircle className="h-3.5 w-3.5" />
      {loading ? "Queuing…" : label}
    </Button>
  );
}
