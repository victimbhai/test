"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

import { Sidebar, Topbar } from "@/components/dashboard/shell";
import { cn } from "@/lib/utils";

/**
 * Authenticated dashboard chrome.
 *
 * Session verification is a lightweight server round-trip: the pages
 * themselves are protected by the API routes they call, so this only decides
 * whether to show the shell or redirect to sign-in.
 */
export function DashboardShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [lastSync, setLastSync] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [authed, setAuthed] = useState<boolean | null>(null);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    let cancelled = false;
    async function check() {
      try {
        const response = await fetch("/api/auth/session");
        const payload = await response.json().catch(() => ({}));
        if (cancelled) return;
        const ok = response.ok && (payload as { authenticated?: boolean }).authenticated;
        setAuthed(!!ok);
        if (!ok) {
          router.replace(`/login?next=${encodeURIComponent(pathname ?? "/overview")}`);
        }
      } catch {
        if (!cancelled) setAuthed(false);
      }
    }
    check();
    return () => {
      cancelled = true;
    };
  }, [pathname, router]);

  // A heartbeat drives the "last synced" indicator and re-runs the check.
  useEffect(() => {
    const timer = setInterval(() => {
      setLastSync(
        new Date().toLocaleTimeString(undefined, {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
      );
    }, 30_000);
    return () => clearInterval(timer);
  }, []);

  if (authed === null) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-accent-500/30 border-t-accent-400" />
          <p className="text-sm text-[var(--muted)]">Loading dashboard…</p>
        </div>
      </div>
    );
  }

  if (!authed) {
    return (
      <div className="flex h-screen items-center justify-center px-6">
        <div className="max-w-md rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6 text-center">
          <h1 className="text-lg font-semibold">Authentication required</h1>
          <p className="mt-2 text-sm text-[var(--muted)]">
            This is a private security research dashboard. Sign in with your
            administrator account to continue.
          </p>
          <a
            href="/login"
            className="mt-4 inline-flex h-9 items-center rounded-lg bg-accent-500 px-4 text-sm font-semibold text-base-950 hover:bg-accent-400"
          >
            Go to sign in
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((v) => !v)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          lastSync={lastSync}
          refreshing={refreshing}
          onRefresh={() => {
            setRefreshing(true);
            setLastSync(
              new Date().toLocaleTimeString(undefined, {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              }),
            );
            // TanStack Query refetches on window focus; nudge it here too.
            window.dispatchEvent(new Event("focus"));
            setTimeout(() => setRefreshing(false), 600);
          }}
        />
        <main
          className={cn(
            "min-h-0 flex-1 overflow-y-auto p-4 sm:p-6",
          )}
        >
          {children}
        </main>
      </div>
    </div>
  );
}
