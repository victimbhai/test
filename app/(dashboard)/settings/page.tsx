"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { LogOut, Settings as SettingsIcon, ShieldCheck } from "lucide-react";

import { createClient } from "@/lib/supabase/client";
import { isGitHubConfigured, isSupabaseConfigured } from "@/lib/config";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { toast } from "sonner";

export default function SettingsPage() {
  const router = useRouter();
  const [signingOut, setSigningOut] = useState(false);

  async function signOut() {
    setSigningOut(true);
    const supabase = createClient();
    if (supabase) await supabase.auth.signOut();
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    router.replace("/login");
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Deployment configuration and account.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-ok-400" />
            Integration status
          </CardTitle>
          <CardDescription>
            Read-only view of what this deployment can do.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <StatusRow
            label="Supabase (database + auth + storage)"
            ok={isSupabaseConfigured()}
          />
          <StatusRow
            label="GitHub Actions (dispatch + run tracking)"
            ok={isGitHubConfigured()}
          />
          <StatusRow label="Vercel cron (dispatch drain + reconcile)" ok />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Monitoring defaults</CardTitle>
          <CardDescription>
            Applied when the engine runs on GitHub Actions.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <DefaultRow label="Schedule" value="Every 15 minutes (staggered cron)" />
          <DefaultRow label="Runner" value="Python 3.12 · monitor/runner.py" />
          <DefaultRow label="Snapshots per asset" value="50 (configurable)" />
          <DefaultRow label="Max download size" value="20 MB per asset" />
          <DefaultRow label="Retention" value="Oldest versions pruned after each scan" />
          <DefaultRow
            label="Dispatch reliability"
            value="Durable outbox with exponential backoff and manual retry"
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security posture</CardTitle>
          <CardDescription>
            How this dashboard protects your data.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-xs leading-relaxed text-[var(--muted)]">
          <p>
            <strong className="text-[var(--foreground)]">SSRF protection.</strong>{" "}
            Every target is validated before any fetch: http/https only, no
            credentials in the URL, and loopback, private, link-local and
            cloud-metadata addresses are rejected. Every redirect hop is
            re-validated.
          </p>
          <p>
            <strong className="text-[var(--foreground)]">Row Level Security.</strong>{" "}
            Every table is owner-scoped. The service-role key is used only
            server-side for the monitoring engine and notification credentials.
          </p>
          <p>
            <strong className="text-[var(--foreground)]">Immutable snapshots.</strong>{" "}
            Version rows cannot be updated through the client APIs, so history
            stays consistent.
          </p>
          <p>
            <strong className="text-[var(--foreground)]">Untrusted content.</strong>{" "}
            Downloaded JavaScript is rendered only as text inside Monaco. It is
            never injected as HTML and never executed.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <SettingsIcon className="h-4 w-4" />
            Account
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Button variant="destructive" size="sm" onClick={signOut} disabled={signingOut}>
            <LogOut className="h-3.5 w-3.5" />
            {signingOut ? "Signing out…" : "Sign out"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function StatusRow({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] px-3 py-2">
      <span className="text-xs">{label}</span>
      <Badge variant={ok ? "ok" : "warn"}>{ok ? "Configured" : "Not configured"}</Badge>
    </div>
  );
}

function DefaultRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-2 last:border-0 last:pb-0">
      <span className="text-xs text-[var(--muted)]">{label}</span>
      <span className="text-xs font-medium">{value}</span>
    </div>
  );
}
