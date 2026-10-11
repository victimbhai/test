"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { FileJson, Loader2, LogIn } from "lucide-react";

import { createClient } from "@/lib/supabase/client";
import { isSupabaseConfigured } from "@/lib/config";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/**
 * Sign-in page.
 *
 * This dashboard is private by default: there is no public registration. The
 * administrator account is created once in Supabase, and Row Level Security
 * confines every subsequent request to that user's rows.
 */
export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <main className="flex min-h-screen items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-accent-400" />
        </main>
      }
    >
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") ?? "/overview";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<"password" | "magic">("password");

  if (!isSupabaseConfigured()) {
    return (
      <main className="flex min-h-screen items-center justify-center px-6">
        <div className="w-full max-w-md rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6">
          <h1 className="text-lg font-semibold">Supabase is not configured</h1>
          <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">
            Set these environment variables in your Vercel project, then reload:
          </p>
          <pre className="mt-3 overflow-x-auto rounded-lg bg-[var(--surface-raised)] p-3 font-mono text-[11px] text-[var(--foreground)]">
{`NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=`}
          </pre>
          <p className="mt-3 text-xs text-[var(--muted)]">
            Server-side values (SUPABASE_SECRET_KEY, GITHUB_ACCESS_TOKEN, …)
            must also be present; see .env.example.
          </p>
        </div>
      </main>
    );
  }

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setLoading(true);

    const supabase = createClient();
    if (!supabase) {
      setError("Supabase client is unavailable");
      setLoading(false);
      return;
    }

    try {
      if (mode === "magic") {
        const { error: signInError } = await supabase.auth.signInWithOtp({
          email,
          options: {
            emailRedirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(next)}`,
          },
        });
        if (signInError) throw signInError;
        setError(null);
        setLoading(false);
        alert("Check your email for a sign-in link.");
        return;
      }

      const { error: signInError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });
      if (signInError) throw signInError;

      router.push(next);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
      setLoading(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-accent-500/15 text-accent-400">
            <FileJson className="h-5 w-5" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">
            JSMon Security Dashboard
          </h1>
          <p className="text-sm text-[var(--muted)]">
            Private JavaScript change monitoring
          </p>
        </div>

        <form
          onSubmit={onSubmit}
          className="space-y-4 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5"
        >
          <div className="space-y-1.5">
            <label htmlFor="email" className="text-sm font-medium">
              Email
            </label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@example.com"
            />
          </div>

          {mode === "password" && (
            <div className="space-y-1.5">
              <label htmlFor="password" className="text-sm font-medium">
                Password
              </label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="••••••••"
              />
            </div>
          )}

          {error && (
            <p className="rounded-lg border border-bad-500/40 bg-bad-500/10 px-3 py-2 text-xs text-bad-400">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <LogIn className="h-4 w-4" />
            )}
            {mode === "password" ? "Sign in" : "Send magic link"}
          </Button>

          <button
            type="button"
            onClick={() => setMode(mode === "password" ? "magic" : "password")}
            className="w-full text-xs text-[var(--muted)] hover:text-[var(--foreground)]"
          >
            {mode === "password"
              ? "Use an email link instead"
              : "Use a password instead"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs leading-relaxed text-[var(--muted)]">
          No public registration. Accounts are created in Supabase by the
          operator.
        </p>
      </div>
    </main>
  );
}
