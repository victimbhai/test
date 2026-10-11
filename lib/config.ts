/**
 * Centralised environment configuration.
 *
 * Rules:
 *   - NEXT_PUBLIC_* values are safe for the browser (URL + publishable key).
 *   - The Supabase secret key, GitHub token and notification credentials are
 *     server-only. They are read lazily and never bundled into the client.
 *   - Missing configuration must degrade gracefully: the dashboard renders an
 *     explicit "not configured" state instead of crashing.
 */

export interface SupabaseConfig {
  url: string;
  publishableKey: string;
}

let cachedConfig: SupabaseConfig | null | undefined;

/**
 * Drop the cached configuration.
 *
 * The caches below are module-level so a serverless invocation reads env once.
 * Tests (and `next dev` HMR) can change the environment after import, so they
 * need a way to invalidate that memo. Never call this from application code.
 */
export function __resetConfigCacheForTests(): void {
  cachedConfig = undefined;
  cachedGithub = undefined;
}

export function getSupabaseConfig(): SupabaseConfig | null {
  if (cachedConfig !== undefined) return cachedConfig;

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY?.trim();

  if (!url || !publishableKey) {
    cachedConfig = null;
    return null;
  }

  cachedConfig = { url, publishableKey };
  return cachedConfig;
}

export function isSupabaseConfigured(): boolean {
  return getSupabaseConfig() !== null;
}

/** Server-only secret. Throws when absent so misconfiguration fails loudly. */
export function requireServerSecret(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(
      `Missing required server environment variable ${name}. ` +
        `Set it in your Vercel project settings (server-side scope).`,
    );
  }
  return value;
}

export function getSupabaseSecretKey(): string {
  return requireServerSecret("SUPABASE_SECRET_KEY");
}

export interface GitHubConfig {
  owner: string;
  repo: string;
  workflowId: string;
  token: string;
  ref: string;
}

let cachedGithub: GitHubConfig | null | undefined;

export function getGitHubConfig(): GitHubConfig | null {
  if (cachedGithub !== undefined) return cachedGithub;

  const owner = process.env.GITHUB_OWNER?.trim();
  const repo = process.env.GITHUB_REPO?.trim();
  const workflowId = process.env.GITHUB_WORKFLOW_ID?.trim();
  const token = process.env.GITHUB_ACCESS_TOKEN?.trim();
  const ref = process.env.GITHUB_WORKFLOW_REF?.trim() || "main";

  if (!owner || !repo || !workflowId || !token) {
    cachedGithub = null;
    return null;
  }

  cachedGithub = { owner, repo, workflowId, token, ref };
  return cachedGithub;
}

export function isGitHubConfigured(): boolean {
  return getGitHubConfig() !== null;
}

/** The dashboard's own URL, used to build links inside notifications. */
export function getAppUrl(): string {
  return (
    process.env.NEXT_PUBLIC_APP_URL?.trim() ||
    (process.env.VERCEL_PROJECT_PRODUCTION_URL
      ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
      : "http://localhost:3000")
  );
}
