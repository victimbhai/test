import { createServerClient } from "@supabase/ssr";
import { createClient as createSupabaseClient } from "@supabase/supabase-js";
import { cookies } from "next/headers";

import { getSupabaseConfig, getSupabaseSecretKey } from "@/lib/config";

/**
 * Request-scoped Supabase client that carries the caller's cookies.
 *
 * This client is subject to Row Level Security: it can only read and write
 * rows owned by the signed-in user. Use it for anything triggered by a user
 * request.
 *
 * NOTE: Next 16 prerenders route handlers, and `cookies()` rejects once the
 * prerender finishes. Callers must therefore either (a) run inside a request
 * (the normal case) or (b) tolerate a null client. Every route here checks for
 * null and returns a 503, so a prerender pass degrades safely instead of
 * crashing the build.
 */
export async function createClient() {
  const config = getSupabaseConfig();
  if (!config) return null;

  let cookieStore: Awaited<ReturnType<typeof cookies>>;
  try {
    cookieStore = await cookies();
  } catch {
    // Prerender pass with no request scope.
    return null;
  }

  return createServerClient(config.url, config.publishableKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) =>
            cookieStore.set(name, value, options),
          );
        } catch {
          // Called from a Server Component: the middleware refreshes the
          // session instead, so swallowing here is correct.
        }
      },
    },
  });
}

/**
 * Service-role client. Bypasses Row Level Security.
 *
 * ONLY ever use this server-side (API routes, server actions) for operations
 * that legitimately act on behalf of the system:
 *   - the monitoring engine's writes
 *   - reading notification credentials
 *   - administrative audit logging
 *
 * Never import this into a client component and never return its data to the
 * browser without an explicit ownership check.
 */
export function createServiceClient() {
  const config = getSupabaseConfig();
  if (!config) return null;

  return createSupabaseClient(config.url, getSupabaseSecretKey(), {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}
