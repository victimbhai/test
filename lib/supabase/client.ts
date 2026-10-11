import { createBrowserClient } from "@supabase/ssr";

import { getSupabaseConfig } from "@/lib/config";

/**
 * Browser-side Supabase client.
 *
 * Uses only the publishable (anon) key. Row Level Security confines this
 * client to the signed-in user's rows, so it must never be given the secret
 * key.
 */
export function createClient() {
  const config = getSupabaseConfig();
  if (!config) return null;

  return createBrowserClient(config.url, config.publishableKey);
}
