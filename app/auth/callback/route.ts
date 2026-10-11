import { NextResponse } from "next/server";

import { createClient } from "@/lib/supabase/server";

/**
 * OAuth / magic-link callback.
 *
 * Supabase redirects here with a `code` (PKCE) or a token hash. We exchange it
 * server-side so the session cookie is set with the right attributes, then
 * forward to the dashboard.
 */
export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const next = searchParams.get("next") ?? "/overview";
  const safeNext = next.startsWith("/") && !next.startsWith("//") ? next : "/overview";

  if (code) {
    const supabase = await createClient();
    if (supabase) {
      const { error } = await supabase.auth.exchangeCodeForSession(code);
      if (!error) {
        return NextResponse.redirect(`${origin}${safeNext}`);
      }
    }
  }

  return NextResponse.redirect(`${origin}/login?error=callback_failed`);
}
