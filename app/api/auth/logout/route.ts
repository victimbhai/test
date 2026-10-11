import { type NextRequest, NextResponse } from "next/server";

import { createClient } from "@/lib/supabase/server";
import { isSupabaseConfigured } from "@/lib/config";

/**
 * POST /api/auth/logout — end the session.
 *
 * Uses the server client so the auth cookies are cleared with the correct
 * attributes; a client-side signOut alone can leave a stale cookie behind.
 */
export async function POST(_request: NextRequest) {
  if (!isSupabaseConfigured()) {
    return NextResponse.json({ error: "Supabase is not configured" }, { status: 503 });
  }

  const supabase = await createClient();
  if (!supabase) {
    return NextResponse.json({ error: "Supabase unavailable" }, { status: 503 });
  }

  await supabase.auth.signOut();
  return NextResponse.json({ signedOut: true });
}
