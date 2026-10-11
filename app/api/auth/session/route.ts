import { NextResponse } from "next/server";

import { createClient } from "@/lib/supabase/server";

/** GET /api/auth/session — lightweight authentication probe for the shell. */
export async function GET() {
  const supabase = await createClient();
  if (!supabase) {
    return NextResponse.json(
      { authenticated: false, configured: false },
      { status: 503 },
    );
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ authenticated: false }, { status: 401 });
  }

  return NextResponse.json({
    authenticated: true,
    user: { id: user.id, email: user.email },
  });
}
