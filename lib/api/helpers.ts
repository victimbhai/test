import { NextResponse } from "next/server";
import { z, type ZodError } from "zod";

import { createClient } from "@/lib/supabase/server";
import { isSupabaseConfigured } from "@/lib/config";

/**
 * Shared API plumbing: authentication, error envelopes, and safe logging.
 *
 * Every route authenticates server-side. Client-side checks are UX only.
 */

export interface AuthContext {
  userId: string;
  email: string | null;
}

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; response: NextResponse };

export function jsonError(
  message: string,
  status = 400,
  extra?: Record<string, unknown>,
) {
  return NextResponse.json(
    { error: message, ...(extra ?? {}) },
    { status },
  );
}

/**
 * Never echo raw driver/Supabase errors to the client: they can carry schema
 * details or fragments of stored data.
 */
function safeMessage(error: unknown): string {
  if (error instanceof z.ZodError) return "Request validation failed";
  if (error instanceof Error) {
    const message = error.message;
    // Supabase/Postgres driver strings leak table and column names.
    if (/duplicate key|violates|relation|column|syntax error/i.test(message)) {
      return "Database constraint or integrity error";
    }
    if (/JWT|token|auth/i.test(message)) return "Authentication error";
    return message.slice(0, 300);
  }
  return "Unexpected server error";
}

export async function requireAuth(): Promise<ApiResult<AuthContext>> {
  if (!isSupabaseConfigured()) {
    return {
      ok: false,
      response: jsonError(
        "Supabase is not configured. Set NEXT_PUBLIC_SUPABASE_URL and " +
          "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY.",
        503,
      ),
    };
  }

  const supabase = await createClient();
  if (!supabase) {
    return {
      ok: false,
      response: jsonError("Supabase client unavailable", 503),
    };
  }

  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    return {
      ok: false,
      response: jsonError("Authentication required", 401),
    };
  }

  return { ok: true, data: { userId: user.id, email: user.email ?? null } };
}

/** Read and validate a JSON body against a Zod schema. */
export async function parseBody<T extends z.ZodType>(
  request: Request,
  schema: T,
): Promise<ApiResult<z.infer<T>>> {
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return {
      ok: false,
      response: jsonError("Request body must be valid JSON", 400),
    };
  }

  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => ({
      path: issue.path.join("."),
      message: issue.message,
    }));
    return {
      ok: false,
      response: NextResponse.json(
        { error: "Validation failed", issues },
        { status: 422 },
      ),
    };
  }

  return { ok: true, data: parsed.data };
}

/** Wrap a handler so thrown errors become safe JSON responses. */
export function withErrorHandling<T>(
  handler: () => Promise<NextResponse<T>>,
): Promise<NextResponse> {
  return handler().catch((error: unknown) => {
    console.error("[api] unhandled error:", error);
    return jsonError(safeMessage(error), 500);
  });
}

/** Verify the authenticated user owns a project. */
export async function assertProjectOwnership(
  supabase: NonNullable<Awaited<ReturnType<typeof createClient>>>,
  projectId: string,
  userId: string,
): Promise<boolean> {
  const { data, error } = await supabase
    .from("projects")
    .select("id")
    .eq("id", projectId)
    .eq("owner_id", userId)
    .maybeSingle();

  return !error && !!data;
}
