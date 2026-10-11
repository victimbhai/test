import { NextResponse } from "next/server";

import { createClient, createServiceClient } from "@/lib/supabase/server";
import {
  assertProjectOwnership,
  jsonError,
  parseBody,
  requireAuth,
  withErrorHandling,
} from "@/lib/api/helpers";
import { createProjectSchema, updateProjectSchema } from "@/lib/validation/schemas";
import type { Project } from "@/lib/supabase/types";

/** GET /api/projects — list the caller's projects. */
export async function GET() {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    const { data, error } = await supabase
      .from("projects")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) return jsonError("Could not load projects", 500);

    return NextResponse.json({ projects: (data ?? []) as Project[] });
  });
}

/** POST /api/projects — create a project (and optionally seed targets). */
export async function POST(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const body = await parseBody(request, createProjectSchema);
    if (!body.ok) return body.response;

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    const { data: project, error } = await supabase
      .from("projects")
      .insert({
        owner_id: auth.data.userId,
        name: body.data.name,
        primary_domain: body.data.primary_domain ?? null,
        description: body.data.description ?? null,
        tags: body.data.tags,
        enabled: body.data.enabled,
        interval_minutes: body.data.interval_minutes,
        scope_notes: body.data.scope_notes ?? null,
        allowed_hosts: body.data.allowed_hosts,
      })
      .select()
      .single();

    if (error || !project) return jsonError("Could not create project", 500);

    return NextResponse.json({ project: project as Project }, { status: 201 });
  });
}

/** PATCH /api/projects?id=... — update a project. */
export async function PATCH(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const id = new URL(request.url).searchParams.get("id");
    if (!id) return jsonError("Project id is required", 400);

    const body = await parseBody(request, updateProjectSchema);
    if (!body.ok) return body.response;

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    if (!(await assertProjectOwnership(supabase, id, auth.data.userId))) {
      return jsonError("Project not found", 404);
    }

    const patch: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(body.data)) {
      if (value !== undefined) patch[key] = value;
    }
    if (Object.keys(patch).length === 0) {
      return jsonError("No updatable fields supplied", 400);
    }

    const { data, error } = await supabase
      .from("projects")
      .update(patch)
      .eq("id", id)
      .eq("owner_id", auth.data.userId)
      .select()
      .single();

    if (error || !data) return jsonError("Could not update project", 500);

    return NextResponse.json({ project: data as Project });
  });
}

/** DELETE /api/projects?id=... — delete a project and its targets. */
export async function DELETE(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const id = new URL(request.url).searchParams.get("id");
    if (!id) return jsonError("Project id is required", 400);

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    if (!(await assertProjectOwnership(supabase, id, auth.data.userId))) {
      return jsonError("Project not found", 404);
    }

    // Cancel any live dispatch jobs first so a queued scan cannot resurrect
    // rows we are about to delete.
    const service = createServiceClient();
    if (service) {
      await service
        .from("dispatch_jobs")
        .update({ status: "cancelled" })
        .eq("project_id", id)
        .in("status", ["pending", "dispatching", "queued", "running"]);
    }

    const { error } = await supabase.from("projects").delete().eq("id", id);
    if (error) return jsonError("Could not delete project", 500);

    return NextResponse.json({ deleted: true });
  });
}
