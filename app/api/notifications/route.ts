import { NextResponse } from "next/server";

import { createClient, createServiceClient } from "@/lib/supabase/server";
import {
  assertProjectOwnership,
  jsonError,
  parseBody,
  requireAuth,
  withErrorHandling,
} from "@/lib/api/helpers";
import { notificationSettingsSchema } from "@/lib/validation/schemas";
import type { NotificationSetting } from "@/lib/supabase/types";

/**
 * Notification channel management.
 *
 * Credentials (bot tokens, webhook URLs) are written with the service role and
 * are NEVER read back to the browser: the UI sees only presence flags via the
 * `notification_settings_safe` view. Test sends happen server-side.
 */

/** GET /api/notifications — settings for the caller's projects. */
export async function GET(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const projectId = new URL(request.url).searchParams.get("project_id");
    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    let query = supabase
      .from("notification_settings_safe")
      .select("*")
      .order("created_at", { ascending: false });

    if (projectId) {
      if (!(await assertProjectOwnership(supabase, projectId, auth.data.userId))) {
        return jsonError("Project not found", 404);
      }
      query = query.eq("project_id", projectId);
    }

    const { data, error } = await query;
    if (error) return jsonError("Could not load notification settings", 500);

    return NextResponse.json({
      settings: (data ?? []) as NotificationSetting[],
    });
  });
}

/** POST /api/notifications — create or update a channel. */
export async function POST(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const body = await parseBody(request, notificationSettingsSchema);
    if (!body.ok) return body.response;

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    if (body.data.project_id) {
      if (
        !(await assertProjectOwnership(supabase, body.data.project_id, auth.data.userId))
      ) {
        return jsonError("Project not found", 404);
      }
    }

    const service = createServiceClient();
    if (!service) return jsonError("Server is missing the service key", 503);

    // Channel-specific validation: Telegram needs token + chat, Slack a token.
    if (body.data.enabled) {
      if (body.data.channel === "telegram") {
        if (!body.data.bot_token || !body.data.chat_id) {
          return jsonError(
            "Telegram requires both a bot token and a chat ID",
            422,
          );
        }
      }
      if (body.data.channel === "slack" && !body.data.bot_token) {
        return jsonError("Slack requires a bot token", 422);
      }
    }

    const row: Record<string, unknown> = {
      project_id: body.data.project_id ?? null,
      channel: body.data.channel,
      enabled: body.data.enabled,
      min_severity: body.data.min_severity,
      updated_at: new Date().toISOString(),
    };

    // Only overwrite a credential when a new value is supplied, so the UI can
    // save "enabled" without re-pasting the token.
    if (body.data.bot_token) row.bot_token = body.data.bot_token;
    if (body.data.chat_id) row.chat_id = body.data.chat_id;
    if (body.data.webhook_url) row.webhook_url = body.data.webhook_url;

    const { data, error } = await service
      .from("notification_settings")
      .upsert(row, { onConflict: "project_id,channel" })
      .select()
      .single();

    if (error || !data) return jsonError("Could not save notification settings", 500);

    // Read back through the safe view so no credential is echoed.
    const { data: safe } = await supabase
      .from("notification_settings_safe")
      .select("*")
      .eq("id", data.id)
      .maybeSingle();

    return NextResponse.json({
      setting: (safe ?? data) as NotificationSetting,
    });
  });
}

/** POST /api/notifications/test — send a test message. */
export async function PUT(request: Request) {
  return withErrorHandling(async () => {
    const auth = await requireAuth();
    if (!auth.ok) return auth.response;

    const body = await parseBody(
      request,
      notificationSettingsSchema.pick({ channel: true, project_id: true }),
    );
    if (!body.ok) return body.response;

    const supabase = await createClient();
    if (!supabase) return jsonError("Supabase unavailable", 503);

    if (body.data.project_id) {
      if (
        !(await assertProjectOwnership(supabase, body.data.project_id, auth.data.userId))
      ) {
        return jsonError("Project not found", 404);
      }
    }

    const service = createServiceClient();
    if (!service) return jsonError("Server is missing the service key", 503);

    const { data: settings } = await service
      .from("notification_settings")
      .select("*")
      .eq("channel", body.data.channel)
      .is("project_id", body.data.project_id ?? null)
      .maybeSingle();

    if (!settings) {
      return jsonError("No configuration saved for this channel", 404);
    }

    const result = await sendTestNotification(settings, body.data.channel);

    return NextResponse.json(result, { status: result.ok ? 200 : 502 });
  });
}

interface ChannelRow {
  channel: string;
  bot_token: string | null;
  chat_id: string | null;
  webhook_url: string | null;
}

async function sendTestNotification(
  settings: ChannelRow,
  channel: string,
): Promise<{ ok: boolean; detail: string }> {
  const message = "JSMon test notification: your configuration is working.";

  try {
    if (channel === "telegram") {
      if (!settings.bot_token || !settings.chat_id) {
        return { ok: false, detail: "Telegram token or chat ID is missing" };
      }
      const response = await fetch(
        `https://api.telegram.org/bot${settings.bot_token}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: settings.chat_id,
            text: message,
          }),
        },
      );
      const payload = (await response.json()) as {
        ok: boolean;
        description?: string;
      };
      return payload.ok
        ? { ok: true, detail: "Telegram test message accepted" }
        : { ok: false, detail: payload.description ?? "Telegram rejected the message" };
    }

    if (channel === "slack") {
      if (!settings.bot_token) {
        return { ok: false, detail: "Slack token is missing" };
      }
      const response = await fetch("https://slack.com/api/chat.postMessage", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${settings.bot_token}`,
        },
        body: JSON.stringify({
          channel: settings.chat_id ?? "",
          text: message,
        }),
      });
      const payload = (await response.json()) as {
        ok: boolean;
        error?: string;
      };
      return payload.ok
        ? { ok: true, detail: "Slack test message accepted" }
        : { ok: false, detail: payload.error ?? "Slack rejected the message" };
    }

    return { ok: false, detail: `Unsupported channel: ${channel}` };
  } catch (error) {
    return {
      ok: false,
      detail:
        error instanceof Error ? error.message.slice(0, 200) : "Request failed",
    };
  }
}
