"use client";

import { useEffect, useState } from "react";
import { Bell, Loader2, Send, ShieldCheck } from "lucide-react";

import { useProjects } from "@/lib/hooks/useMonitoring";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { toast } from "sonner";

interface ChannelSetting {
  id: string;
  project_id: string | null;
  channel: string;
  enabled: boolean;
  min_severity: string;
  has_bot_token: boolean;
  has_chat_id: boolean;
}

/**
 * Notification channel configuration.
 *
 * Credentials are written server-side and never read back: the UI shows
 * presence flags ("token saved") rather than values. Test sends go through
 * the API, which uses the stored credential directly.
 */
export default function NotificationsPage() {
  const { data: projectsData } = useProjects();
  const projects = projectsData?.projects ?? [];

  const [projectId, setProjectId] = useState<string | null>(null);
  const [settings, setSettings] = useState<ChannelSetting[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);

  const [telegram, setTelegram] = useState({
    enabled: false,
    bot_token: "",
    chat_id: "",
    min_severity: "low",
  });
  const [slack, setSlack] = useState({
    enabled: false,
    bot_token: "",
    chat_id: "",
    min_severity: "low",
  });

  useEffect(() => {
    if (projects.length > 0 && projectId === null) {
      setProjectId(projects[0].id);
    }
  }, [projects, projectId]);

  useEffect(() => {
    if (!projectId) return;
    let cancelled = false;
    setLoading(true);
    fetch(`/api/notifications?project_id=${projectId}`)
      .then((response) => response.json())
      .then((payload) => {
        if (cancelled) return;
        const rows = (payload.settings ?? []) as ChannelSetting[];
        setSettings(rows);

        const tg = rows.find((row) => row.channel === "telegram");
        const sl = rows.find((row) => row.channel === "slack");

        setTelegram({
          enabled: tg?.enabled ?? false,
          bot_token: "",
          chat_id: "",
          min_severity: tg?.min_severity ?? "low",
        });
        setSlack({
          enabled: sl?.enabled ?? false,
          bot_token: "",
          chat_id: "",
          min_severity: sl?.min_severity ?? "low",
        });
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  async function save(
    channel: "telegram" | "slack",
    values: { enabled: boolean; bot_token: string; chat_id: string; min_severity: string },
  ) {
    if (!projectId) return;
    setSaving(true);
    try {
      const response = await fetch("/api/notifications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: projectId,
          channel,
          enabled: values.enabled,
          min_severity: values.min_severity,
          ...(values.bot_token ? { bot_token: values.bot_token } : {}),
          ...(values.chat_id ? { chat_id: values.chat_id } : {}),
        }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error ?? "Save failed");
      toast.success(`${channel} settings saved`);
      // Clear the credential inputs; they are stored server-side now.
      if (channel === "telegram") setTelegram((prev) => ({ ...prev, bot_token: "", chat_id: "" }));
      else setSlack((prev) => ({ ...prev, bot_token: "", chat_id: "" }));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function test(channel: "telegram" | "slack") {
    if (!projectId) return;
    setTesting(channel);
    try {
      const response = await fetch("/api/notifications", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel, project_id: projectId }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error ?? "Test failed");
      toast.success(payload.detail ?? "Test message sent");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Test failed");
    } finally {
      setTesting(null);
    }
  }

  const tgSetting = settings.find((row) => row.channel === "telegram");
  const slSetting = settings.find((row) => row.channel === "slack");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Notifications</h1>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Get alerted when a monitored JavaScript file genuinely changes.
        </p>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-4">
          <Label htmlFor="notify-project" className="text-xs text-[var(--muted)]">
            Project
          </Label>
          <select
            id="notify-project"
            value={projectId ?? ""}
            onChange={(event) => setProjectId(event.target.value || null)}
            className="h-9 min-w-[220px] rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] px-3 text-sm"
          >
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
          <p className="text-xs text-[var(--muted)]">
            Preferences apply per project.
          </p>
        </CardContent>
      </Card>

      {loading ? (
        <div className="skeleton h-64 rounded-xl" />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <ChannelCard
            title="Telegram"
            description="Bot token plus chat ID. Changes arrive with hashes, sizes and a dashboard link."
            enabled={telegram.enabled}
            onEnabledChange={(value) =>
              setTelegram({ ...telegram, enabled: value })
            }
            botToken={telegram.bot_token}
            onBotTokenChange={(value) =>
              setTelegram({ ...telegram, bot_token: value })
            }
            chatId={telegram.chat_id}
            onChatIdChange={(value) => setTelegram({ ...telegram, chat_id: value })}
            minSeverity={telegram.min_severity}
            onMinSeverityChange={(value) =>
              setTelegram({ ...telegram, min_severity: value })
            }
            hasToken={tgSetting?.has_bot_token ?? false}
            hasChat={tgSetting?.has_chat_id ?? false}
            onSave={() => save("telegram", telegram)}
            onTest={() => test("telegram")}
            saving={saving}
            testing={testing === "telegram"}
            chatLabel="Chat ID"
          />

          <ChannelCard
            title="Slack"
            description="Bot token with chat:write. The bot must be invited to the channel."
            enabled={slack.enabled}
            onEnabledChange={(value) => setSlack({ ...slack, enabled: value })}
            botToken={slack.bot_token}
            onBotTokenChange={(value) => setSlack({ ...slack, bot_token: value })}
            chatId={slack.chat_id}
            onChatIdChange={(value) => setSlack({ ...slack, chat_id: value })}
            minSeverity={slack.min_severity}
            onMinSeverityChange={(value) => setSlack({ ...slack, min_severity: value })}
            hasToken={slSetting?.has_bot_token ?? false}
            hasChat={slSetting?.has_chat_id ?? false}
            onSave={() => save("slack", slack)}
            onTest={() => test("slack")}
            saving={saving}
            testing={testing === "slack"}
            chatLabel="Channel ID"
          />
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-ok-400" />
            How notification deduplication works
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-xs leading-relaxed text-[var(--muted)]">
          <p>
            An unchanged asset never alerts: the engine compares the SHA-256 of
            the downloaded bytes against the stored hash and skips identical
            content, including via conditional HTTP requests.
          </p>
          <p>
            A failed delivery is recorded in{" "}
            <code className="font-mono">notification_events</code> but never
            rolls back the stored scan result, so monitoring state stays correct
            even when a channel is down.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

function ChannelCard({
  title,
  description,
  enabled,
  onEnabledChange,
  botToken,
  onBotTokenChange,
  chatId,
  onChatIdChange,
  minSeverity,
  onMinSeverityChange,
  hasToken,
  hasChat,
  onSave,
  onTest,
  saving,
  testing,
  chatLabel,
}: {
  title: string;
  description: string;
  enabled: boolean;
  onEnabledChange: (value: boolean) => void;
  botToken: string;
  onBotTokenChange: (value: string) => void;
  chatId: string;
  onChatIdChange: (value: string) => void;
  minSeverity: string;
  onMinSeverityChange: (value: string) => void;
  hasToken: boolean;
  hasChat: boolean;
  onSave: () => void;
  onTest: () => void;
  saving: boolean;
  testing: boolean;
  chatLabel: string;
}) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-4 w-4" />
              {title}
            </CardTitle>
            <CardDescription>{description}</CardDescription>
          </div>
          <label className="flex cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(event) => onEnabledChange(event.target.checked)}
              className="h-4 w-4 accent-accent-500"
            />
            <span className="text-xs">{enabled ? "Enabled" : "Disabled"}</span>
          </label>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-1.5">
          <Label htmlFor={`${title}-token`}>Bot token</Label>
          <Input
            id={`${title}-token`}
            type="password"
            value={botToken}
            onChange={(event) => onBotTokenChange(event.target.value)}
            placeholder={hasToken ? "•••• stored ••••" : "paste token"}
            autoComplete="off"
          />
          {hasToken && !botToken && (
            <p className="text-[11px] text-ok-400">A token is already saved.</p>
          )}
        </div>

        <div className="space-y-1.5">
          <Label htmlFor={`${title}-chat`}>{chatLabel}</Label>
          <Input
            id={`${title}-chat`}
            value={chatId}
            onChange={(event) => onChatIdChange(event.target.value)}
            placeholder={hasChat ? "•••• stored ••••" : "e.g. -1001234567890"}
          />
          {hasChat && !chatId && (
            <p className="text-[11px] text-ok-400">
              A {chatLabel.toLowerCase()} is already saved.
            </p>
          )}
        </div>

        <div className="space-y-1.5">
          <Label htmlFor={`${title}-severity`}>Minimum indicator severity</Label>
          <select
            id={`${title}-severity`}
            value={minSeverity}
            onChange={(event) => onMinSeverityChange(event.target.value)}
            className="h-9 w-full rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] px-3 text-sm"
          >
            <option value="low">All changes</option>
            <option value="medium">Medium and above</option>
            <option value="high">High only</option>
          </select>
        </div>

        <div className="flex items-center gap-2 border-t border-[var(--border)] pt-3">
          <Button size="sm" onClick={onSave} disabled={saving}>
            {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Save
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={onTest}
            disabled={testing || !hasToken}
            title={!hasToken ? "Save a token first" : "Send a test message"}
          >
            {testing ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Send className="h-3.5 w-3.5" />
            )}
            Test
          </Button>
          {enabled && (
            <Badge variant="ok" className="ml-auto">
              Active
            </Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
