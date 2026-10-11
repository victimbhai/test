/**
 * Database types mirroring supabase/migrations.
 *
 * Kept hand-written rather than generated so the file stays readable and does
 * not require a live project to typecheck. Regenerate with
 * `supabase gen types typescript` if the schema changes materially.
 */

export type ScanStatus =
  | "queued"
  | "running"
  | "success"
  | "partial"
  | "failed"
  | "cancelled";

export type ChangeKind = "baseline" | "modified" | "restored";

export type NotifyChannel = "telegram" | "slack" | "email";

export type NotifyStatus = "sent" | "failed" | "deduplicated" | "skipped";

export interface Project {
  id: string;
  owner_id: string;
  name: string;
  primary_domain: string | null;
  description: string | null;
  tags: string[];
  enabled: boolean;
  interval_minutes: number;
  scope_notes: string | null;
  allowed_hosts: string[];
  created_at: string;
  updated_at: string;
}

export interface Asset {
  id: string;
  project_id: string;
  url: string;
  enabled: boolean;
  latest_hash: string | null;
  latest_version_id: string | null;
  last_checked_at: string | null;
  last_changed_at: string | null;
  last_http_status: number | null;
  etag: string | null;
  last_modified: string | null;
  file_size: number | null;
  discovery_source: "manual" | "discovery" | "import";
  created_at: string;
  updated_at: string;
}

export interface AssetVersion {
  id: string;
  asset_id: string;
  sha256_hash: string;
  storage_object_path: string;
  file_size: number;
  captured_at: string;
  scan_run_id: string | null;
}

export interface ScanRun {
  id: string;
  github_run_id: string | null;
  trigger_type: "schedule" | "workflow_dispatch" | "manual" | "api";
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
  assets_checked: number;
  changes_detected: number;
  errors_count: number;
  project_id: string | null;
  asset_id: string | null;
  error_summary: string | null;
  created_at: string;
}

export interface ChangeEvent {
  id: string;
  asset_id: string;
  previous_version_id: string | null;
  current_version_id: string;
  detected_at: string;
  size_difference: number;
  change_metadata: ChangeMetadata;
}

export interface IndicatorSummary {
  total: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
}

export interface ChangeMetadata {
  added_lines?: number;
  removed_lines?: number;
  size_delta_bytes?: number;
  size_delta_percent?: number;
  indicator_summary?: IndicatorSummary;
  truncated?: boolean;
}

export interface NotificationSetting {
  id: string;
  project_id: string | null;
  channel: NotifyChannel;
  enabled: boolean;
  min_severity: "low" | "medium" | "high";
  has_bot_token: boolean;
  has_chat_id: boolean;
  has_webhook: boolean;
  created_at: string;
  updated_at: string;
}

export interface NotificationEvent {
  id: string;
  change_event_id: string | null;
  asset_id: string;
  channel: NotifyChannel;
  status: NotifyStatus;
  error: string | null;
  sent_at: string;
}

export interface MonitoringSettings {
  id: string;
  owner_id: string;
  schedule_cron: string;
  max_versions_per_asset: number;
  max_bytes_per_asset: number;
  notify_on_baseline: boolean;
  auto_discover_on_create: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: string;
  owner_id: string | null;
  action: string;
  entity_type: string;
  entity_id: string | null;
  details: Record<string, unknown>;
  ip_address: string | null;
  created_at: string;
}

/** Shape returned by the dashboard_stats() SQL function. */
export interface DashboardStats {
  projects: number;
  assets: number;
  active_assets: number;
  changes_24h: number;
  changes_7d: number;
  failed_checks: number;
  last_successful_scan: string | null;
}

/** Row from the recent_changes view. */
export interface RecentChange {
  id: string;
  asset_id: string;
  asset_url: string;
  project_id: string;
  project_name: string;
  owner_id: string;
  previous_version_id: string | null;
  current_version_id: string;
  detected_at: string;
  size_difference: number;
  change_metadata: ChangeMetadata;
  previous_size: number | null;
  current_size: number;
  previous_hash: string | null;
  current_hash: string;
}

/** A security-relevant review indicator produced by the engine. */
export interface ReviewIndicator {
  category: string;
  label: string;
  severity: "high" | "medium" | "low";
  line_number: number;
  match: string;
  context: string;
}

/** Diff payload served by /api/changes/[id]/diff. */
export interface DiffPayload {
  unified: string;
  hunks: Array<{
    old_start: number;
    old_lines: string[];
    new_start: number;
    new_lines: string[];
  }>;
  added_lines: number;
  removed_lines: number;
  old_lines: number;
  new_lines: number;
  truncated: boolean;
  context_lines: number;
  indicators: ReviewIndicator[];
}

export interface Database {
  public: {
    Tables: {
      projects: { Row: Project; Insert: Partial<Project>; Update: Partial<Project> };
      assets: { Row: Asset; Insert: Partial<Asset>; Update: Partial<Asset> };
      asset_versions: {
        Row: AssetVersion;
        Insert: Partial<AssetVersion>;
        Update: Partial<AssetVersion>;
      };
      scan_runs: { Row: ScanRun; Insert: Partial<ScanRun>; Update: Partial<ScanRun> };
      change_events: {
        Row: ChangeEvent;
        Insert: Partial<ChangeEvent>;
        Update: Partial<ChangeEvent>;
      };
      notification_settings: {
        Row: NotificationSetting;
        Insert: Partial<NotificationSetting>;
        Update: Partial<NotificationSetting>;
      };
      notification_events: {
        Row: NotificationEvent;
        Insert: Partial<NotificationEvent>;
        Update: Partial<NotificationEvent>;
      };
      monitoring_settings: {
        Row: MonitoringSettings;
        Insert: Partial<MonitoringSettings>;
        Update: Partial<MonitoringSettings>;
      };
      audit_logs: { Row: AuditLog; Insert: Partial<AuditLog>; Update: Partial<AuditLog> };
    };
    Views: {
      notification_settings_safe: { Row: NotificationSetting };
      recent_changes: { Row: RecentChange };
    };
    Functions: {
      dashboard_stats: {
        Args: { p_owner?: string };
        Returns: DashboardStats;
      };
    };
  };
}
