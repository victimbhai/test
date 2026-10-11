-- JSMon Security Dashboard — initial schema
--
-- Design notes
--   * Every table is owned by an authenticated Supabase user (owner_id) and
--     protected by Row Level Security. This is a personal dashboard: the
--     default policy grants access only to rows the caller owns.
--   * asset_versions is immutable. There is no UPDATE policy, and a unique
--     key on (asset_id, sha256_hash) makes re-inserting identical content a
--     no-op, which keeps historical references stable.
--   * change_events is likewise deduplicated on (asset_id, current_version_id)
--     so a re-scan can never produce a duplicate event.
--   * The monitoring engine runs with the service role (bypasses RLS); the
--     dashboard runs with the user's JWT and is confined by these policies.

create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------------------
-- Enum-like domains
-- ---------------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_type where typname = 'scan_status') then
    create type scan_status as enum (
      'queued', 'running', 'success', 'partial', 'failed', 'cancelled'
    );
  end if;
  if not exists (select 1 from pg_type where typname = 'change_kind') then
    create type change_kind as enum ('baseline', 'modified', 'restored');
  end if;
  if not exists (select 1 from pg_type where typname = 'notify_channel') then
    create type notify_channel as enum ('telegram', 'slack', 'email');
  end if;
  if not exists (select 1 from pg_type where typname = 'notify_status') then
    create type notify_status as enum ('sent', 'failed', 'deduplicated', 'skipped');
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- projects
-- ---------------------------------------------------------------------------
create table if not exists projects (
  id             uuid primary key default gen_random_uuid(),
  owner_id       uuid not null references auth.users(id) on delete cascade,
  name           text not null check (length(btrim(name)) between 1 and 120),
  primary_domain text,
  description    text check (description is null or length(description) <= 2000),
  tags           text[] not null default '{}',
  enabled        boolean not null default true,
  -- Monitoring preference; the scheduler still runs on the GitHub Actions
  -- cron, this is the operator's declared intent shown in the dashboard.
  interval_minutes integer not null default 15
                   check (interval_minutes between 1 and 10080),
  -- Authorization/scope notes: what the operator is permitted to test.
  scope_notes    text check (scope_notes is null or length(scope_notes) <= 4000),
  -- Explicit hostname allowlist for discovery and fetching.
  allowed_hosts  text[] not null default '{}',
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create index if not exists projects_owner_idx on projects(owner_id);
create index if not exists projects_enabled_idx on projects(owner_id, enabled);

-- ---------------------------------------------------------------------------
-- assets — one JavaScript URL being monitored
-- ---------------------------------------------------------------------------
create table if not exists assets (
  id                 uuid primary key default gen_random_uuid(),
  project_id         uuid not null references projects(id) on delete cascade,
  url                text not null,
  enabled            boolean not null default true,
  -- Denormalised pointer to the current snapshot for fast dashboard reads.
  latest_hash        text,
  latest_version_id  uuid,
  last_checked_at    timestamptz,
  last_changed_at    timestamptz,
  last_http_status   integer,
  -- Conditional-request validators, so unchanged assets are not re-downloaded.
  etag               text,
  last_modified      text,
  file_size          bigint,
  discovery_source   text not null default 'manual'
                     check (discovery_source in ('manual', 'discovery', 'import')),
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  -- One row per URL inside a project.
  unique (project_id, url)
);

create index if not exists assets_project_idx on assets(project_id);
create index if not exists assets_enabled_idx on assets(project_id, enabled);
create index if not exists assets_last_checked_idx on assets(last_checked_at);

-- ---------------------------------------------------------------------------
-- asset_versions — immutable snapshots
-- ---------------------------------------------------------------------------
create table if not exists asset_versions (
  id                  uuid primary key default gen_random_uuid(),
  asset_id            uuid not null references assets(id) on delete cascade,
  sha256_hash         text not null check (sha256_hash ~ '^[0-9a-f]{64}$'),
  -- Path inside the private Supabase Storage bucket.
  storage_object_path text not null,
  file_size           bigint not null check (file_size >= 0),
  captured_at         timestamptz not null default now(),
  scan_run_id         uuid,
  -- Immutability: identical content for one asset is stored exactly once.
  unique (asset_id, sha256_hash)
);

create index if not exists asset_versions_asset_idx
  on asset_versions(asset_id, captured_at desc);

-- ---------------------------------------------------------------------------
-- scan_runs — one execution of the monitoring engine
-- ---------------------------------------------------------------------------
create table if not exists scan_runs (
  id               uuid primary key default gen_random_uuid(),
  -- GitHub Actions run id, used to link the dashboard row to the workflow.
  github_run_id    text,
  trigger_type     text not null default 'manual'
                   check (trigger_type in
                     ('schedule', 'workflow_dispatch', 'manual', 'api')),
  status           scan_status not null default 'queued',
  started_at       timestamptz not null default now(),
  completed_at     timestamptz,
  duration_seconds integer generated always as (
                     case
                       when completed_at is null then null
                       else extract(epoch from (completed_at - started_at))::int
                     end
                   ) stored,
  assets_checked   integer not null default 0,
  changes_detected integer not null default 0,
  errors_count     integer not null default 0,
  -- Optional scope of the run (null = every enabled asset).
  project_id       uuid references projects(id) on delete set null,
  asset_id         uuid references assets(id) on delete set null,
  -- Operator-safe error text. Credentials and response bodies are never stored.
  error_summary    text check (error_summary is null or length(error_summary) <= 4000),
  created_at       timestamptz not null default now()
);

create index if not exists scan_runs_started_idx on scan_runs(started_at desc);
create index if not exists scan_runs_status_idx on scan_runs(status);
create index if not exists scan_runs_github_idx on scan_runs(github_run_id);

-- The engine inserts asset_versions.scan_run_id without an FK to keep the
-- worker decoupled; add it once both tables exist.
do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'asset_versions_scan_run_fk'
  ) then
    alter table asset_versions
      add constraint asset_versions_scan_run_fk
      foreign key (scan_run_id) references scan_runs(id) on delete set null;
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- change_events — a detected content change
-- ---------------------------------------------------------------------------
create table if not exists change_events (
  id                  uuid primary key default gen_random_uuid(),
  asset_id            uuid not null references assets(id) on delete cascade,
  previous_version_id uuid references asset_versions(id) on delete set null,
  current_version_id  uuid not null references asset_versions(id) on delete cascade,
  detected_at         timestamptz not null default now(),
  -- current size - previous size, in bytes.
  size_difference     bigint not null default 0,
  change_metadata     jsonb not null default '{}'::jsonb,
  -- Deduplication: one event per (asset, new version).
  unique (asset_id, current_version_id)
);

create index if not exists change_events_asset_idx
  on change_events(asset_id, detected_at desc);
create index if not exists change_events_detected_idx on change_events(detected_at desc);

-- ---------------------------------------------------------------------------
-- notification_settings — one row per project + channel
-- ---------------------------------------------------------------------------
create table if not exists notification_settings (
  id          uuid primary key default gen_random_uuid(),
  project_id  uuid references projects(id) on delete cascade,
  channel     notify_channel not null,
  -- Credentials are stored server-side only and never selected by the
  -- dashboard's anon/authenticated policies.
  bot_token   text,
  chat_id     text,
  webhook_url text,
  enabled     boolean not null default false,
  -- Only notify for changes carrying at least one indicator of this severity.
  min_severity text not null default 'low'
                check (min_severity in ('low', 'medium', 'high')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (project_id, channel)
);

create index if not exists notification_settings_project_idx
  on notification_settings(project_id);

-- ---------------------------------------------------------------------------
-- notification_events — delivery audit trail
-- ---------------------------------------------------------------------------
create table if not exists notification_events (
  id              uuid primary key default gen_random_uuid(),
  change_event_id uuid references change_events(id) on delete cascade,
  asset_id        uuid references assets(id) on delete cascade,
  channel         notify_channel not null,
  status          notify_status not null,
  error           text check (error is null or length(error) <= 500),
  sent_at         timestamptz not null default now()
);

create index if not exists notification_events_asset_idx
  on notification_events(asset_id, sent_at desc);
create index if not exists notification_events_change_idx
  on notification_events(change_event_id);

-- ---------------------------------------------------------------------------
-- monitoring_settings — singleton operator preferences
-- ---------------------------------------------------------------------------
create table if not exists monitoring_settings (
  id                       uuid primary key default gen_random_uuid(),
  owner_id                 uuid not null unique references auth.users(id) on delete cascade,
  schedule_cron            text not null default '7,22,37,52 * * * *',
  -- Retention: how many versions to keep per asset. 0 = unlimited.
  max_versions_per_asset   integer not null default 50 check (max_versions_per_asset >= 0),
  max_bytes_per_asset      bigint not null default 20971520 check (max_bytes_per_asset > 0),
  notify_on_baseline       boolean not null default false,
  auto_discover_on_create  boolean not null default false,
  created_at               timestamptz not null default now(),
  updated_at               timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- audit_logs — administrative actions
-- ---------------------------------------------------------------------------
create table if not exists audit_logs (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid references auth.users(id) on delete set null,
  action      text not null check (length(btrim(action)) between 1 and 80),
  entity_type text not null check (length(btrim(entity_type)) between 1 and 40),
  entity_id   uuid,
  details     jsonb not null default '{}'::jsonb,
  ip_address  inet,
  created_at  timestamptz not null default now()
);

create index if not exists audit_logs_owner_idx
  on audit_logs(owner_id, created_at desc);
create index if not exists audit_logs_entity_idx
  on audit_logs(entity_type, entity_id);

-- ---------------------------------------------------------------------------
-- updated_at maintenance
-- ---------------------------------------------------------------------------
create or replace function touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists projects_touch on projects;
create trigger projects_touch before update on projects
  for each row execute function touch_updated_at();

drop trigger if exists assets_touch on assets;
create trigger assets_touch before update on assets
  for each row execute function touch_updated_at();

drop trigger if exists notification_settings_touch on notification_settings;
create trigger notification_settings_touch before update on notification_settings
  for each row execute function touch_updated_at();

drop trigger if exists monitoring_settings_touch on monitoring_settings;
create trigger monitoring_settings_touch before update on monitoring_settings
  for each row execute function touch_updated_at();

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------
alter table projects               enable row level security;
alter table assets                 enable row level security;
alter table asset_versions         enable row level security;
alter table scan_runs              enable row level security;
alter table change_events          enable row level security;
alter table notification_settings  enable row level security;
alter table notification_events    enable row level security;
alter table monitoring_settings    enable row level security;
alter table audit_logs             enable row level security;

-- projects: full CRUD for the owner only
drop policy if exists projects_owner_all on projects;
create policy projects_owner_all on projects
  for all
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

-- assets: access follows the parent project
drop policy if exists assets_via_project on assets;
create policy assets_via_project on assets
  for all
  using (exists (
    select 1 from projects p
    where p.id = assets.project_id and p.owner_id = auth.uid()
  ))
  with check (exists (
    select 1 from projects p
    where p.id = assets.project_id and p.owner_id = auth.uid()
  ));

-- asset_versions: readable and immutable. No update/delete policy exists, so
-- history can never be rewritten through the client APIs.
drop policy if exists asset_versions_via_asset on asset_versions;
create policy asset_versions_via_asset on asset_versions
  for select
  using (exists (
    select 1 from assets a
    join projects p on p.id = a.project_id
    where a.id = asset_versions.asset_id and p.owner_id = auth.uid()
  ));

drop policy if exists asset_versions_insert on asset_versions;
create policy asset_versions_insert on asset_versions
  for insert
  with check (exists (
    select 1 from assets a
    join projects p on p.id = a.project_id
    where a.id = asset_versions.asset_id and p.owner_id = auth.uid()
  ));

-- scan_runs: read-only for the owner
drop policy if exists scan_runs_select on scan_runs;
create policy scan_runs_select on scan_runs
  for select
  using (
    project_id is null
    or exists (
      select 1 from projects p
      where p.id = scan_runs.project_id and p.owner_id = auth.uid()
    )
  );

-- change_events: read-only for the owner
drop policy if exists change_events_select on change_events;
create policy change_events_select on change_events
  for select
  using (exists (
    select 1 from assets a
    join projects p on p.id = a.project_id
    where a.id = change_events.asset_id and p.owner_id = auth.uid()
  ));

-- notification_settings: owner-managed, but credentials are never exposed to
-- the browser. The dashboard reads only `enabled`/`min_severity` through a
-- restricted view; writes go through the server API with the service role.
drop policy if exists notification_settings_via_project on notification_settings;
create policy notification_settings_via_project on notification_settings
  for all
  using (
    project_id is null
    or exists (
      select 1 from projects p
      where p.id = notification_settings.project_id and p.owner_id = auth.uid()
    )
  )
  with check (
    project_id is null
    or exists (
      select 1 from projects p
      where p.id = notification_settings.project_id and p.owner_id = auth.uid()
    )
  );

-- notification_events: read-only for the owner
drop policy if exists notification_events_select on notification_events;
create policy notification_events_select on notification_events
  for select
  using (exists (
    select 1 from assets a
    join projects p on p.id = a.project_id
    where a.id = notification_events.asset_id and p.owner_id = auth.uid()
  ));

-- monitoring_settings: owner only
drop policy if exists monitoring_settings_owner on monitoring_settings;
create policy monitoring_settings_owner on monitoring_settings
  for all
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

-- audit_logs: read-only for the owner, written by the server
drop policy if exists audit_logs_select on audit_logs;
create policy audit_logs_select on audit_logs
  for select
  using (owner_id = auth.uid());

-- ---------------------------------------------------------------------------
-- Safe view: notification settings without credentials
-- ---------------------------------------------------------------------------
create or replace view notification_settings_safe
with (security_invoker = true) as
select
  id,
  project_id,
  channel,
  enabled,
  min_severity,
  -- Presence flags only; never the credential itself.
  (bot_token is not null and length(btrim(bot_token)) > 0)   as has_bot_token,
  (chat_id is not null and length(btrim(chat_id)) > 0)       as has_chat_id,
  (webhook_url is not null and length(btrim(webhook_url)) > 0) as has_webhook,
  created_at,
  updated_at
from notification_settings;

-- ---------------------------------------------------------------------------
-- Dashboard statistics helper
-- ---------------------------------------------------------------------------
create or replace function dashboard_stats(p_owner uuid default auth.uid())
returns jsonb
language sql
stable
security invoker
as $$
  select jsonb_build_object(
    'projects', (
      select count(*) from projects where owner_id = p_owner
    ),
    'assets', (
      select count(*) from assets a
      join projects p on p.id = a.project_id
      where p.owner_id = p_owner
    ),
    'active_assets', (
      select count(*) from assets a
      join projects p on p.id = a.project_id
      where p.owner_id = p_owner and a.enabled and p.enabled
    ),
    'changes_24h', (
      select count(*) from change_events ce
      join assets a on a.id = ce.asset_id
      join projects p on p.id = a.project_id
      where p.owner_id = p_owner
        and ce.detected_at > now() - interval '24 hours'
    ),
    'changes_7d', (
      select count(*) from change_events ce
      join assets a on a.id = ce.asset_id
      join projects p on p.id = a.project_id
      where p.owner_id = p_owner
        and ce.detected_at > now() - interval '7 days'
    ),
    'failed_checks', (
      select count(*) from assets a
      join projects p on p.id = a.project_id
      where p.owner_id = p_owner and a.enabled
        and a.last_http_status is not null
        and a.last_http_status >= 400
    ),
    'last_successful_scan', (
      select max(s.completed_at) from scan_runs s
      left join projects p on p.id = s.project_id
      where s.status = 'success'
        and (s.project_id is null or p.owner_id = p_owner)
    )
  );
$$;

-- ---------------------------------------------------------------------------
-- Realtime publication for dashboard live updates
-- ---------------------------------------------------------------------------
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table change_events;
  exception when duplicate_object then null;
end
$$;

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table assets;
  exception when duplicate_object then null;
end
$$;

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table scan_runs;
  exception when duplicate_object then null;
end
$$;
