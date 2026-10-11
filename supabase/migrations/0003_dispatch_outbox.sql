-- Dispatch outbox: durable job queue for GitHub Actions triggers.
--
-- WHY THIS EXISTS
--   The dashboard must trigger a scan when a target is saved, but GitHub's
--   dispatch API is a network call that can fail (rate limit, 5xx, deploy
--   blip). If the dispatch is lost, the target is enrolled but never scanned —
--   silently. The outbox makes the intent durable first, then delivers it.
--
--   Ordering guarantee:
--     1. INSERT the target row and the outbox row in one transaction.
--     2. A server-side dispatcher drains the outbox.
--     3. Each row records attempts, last error, and a next_retry_at backoff.
--
--   A dispatch that was accepted by GitHub is NOT a completed scan; it only
--   means "queued". Scan truth lives in scan_runs.

create table if not exists dispatch_jobs (
  id            uuid primary key default gen_random_uuid(),
  owner_id      uuid not null references auth.users(id) on delete cascade,
  project_id    uuid references projects(id) on delete cascade,
  asset_id      uuid references assets(id) on delete cascade,

  -- Workflow inputs, captured at enqueue time so a later edit to the target
  -- cannot change what an already-queued job scans.
  payload        jsonb not null default '{}'::jsonb,

  status        text not null default 'pending'
                check (status in
                  ('pending', 'dispatching', 'queued', 'running',
                   'completed', 'failed', 'cancelled')),

  attempts      integer not null default 0 check (attempts >= 0),
  max_attempts  integer not null default 5 check (max_attempts >= 1),

  -- Delivery bookkeeping.
  last_error    text check (last_error is null or length(last_error) <= 2000),
  next_retry_at timestamptz,

  -- GitHub side. github_run_id is filled once the dispatched run is observed;
  -- a null value with status='queued' means GitHub accepted it but we have not
  -- yet correlated the run.
  github_run_id text,
  dispatched_at timestamptz,

  -- Operator-safe reason the job was created, shown in the dashboard.
  reason        text not null default 'manual'
                check (reason in ('target_created', 'bulk_import', 'manual',
                                  'retry', 'schedule')),

  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- The dispatcher's claim query: oldest pending job that is due.
create index if not exists dispatch_jobs_claim_idx
  on dispatch_jobs(status, next_retry_at nulls first, created_at);

create index if not exists dispatch_jobs_owner_idx
  on dispatch_jobs(owner_id, created_at desc);

create index if not exists dispatch_jobs_asset_idx
  on dispatch_jobs(asset_id, created_at desc);

create index if not exists dispatch_jobs_github_run_idx
  on dispatch_jobs(github_run_id);

drop trigger if exists dispatch_jobs_touch on dispatch_jobs;
create trigger dispatch_jobs_touch before update on dispatch_jobs
  for each row execute function touch_updated_at();

-- ---------------------------------------------------------------------------
-- Concurrency guard: never two live scans for the same asset.
--
-- A partial unique index is the right tool here because it enforces the
-- invariant at the storage layer, so even a buggy or racing dispatcher cannot
-- enqueue a duplicate.
-- ---------------------------------------------------------------------------
create unique index if not exists dispatch_jobs_one_active_per_asset
  on dispatch_jobs(asset_id)
  where asset_id is not null
    and status in ('pending', 'dispatching', 'queued', 'running');

-- ---------------------------------------------------------------------------
-- Enqueue helper.
--
-- Idempotent: if a live job already exists for the asset it is returned
-- unchanged rather than duplicated, which is what makes double-clicking
-- "Save & Start Monitoring" safe.
-- ---------------------------------------------------------------------------
create or replace function enqueue_scan(
  p_owner     uuid,
  p_project_id uuid default null,
  p_asset_id  uuid default null,
  p_reason    text default 'manual',
  p_payload   jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_existing uuid;
  v_new      uuid;
begin
  -- Already a live job for this asset? Reuse it.
  if p_asset_id is not null then
    select id into v_existing
    from dispatch_jobs
    where asset_id = p_asset_id
      and status in ('pending', 'dispatching', 'queued', 'running')
    order by created_at desc
    limit 1;

    if v_existing is not null then
      return v_existing;
    end if;
  end if;

  insert into dispatch_jobs (owner_id, project_id, asset_id, reason, payload)
  values (p_owner, p_project_id, p_asset_id, p_reason, coalesce(p_payload, '{}'::jsonb))
  returning id into v_new;

  return v_new;
end;
$$;

-- ---------------------------------------------------------------------------
-- Claim a due job for dispatching (SKIP LOCKED makes this safe under
-- concurrent dispatchers, e.g. two serverless invocations at once).
-- ---------------------------------------------------------------------------
create or replace function claim_dispatch_job(p_limit integer default 5)
returns setof dispatch_jobs
language plpgsql
security definer
set search_path = public
as $$
begin
  return query
  update dispatch_jobs j
  set status = 'dispatching',
      attempts = j.attempts + 1,
      updated_at = now()
  where j.id in (
    select id
    from dispatch_jobs
    where status = 'pending'
      and (next_retry_at is null or next_retry_at <= now())
    order by next_retry_at nulls first, created_at
    limit p_limit
    for update skip locked
  )
  returning j.*;
end;
$$;

-- Mark a dispatch as accepted by GitHub (queued, not complete).
create or replace function mark_dispatch_queued(
  p_job uuid,
  p_github_run_id text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update dispatch_jobs
  set status = 'queued',
      dispatched_at = now(),
      github_run_id = coalesce(p_github_run_id, github_run_id),
      last_error = null,
      next_retry_at = null,
      updated_at = now()
  where id = p_job;
end;
$$;

-- Record a failed dispatch attempt with exponential backoff.
create or replace function mark_dispatch_failed(
  p_job uuid,
  p_error text,
  p_backoff_seconds integer default 60
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_attempts integer;
  v_max     integer;
begin
  select attempts, max_attempts into v_attempts, v_max
  from dispatch_jobs where id = p_job;

  if v_attempts >= v_max then
    update dispatch_jobs
    set status = 'failed',
        last_error = left(p_error, 2000),
        next_retry_at = null,
        updated_at = now()
    where id = p_job;
  else
    -- Exponential backoff, capped at 30 minutes.
    update dispatch_jobs
    set status = 'pending',
        last_error = left(p_error, 2000),
        next_retry_at = now() + make_interval(
          secs => least(p_backoff_seconds * power(2, v_attempts - 1), 1800)::int
        ),
        updated_at = now()
    where id = p_job;
  end if;
end;
$$;

-- Manual retry: reset a failed job so the dispatcher picks it up again.
create or replace function retry_dispatch_job(p_job uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update dispatch_jobs
  set status = 'pending',
      attempts = 0,
      last_error = null,
      next_retry_at = now(),
      updated_at = now()
  where id = p_job
    and status in ('failed', 'cancelled');
end;
$$;

-- ---------------------------------------------------------------------------
-- RLS: the outbox is server-managed. The browser may read its own jobs (to
-- render status) but never write them; all writes go through the service role.
-- ---------------------------------------------------------------------------
alter table dispatch_jobs enable row level security;

drop policy if exists dispatch_jobs_select on dispatch_jobs;
create policy dispatch_jobs_select on dispatch_jobs
  for select
  using (owner_id = auth.uid());

-- ---------------------------------------------------------------------------
-- Realtime: status pills must update without a page reload.
-- ---------------------------------------------------------------------------
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table dispatch_jobs;
  exception when duplicate_object then null;
end
$$;
