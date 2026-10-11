-- Retention policy enforcement and helper indexes.
--
-- The engine prunes old versions per asset (JSMON_MAX_VERSIONS_PER_ASSET), but
-- the database should also enforce an upper bound so a misconfigured run can
-- never grow asset_versions without limit. This function is invoked by the
-- runner after each scan and can also be called from a scheduled job.

create or replace function prune_asset_versions(
  p_asset_id uuid,
  p_keep integer
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  deleted integer;
begin
  if p_keep is null or p_keep <= 0 then
    return 0;
  end if;

  with ranked as (
    select id,
           row_number() over (order by captured_at desc, id desc) as rn
    from asset_versions
    where asset_id = p_asset_id
  ),
  doomed as (
    delete from asset_versions v
    using ranked r
    where v.id = r.id and r.rn > p_keep
    returning v.id
  )
  select count(*) into deleted from doomed;

  return deleted;
end;
$$;

-- Change events must never outlive the versions they reference. When a
-- version is pruned, its change event should go with it so the dashboard does
-- not show a change whose snapshots no longer exist.
create or replace function cleanup_orphan_change_events()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  deleted integer;
begin
  with doomed as (
    delete from change_events ce
    where not exists (
      select 1 from asset_versions v where v.id = ce.current_version_id
    )
    returning ce.id
  )
  select count(*) into deleted from doomed;
  return deleted;
end;
$$;

-- Keep assets.latest_version_id consistent: if the pointed-at version is
-- pruned, fall back to the newest surviving version.
create or replace function heal_asset_latest_version(p_asset_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v record;
begin
  select * into v
  from asset_versions
  where asset_id = p_asset_id
  order by captured_at desc, id desc
  limit 1;

  if v.id is null then
    return;
  end if;

  update assets
  set latest_version_id = v.id,
      latest_hash = v.sha256_hash,
      file_size = v.file_size,
      updated_at = now()
  where id = p_asset_id
    and (latest_version_id is distinct from v.id or latest_hash is distinct from v.sha256_hash);
end;
$$;

-- Indexes that make the dashboard's most common queries cheap.
create index if not exists assets_lookup_idx
  on assets(project_id, enabled, last_checked_at desc);
create index if not exists change_events_recent_idx
  on change_events(detected_at desc, asset_id);
create index if not exists scan_runs_recent_idx
  on scan_runs(started_at desc, status);

-- Change events joined to their asset + project, used by the activity feed.
create or replace view recent_changes
with (security_invoker = true) as
select
  ce.id,
  ce.asset_id,
  a.url                as asset_url,
  a.project_id,
  p.name               as project_name,
  p.owner_id,
  ce.previous_version_id,
  ce.current_version_id,
  ce.detected_at,
  ce.size_difference,
  ce.change_metadata,
  prev.file_size       as previous_size,
  curr.file_size       as current_size,
  prev.sha256_hash     as previous_hash,
  curr.sha256_hash     as current_hash
from change_events ce
join assets a on a.id = ce.asset_id
join projects p on p.id = a.project_id
left join asset_versions prev on prev.id = ce.previous_version_id
join asset_versions curr on curr.id = ce.current_version_id;
