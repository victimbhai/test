# Deployment guide

Everything needed to go from an empty repository to a working private
dashboard, in order. Budget about 30 minutes.

You will end up with:

- a GitHub repository hosting the code and the monitoring workflow
- a Supabase project holding targets, snapshots metadata, and change history
- a private Supabase Storage bucket holding the actual JavaScript snapshots
- a Vercel deployment serving the dashboard and its API routes

---

## 1. Create the GitHub repository

```bash
git remote add origin git@github.com:<you>/<repo>.git
git push -u origin main
```

Then confirm the workflow file is present on the default branch — GitHub only
dispatches workflows that exist on the ref you target:

```bash
git ls-tree --name-only origin/main .github/workflows/
# .github/workflows/jsmon-monitor.yml
# .github/workflows/ci.yml
```

## 2. Create the Supabase project

1. Sign in at [supabase.com](https://supabase.com) and create a project.
2. Note the **Project URL** and both keys from
   Project Settings → API:
   - `anon` / `publishable` key → browser
   - `service_role` / `secret` key → server only

## 3. Apply the database migrations

Three files, applied **in this order**. Supabase dashboard → SQL Editor →
paste each file and run it.

| File | What it does |
| --- | --- |
| `supabase/migrations/0001_init.sql` | Tables, indexes, enums, RLS policies, the `dashboard_stats()` function, safe views, realtime publication |
| `supabase/migrations/0002_retention.sql` | Version pruning, orphan cleanup, pointer healing, the `recent_changes` view |
| `supabase/migrations/0003_dispatch_outbox.sql` | The `dispatch_jobs` queue and its enqueue/claim/retry functions |

Or with the CLI:

```bash
supabase link --project-ref <your-ref>
supabase db push
```

Verify the tables exist:

```sql
select table_name from information_schema.tables
where table_schema = 'public' order by table_name;
```

You should see `assets`, `asset_versions`, `audit_logs`, `change_events`,
`dispatch_jobs`, `monitoring_settings`, `notification_events`,
`notification_settings`, `projects`, `scan_runs`.

## 4. Configure private storage

1. Supabase dashboard → **Storage** → **New bucket**.
2. Name: `js-snapshots` (must match `JSMON_STORAGE_BUCKET`).
3. **Public bucket: OFF.** Snapshots are private and reached only through
   short-lived signed URLs issued by authenticated API routes.

No storage policies are needed: the service-role key used by the engine
bypasses RLS, and the dashboard never reads Storage directly.

## 5. Configure authentication

This dashboard is private. There is no public registration.

1. Supabase → **Authentication** → **Providers** → enable **Email**.
2. For a personal dashboard, disable "Allow new users to sign up" under
   Authentication → Sign In / Providers → Email, so only accounts you create
   in the dashboard can exist.
3. Create your administrator account:
   Authentication → Users → **Add user** → set email and password, and tick
   "Auto Confirm User".
4. Under Authentication → URL Configuration, set the Site URL to your Vercel
   domain and add `<your-domain>/auth/callback` as a redirect URL.

## 6. Configure GitHub secrets

Repository → Settings → Secrets and variables → **Actions** → New repository
secret.

| Secret | Value | Required |
| --- | --- | --- |
| `NEXT_PUBLIC_SUPABASE_URL` | `https://<ref>.supabase.co` | yes |
| `SUPABASE_SECRET_KEY` | service-role key | yes* |
| `SUPABASE_DB_URL` | Postgres connection string | yes* |
| `JSMON_NOTIFY_TELEGRAM` | `true` / `false` | optional |
| `JSMON_TELEGRAM_TOKEN` | bot token | optional |
| `JSMON_TELEGRAM_CHAT_ID` | chat id | optional |
| `JSMON_NOTIFY_SLACK` | `true` / `false` | optional |
| `JSMON_SLACK_TOKEN` | bot token | optional |
| `JSMON_SLACK_CHANNEL_ID` | channel id | optional |
| `NEXT_PUBLIC_APP_URL` | your Vercel URL | recommended |
| `JSMON_MAX_BYTES` | `20971520` | optional |
| `JSMON_MAX_VERSIONS_PER_ASSET` | `50` | optional |
| `JSMON_HOST_ALLOWLIST` | extra egress allowlist | optional |

\* At least one of `SUPABASE_SECRET_KEY` or `SUPABASE_DB_URL` must be set. The
workflow validates this before it starts and exits with a clear error.

### Token permissions

For `GITHUB_ACCESS_TOKEN` (a Vercel environment variable, **not** a GitHub
secret), create a fine-grained personal access token at
[github.com/settings/personal-access-tokens](https://github.com/settings/personal-access-tokens):

- **Resource owner:** your account
- **Repository access:** only this repository
- **Permissions → Repository permissions:**
  - **Actions: Read and write** — *write* is required to dispatch a workflow;
    read is required to poll run status. Without write the dispatch is
    refused and targets stay Pending.
  - **Contents: Read** — required so the token can resolve the repository.
  - **Metadata: Read** — required by the API for every request.

A GitHub App installation token works too and is preferable for longer-lived
automation, since PATs expire.

## 7. Enable scheduled GitHub Actions

The workflow is scheduled at `7,22,37,52 * * * *` — every 15 minutes,
staggered off the busiest minute of the hour.

For a repository where scheduled workflows have never run, GitHub requires one
manual enablement:

1. Repository → **Actions** → select **JSMon Monitor**.
2. If you see "Workflows aren't being run on this repository", click
   **I understand my workflows, go ahead and enable them**.
3. Use **Run workflow** once to confirm the engine runs end to end.

Notes on GitHub's scheduler:

- Scheduled runs are **queued, not guaranteed on time**. During heavy load
  they can be delayed by minutes or dropped. Treat 15 minutes as a lower
  bound on the interval, which is why the dashboard shows the configured
  interval and the last actual run separately.
- The workflow uses a `concurrency` group so two scans can never overlap and
  corrupt snapshot history.
- Permissions are least-privilege: `contents: read` only.

## 8. Connect the repository to Vercel

1. [vercel.com/new](https://vercel.com/new) → **Import Git Repository**.
2. **Root Directory:** leave as the repository root (the Next.js app is at the
   top level, not in a subdirectory).
3. **Framework Preset:** Next.js (detected automatically).
4. Production branch: `main`.

## 9. Configure Vercel environment variables

Project → Settings → Environment Variables. Apply to **Production** (and
**Preview** if you want staging to work).

### Browser-visible (safe to expose)

| Name | Value |
| --- | --- |
| `NEXT_PUBLIC_SUPABASE_URL` | `https://<ref>.supabase.co` |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | publishable/anon key |
| `NEXT_PUBLIC_APP_URL` | `https://<your-project>.vercel.app` |
| `NEXT_PUBLIC_GITHUB_OWNER` | your GitHub username |
| `NEXT_PUBLIC_GITHUB_REPO` | your repository name |

### Server-only (never sent to the browser)

| Name | Value |
| --- | --- |
| `SUPABASE_SECRET_KEY` | service-role key |
| `GITHUB_OWNER` | your GitHub username |
| `GITHUB_REPO` | your repository name |
| `GITHUB_WORKFLOW_ID` | `jsmon-monitor.yml` |
| `GITHUB_WORKFLOW_REF` | `main` |
| `GITHUB_ACCESS_TOKEN` | fine-grained PAT with Actions read/write |
| `CRON_SECRET` | a long random string — **required** |

`CRON_SECRET` is required for the automatic trigger to work. The Vercel Cron
jobs that deliver queued scans authenticate with it, and the drain route
accepts *only* that bearer token — a browser session is deliberately not
enough. If you skip it, targets you add from the website will stay **Pending**
until a scheduled GitHub Actions run picks them up.

Generate one:

```bash
openssl rand -hex 32
```

The split matters: `NEXT_PUBLIC_*` values are inlined into the JavaScript
bundle, so anything sensitive must never carry that prefix.

## 10. Deploy

```bash
git push origin main
```

Vercel builds automatically. The dashboard appears on
`https://<your-project>.vercel.app`.

Every later push to `main` redeploys the app. Scheduled monitoring runs write
to Supabase instead, so **a scan never creates a deployment**.

## 11. Configure a custom domain (optional)

1. Project → Settings → **Domains** → add your domain.
2. Add the DNS records Vercel shows (an `A` record to `76.76.21.21`, or a
   `CNAME` to `cname.vercel-dns.com` for subdomains).
3. Wait for the certificate to issue.
4. Update `NEXT_PUBLIC_APP_URL` to the custom domain and **redeploy**, so
   notification links point at the right host.
5. Add the custom domain to Supabase → Authentication → URL Configuration.

## 12. Verify the crons

`vercel.json` registers two Vercel Cron jobs:

| Path | Schedule | Purpose |
| --- | --- | --- |
| `/api/dispatch/drain` | every 5 minutes | deliver queued scans to GitHub |
| `/api/dispatch/drain?mode=reconcile` | every 2 minutes | poll GitHub and update job status |

Vercel sends `CRON_SECRET` as a bearer token, which the route checks. Set the
same value in Vercel environment variables — if you leave it unset the crons
cannot authenticate and queued scans are never delivered.

Cron jobs only run on Vercel's **paid** plans. On the Hobby plan they are
disabled, so trigger the drain manually after adding a target:

```bash
curl -X POST https://<your-project>.vercel.app/api/dispatch/drain \
  -H "Authorization: Bearer <CRON_SECRET>"
```

The scan still completes without them: the scheduled GitHub Actions workflow
picks up any target that is still pending, and **Run Scan Now** drains
immediately. The crons only remove the wait.

Confirm they are registered: Project → Settings → **Cron Jobs**.

---

## Test the first successful monitoring cycle

1. Open your Vercel URL and sign in.
2. **Projects → Add Project.** Name it, set the primary domain, and list the
   authorized hostnames you may test.
3. **Add Target →** paste a JavaScript URL on an allowed host →
   **Save & Start Monitoring**.

   You should see the target appear with a **Queued** status pill.
4. **GitHub Actions** page: the dispatch job shows the run link. Open it and
   watch the engine log.
5. Within a minute the status moves **Running → Completed**, and the target
   gains a hash, a size, and a **Baseline** badge.
6. Edit nothing — scan again with **Run Scan Now**. Status stays Completed and
   **no** change event appears (identical content is not a change).
7. Point a second target at a file you control, change its contents, and scan
   again. A change event appears with the size delta and indicator count.
8. **Detected Changes →** open it. The Monaco viewer shows the added and
   removed lines, and any review indicators with jump-to-line.

That completes the loop: target added from the website, scan triggered
automatically, engine ran on GitHub Actions, results stored in Supabase, and
the dashboard updated without a page reload.

---

## Troubleshooting

**Target stays "Pending".** GitHub is not configured or the dispatch was
refused. The GitHub Actions page shows the stored error. Check
`GITHUB_ACCESS_TOKEN` has Actions **write** on this repository, and that
`jsmon-monitor.yml` exists on the `GITHUB_WORKFLOW_REF` branch.

**Dispatch returns 404.** The workflow file is not on the configured ref.
`git ls-tree origin/main .github/workflows/` to confirm.

**"Scope validation failed" in the scan log.** The URL's host is not in the
project's `allowed_hosts`. Add it on the project, or widen the allowlist.

**"Could not resolve host".** The runner could not resolve DNS. Check the URL,
and confirm the host is public.

**Changes never appear.** Confirm the engine actually completed
(GitHub Actions page → Completed), then check that `dispatch/drain` and the
reconcile cron are registered in Vercel.

**Diff viewer is blank.** The snapshot may have been pruned by retention.
Raise `JSMON_MAX_VERSIONS_PER_ASSET`.

**Notifications do not arrive.** Use **Test** on the Notifications page — it
reports the provider's own error message. For Slack, the bot must be invited
to the channel and have `chat:write`.

**Scheduled runs never fire.** Scheduled workflows need one manual enablement
in the repository's Actions tab (step 7).
