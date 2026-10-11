# JSMon Security Dashboard

A web-based JavaScript change monitor for authorized security research.

A refactor of [robre/jsmon](https://github.com/robre/jsmon) from a
single-file CLI into a durable monitoring platform: the Python engine runs on
GitHub Actions, state lives in Supabase, and a private dashboard on Vercel
shows what changed and why it matters.

```
Add a target on the dashboard
        |
        v
[ durable outbox row ]  <-- written in the same transaction as the target
        |
        v
GitHub Actions workflow_dispatch
        |
        v
Python engine: fetch -> sha256 -> compare -> snapshot -> record
        |
        v
Supabase (Postgres + private Storage)
        |
        v
Dashboard refreshes automatically
```

The two halves are deliberately decoupled: a code push deploys the frontend,
a scheduled run writes monitoring data. A scan never triggers a deployment,
and a deployment never runs a scan.

---

## What it does

- **Monitor any authorized JavaScript URL.** First scan creates a baseline;
  later scans report only genuine content changes.
- **Inspect the diff.** Monaco viewer with side-by-side and unified layouts,
  search, collapsed unchanged regions, and a beautified display mode.
- **Security review indicators.** Added lines are scanned for endpoints,
  auth/authorization functions, debug flags, source maps, credential-shaped
  strings (including Shannon-entropy detection), and more. These are review
  prompts, not confirmed vulnerabilities.
- **Discover assets.** Point at an authorized page and it lists the JavaScript
  that page references, split into in-scope and out-of-scope.
- **Get notified.** Telegram or Slack, with hashes, sizes, line counts, and a
  link to the dashboard. Unchanged assets never alert.
- **Scan on demand.** "Run Scan Now" for a target or a whole project.

## Why an outbox

The dashboard must trigger a scan when you save a target, but GitHub's
dispatch API is a network call that can fail. If the dispatch is lost, the
target exists and is never scanned — silently.

So the order is:

1. Insert the target **and** its dispatch job in one transaction.
2. Drain the queue (inline after save, then on a Vercel cron).
3. Record attempts, last error, and exponential backoff per job.

Your save succeeds even if GitHub is rate-limiting, and a failed dispatch is
retried rather than dropped. A partial unique index on live jobs per asset
makes double-clicking "Save & Start Monitoring" safe.

**A dispatch accepted by GitHub means *queued*, never *scanned*.** Scan truth
lives in `scan_runs`; the reconciler polls GitHub and resolves each job to
completed or failed.

---

## Repository layout

```
app/
  (auth)/login/              sign-in (password or magic link)
  (dashboard)/               overview, projects, assets, changes,
                             scans, notifications, actions, settings
  api/                       auth, projects, assets, changes, diff,
                             stats, versions, scans, discover,
                             notifications, scan/trigger, scan/retry,
                             dispatch/drain
components/
  dashboard/                 sidebar, topbar, status pills, empty states
  diff-viewer/               Monaco diff viewer
  ui/                        button, card, badge, input, dialog
lib/
  supabase/                  browser client, server client, types
  github/                    dispatch + run tracking
  monitoring/                outbox dispatcher, diff parsing
  validation/                URL/SSRF schemas (zod)
  api/helpers.ts             auth, validation, safe errors
monitor/
  jsmon/                     the refactored Python engine
  runner.py                  entry point used by GitHub Actions
  requirements.txt           pinned dependencies
supabase/migrations/         0001_init, 0002_retention, 0003_dispatch_outbox
.github/workflows/           jsmon-monitor.yml, ci.yml
tests/                       pytest suite + vitest suite
```

## The Python engine

`monitor/jsmon/` replaces the original `jsmon.py`:

| Module | Responsibility |
| --- | --- |
| `ssrf.py` | URL validation, DNS resolution, IP classification, redirect hops |
| `fetcher.py` | Bounded timeouts, size ceiling, retries, conditional GET |
| `discovery.py` | JavaScript discovery from an authorized page |
| `diffing.py` | Unified diffs, hunks, review indicators |
| `storage.py` | Immutable snapshots in Supabase Storage |
| `database.py` | State via PostgREST or direct Postgres |
| `notifications.py` | Telegram and Slack delivery |
| `runner.py` | The scan loop |

What changed from the original, and why:

| Original | Now | Reason |
| --- | --- | --- |
| `jsmon.json` on disk | Supabase Postgres | state must survive between runners |
| `downloads/` on the runner | private Storage bucket | runner disks are ephemeral |
| no timeouts | connect + read timeouts | a hung host stalled the whole run |
| no size limit | streaming byte ceiling | a huge response OOMs the runner |
| `requests.get(url)` | validated fetch, every redirect re-checked | SSRF |
| exits without a notifier | runs regardless | monitoring must not depend on Telegram |
| md5[:10] | SHA-256 of the raw bytes | collisions and clarity |
| failed download looked unchanged | recorded as an error | never treat failure as "no change" |

## Security posture

- **SSRF protection.** http/https only, no credentials in URLs, and loopback,
  private, link-local and cloud-metadata addresses rejected. Every redirect
  hop is re-validated before it is followed.
- **Row Level Security** on every table. The service-role key is server-side
  only, used for the engine's writes and notification credentials.
- **Immutable snapshots.** Version rows have no update policy, so history
  cannot be rewritten through client APIs.
- **Untrusted content is never executed.** Downloaded JavaScript renders only
  as text inside Monaco — never as HTML, never evaluated.
- **No public registration.** The administrator account is created in
  Supabase; every API route authenticates server-side.

---

## Quick start

See [DEPLOYMENT.md](./DEPLOYMENT.md) for the full walkthrough. The short
version:

```bash
npm install
cp .env.example .env.local      # fill in Supabase + GitHub values

# apply the database schema
supabase db push                # or paste the SQL in the Supabase SQL editor

npm run dev                     # http://localhost:3000
```

Run the Python suite locally:

```bash
py -3.12 -m pip install -r monitor/requirements.txt
PYTHONPATH=monitor pytest
```

Run the web suite:

```bash
npm test
```

## Tests

| Suite | Count | Covers |
| --- | --- | --- |
| `pytest` | 118 | SSRF, fetcher, diffing, discovery, notifications, and the full baseline to unchanged to changed cycle against a local HTTP server |
| `vitest` | 65 | URL validation, diff parsing, and 10 live dispatch tests that drive the real dispatcher against fake GitHub + Supabase |

The Python integration test is the acceptance check: it serves an initial
JavaScript file, then a modified one, and asserts the baseline is created, the
unchanged scan is a no-op, the third scan detects the change, the old snapshot
survives, the diff is correct, and the recorded run reflects all of it.

```bash
npm run build      # production build
npm run typecheck  # tsc --noEmit
npm run lint
```

## License

MIT, continuing the original project's license. The upstream work is
Copyright (c) 2020 robre.
