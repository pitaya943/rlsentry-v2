# Brief: anon-probe — prove what the anon key can actually do

Status: DRAFT, not approved.

First task of the rlsentry chain (see `docs/spec/roadmap.md`).

## Goal

A developer who owns a Supabase project runs one command with the project URL
and the public anon key, and gets a verdict per exposed table: can an anonymous
visitor **read** rows from it, can they **write** to it. The verdict comes from
actually trying, the way an attacker (or the CVE-2025-48757 researchers) would,
not from reading the policy definitions. The command exits non-zero when
anything is exposed, so it can block a deploy.

Why: Supabase's Security Advisor already warns about tables without RLS, and
AI-generated apps still ship with tables readable and writable by anyone. A
warning about configuration is easy to ignore and misses policies that are
switched on but wrong (`using (true)`). Evidence of real access is not.

## Out of scope

- Scanning projects the user does not own; any bulk or list-driven scanning of
  many projects. One project per run.
- Logged-in (`authenticated`) users and cross-user access. Later task.
- Storage buckets, RPC / database functions, Edge Functions, GraphQL. Later tasks.
- Fixing policies or generating SQL fixes. rlsentry reports; it does not change
  the project.
- Running against a local Supabase from migrations in CI. Later task.
- Any web UI or hosted service.

## Scenarios

- **S-1 Readable table is caught.** Given a project with a table that has RLS
  off (or a policy letting anyone select), when the user runs the scan with the
  anon key, then the report marks that table `READ: EXPOSED`, says how many rows
  an anonymous visitor can see, and the command exits non-zero.
- **S-2 Protected table is not a false alarm.** Given a table with RLS on and no
  policy granting anon access, when the user runs the scan, then the report marks
  it `READ: protected` and `WRITE: protected`.
- **S-3 "RLS on but wrong" is caught.** Given a table with RLS enabled and a
  policy `using (true)` for anon, when the user runs the scan, then it is marked
  `READ: EXPOSED` — the case a configuration warning about "RLS disabled" misses.
- **S-4 Writable table is caught without leaving data behind.** Given a table an
  anonymous visitor can insert into, when the user runs the scan, then the report
  marks it `WRITE: EXPOSED`, and afterwards the table holds exactly the rows it
  held before the scan.
- **S-5 Unsure is said, not guessed.** Given a table where the scan cannot tell
  whether anon can write without actually keeping a row, when the user runs the
  scan, then it is marked `WRITE: unknown` with the reason, never `protected`.
- **S-6 Exposed data is not echoed.** Given a readable table holding rows, when
  the scan reports it, then the output names the table, its column names and a
  row count, and contains none of the row values.
- **S-7 Clean project passes.** Given a project where every exposed table is
  protected, when the user runs the scan, then every table is listed as
  protected and the command exits zero.
- **S-8 Machine-readable report.** Given any scan, when the user asks for JSON
  output, then they get one record per table with its read and write verdicts,
  usable by a CI step.
- **S-9 Wrong key is not a clean bill of health.** Given a URL or key that the
  project rejects, when the user runs the scan, then it says so and exits with a
  code distinct from both "clean" and "exposed".

## How to try it

1. Start a local Supabase (or use a throwaway project), create three tables:
   one with RLS off, one with RLS on and `using (true)`, one with RLS on and no
   policies. Insert a few rows in each.
2. Run `rlsentry scan --url <project url> --anon-key <anon key>`.
3. See the first two marked EXPOSED with row counts and no row values, the third
   protected, exit code non-zero. Count rows in each table: unchanged.
4. Drop the two bad tables, rerun: exit code zero.

## Critical areas

- **The write probe.** It runs against the user's real, possibly production,
  database. A mistake here writes or corrupts their data. Any change to how
  writes are probed is high risk.
- **The report output.** It must never carry row values from the user's tables
  (they may be other people's personal data, and reports end up in CI logs).

## Assumptions

- Tables are discovered from what the project's REST API publishes to the anon
  key; when it publishes nothing, the user can name tables by hand. Only the
  `public` schema (and others the API exposes) — not the whole database.
- No service-role key or database password is asked for or accepted in this
  task: the scan sees exactly what an outsider sees.
- Write probing is on by default and must never persist a row; where that
  cannot be guaranteed for a table, the verdict is `unknown` (S-5). Update and
  delete are reported only as far as they can be tested without changing rows.
- Row counts may be capped (e.g. "1000+") to keep the scan cheap.
- A project with up to a few hundred exposed tables finishes in about a minute;
  requests are sequential-ish and rate-limited so the scan is not a load test.
- Python command-line tool, installable with pip.
- Nothing is stored between runs; the report is printed (and optionally written
  to a file the user names).
