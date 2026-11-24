# rlsentry spec

rlsentry is a research and teaching command-line tool about Supabase tables that an anonymous
visitor, holding only the public anon key, can read or change (the class of flaw behind
CVE-2025-48757). `rlsentry attack` builds a throwaway copy of a database from a project's
migrations, fills it with fake rows, really reads, inserts, updates and deletes as the anonymous
visitor through the same REST layer Supabase uses, and reports per table and per operation what
got through, with evidence. A lab of deliberately vulnerable schemas ships with it.

This file says what is true now. What is about to change is in `docs/tasks/<slug>/brief.md`;
why things are the way they are is in each task's `trail.tsv`.

## Areas

- [Attacking a project's migrations](attacking-migrations.md): pointing rlsentry at a folder of
  migrations, what builds, what stops the run, and the refused live target.
- [Verdicts and the report](verdicts-and-report.md): what `EXPOSED` and `protected` mean for
  each operation, value search, the text and JSON report, exit codes.
- [The throwaway copy and its backends](throwaway-copy.md): where the copy runs (local
  processes or Docker), what it is made of, and how it is always torn down.
- [The lab](lab.md): the bundled vulnerable schemas and the verdict each one shows.
- [Roadmap](roadmap.md): the chain of tasks, in order.

## Terms

- **anon, the anonymous visitor**: the PostgreSQL role `anon`, as a browser holding only the
  Supabase anon key reaches it: through PostgREST, with a JWT whose role claim is `anon` and
  that has no `sub`, so `auth.uid()` is null.
- **the copy**: the throwaway PostgreSQL 16 + PostgREST 12.2.3 that one run builds on
  127.0.0.1 and destroys. Nothing else is ever attacked.
- **backend**: where the copy's two servers run: `local` (processes on this machine) or
  `docker` (two containers). `auto` picks one.
- **table**: an ordinary or partitioned table in the `public` schema of the copy. Views and
  other schemas are not tables in this sense (see What rlsentry does not do).
- **operation**: one of `READ`, `INSERT`, `UPDATE`, `DELETE`, each attacked separately on every
  table.
- **verdict**: `EXPOSED` or `protected`, one per table and operation. There is no third
  verdict: when a run cannot honestly give one of the two, it stops with exit 2.
- **EXPOSED**: a real request as anon read rows, or a row was really written, inserted,
  changed or deleted, as checked afterwards by the copy's superuser.
- **protected**: anon read nothing, or row-level security (or a missing grant) refused the
  write, on PostgreSQL's own account of that request.
- **basis**: the one line explaining a verdict: the HTTP answer and, for `protected`, what
  refused it (the policy names, "no INSERT policy", another table, or the missing grant).
- **evidence**: for an `EXPOSED` verdict, the row read, created, changed (before and after) or
  deleted. Every row is fake, so it is shown.
- **value search**: after a refused insert, trying further rows built from values the table's
  own definitions name, to find one the insert policy accepts.
- **PostgreSQL's own account**: the copy's server log (jsonlog with verbose errors, plus
  auto_explain plans) for the one request asked about, read only by rlsentry's superuser
  connection. It names the C function that raised each error, which migration SQL cannot forge.
- **the role `postgres`**: the copy's non-superuser role that runs migrations and seeding, shaped
  like hosted Supabase's `postgres` role (owns what migrations create, bypasses RLS, not a
  superuser). The copy's superuser is `supabase_admin`.
- **run nonce**: a random value the copy's superuser writes into the copy; the channel checks it
  before the first attacking request, to be sure it is talking to the copy this run built.
- **exit codes**: `0` nothing exposed, `1` something exposed, `2` could not build or attack the
  copy, refused, or interrupted.

## What rlsentry does not do

- It never attacks a live or hosted project, including the owner's. `--target` exists only to be
  refused (see [Attacking a project's migrations](attacking-migrations.md)).
- It does not attack as a logged-in (`authenticated`) user, or one user against another.
- It does not attack views, materialized views, tables outside `public`, storage buckets, RPC or
  database functions, Edge Functions, GraphQL or Realtime.
- It does not fix policies or suggest SQL.
- It has no web UI and no hosted service, and stores no report: the report goes to standard
  output.
- It does not reproduce all of Supabase: only its roles, default grants, a stand-in for the
  parts of `auth` that migrations and policies use, and the `pgcrypto`, `uuid-ossp` and
  `pg_stat_statements` extensions in `extensions`. A migration needing more stops the run.
