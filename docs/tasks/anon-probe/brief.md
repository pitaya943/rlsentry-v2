# Brief: anon-probe — attack a disposable copy as the anon visitor

Status: DRAFT, not approved.

First task of the rlsentry chain (see `docs/spec/roadmap.md`). The slug is kept
from the first draft; this task is the `attack` mode.

## Goal

rlsentry is a research and teaching tool about the class of flaw behind
CVE-2025-48757: Supabase tables that an anonymous visitor, holding only the
public anon key, can read or change.

After this task, a person points rlsentry at a Supabase project's migrations.
rlsentry builds a throwaway copy of that database, fills it with fake rows, and
attacks it exactly as an anonymous visitor would — really reading, inserting,
updating and deleting — then reports, per table and per operation, what
succeeded, with the evidence. The copy is thrown away afterwards.

The repository also ships a small lab of deliberately vulnerable demo schemas,
so anyone can run rlsentry and see each kind of verdict without a project of
their own.

Why this and not a warning: Supabase's Security Advisor already warns about
configuration, and the flaw keeps shipping. A warning about a setting is easy to
ignore and misses policies that are on but wrong (`using (true)`, checks that
accept attacker-chosen values). A demonstrated read or write is not. Unlike
scanners that probe a live project, attacking a disposable copy lets rlsentry
behave exactly like an attacker, writes included, with nothing real at risk.

## Out of scope

- Attacking any live or hosted project, including the owner's. The command
  refuses such targets (S-7). Non-destructive probing of live projects is a
  later task (`live-probe`).
- Generating the Lovable-built target app. The owner does that by hand; turning
  it into a lab target is the next task (`lovable-target`).
- Logged-in (`authenticated`) users and cross-user access. Later task.
- Storage buckets, RPC / database functions, Edge Functions, GraphQL, Realtime.
- Fixing policies or generating SQL fixes.
- Any web UI or hosted service.

## Scenarios

- **S-1 Readable table is caught.** Given migrations that create a table with
  RLS off, when the user runs the attack, then the report marks that table
  `READ: EXPOSED`, shows how many of the fake rows the anonymous visitor read
  and one of them as evidence, and the command exits non-zero.
- **S-2 Protected table is not a false alarm.** Given a table with RLS on and no
  policy for the anonymous visitor, when the user runs the attack, then every
  operation on it is marked `protected`.
- **S-3 "RLS on but wrong" is caught.** Given a table with RLS on and a policy
  `using (true)` for anon, when the user runs the attack, then it is marked
  `READ: EXPOSED`.
- **S-4 Each write operation is tried for real.** Given a table the anonymous
  visitor may insert into but not update or delete, when the user runs the
  attack, then the report marks `INSERT: EXPOSED` with the row it created as
  evidence, and `UPDATE: protected`, `DELETE: protected`. The same holds for
  every combination of the three in the lab.
- **S-5 Policies that accept chosen values are caught.** Given a table whose
  insert policy only accepts rows with a particular value (for example
  `status = 'pending'`), when the user runs the attack, then rlsentry finds an
  accepted row and marks `INSERT: EXPOSED`. When nothing it tries is accepted,
  the report says how many rows it tried, not just `protected`.
- **S-6 Migrations of a real project are accepted.** Given a folder of Supabase
  migrations that use the usual Supabase pieces (the `anon` and
  `authenticated` roles, `auth.uid()`, `auth.users` references), when the user
  runs the attack on it, then the copy builds and the attack runs. A migration
  that uses a piece rlsentry does not provide is reported by name, and the run
  stops with a distinct exit code instead of attacking a partial copy.
- **S-7 Never attacks a live project.** Given a target that is not a copy
  rlsentry built itself (for example a hosted project URL), when the user runs
  the attack, then it refuses before sending any request to it.
- **S-8 Nothing is left behind.** Given any run, including one that fails
  halfway or is interrupted, when it ends, then the throwaway copy and anything
  it started are gone.
- **S-9 The lab shows every verdict.** Given the lab shipped in the repository,
  when the user runs the attack on it, then the report contains at least one
  table for each of: read exposed, insert exposed, update exposed, delete
  exposed, value-policy insert exposed, and fully protected.
- **S-10 Machine-readable report and exit codes.** Given any run, when the user
  asks for JSON, then they get one record per table with a verdict and evidence
  per operation. Exit code: `0` nothing exposed, `1` something exposed, `2`
  could not build or attack the copy.

## How to try it

1. `rlsentry attack --lab` → the report from S-9, exit code 1.
2. Point it at a folder with one clean migration
   (`rlsentry attack --migrations ./clean`) → everything protected, exit 0.
3. Run `rlsentry attack --target https://<something>.supabase.co` → refused,
   nothing sent (S-7).
4. Interrupt a run with Ctrl-C; check that no database or process from it is
   still running (S-8).

## Critical areas

- **The live-target guard (S-7).** It is what keeps an attacking tool from
  writing to a real database. Any change to how a target is accepted is high risk.
- **Teardown (S-8).** A leftover copy or process on the user's machine.

## Assumptions

- The throwaway copy is plain PostgreSQL plus the same REST layer Supabase uses,
  with Supabase's roles and a small stand-in for `auth` (enough for `auth.uid()`
  and `auth.users`), not the full Supabase stack. Migrations needing more
  (storage, extensions beyond common ones) stop the run (S-6).
- Fake rows are generated by rlsentry from each column's type, a few per table;
  migrations' own seed data is used too when present.
- Because every row is fake, the report shows evidence values (one row per
  finding). Nothing is stored between runs except a report file the user names.
- Value-policy attacks (S-5) try values from column types, check constraints,
  enum values and values visible in readable rows; a bounded number of tries per
  table (default 50).
- Requires Docker or a local PostgreSQL + REST layer install; rlsentry says
  which is missing. A run on the lab finishes in under a minute.
- Python command-line tool, installable with pip.
- One run at a time per machine is enough; two at once get separate copies.
