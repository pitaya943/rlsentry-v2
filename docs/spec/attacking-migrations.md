# Attacking a project's migrations

A person points rlsentry at a folder of Supabase migrations; rlsentry builds the copy from them,
seeds it and attacks every table as anon, or stops and says why it cannot.

## Scenarios

### Attack a Supabase-style app's migrations

Given a folder of migrations that use the usual Supabase pieces (the `anon` and `authenticated`
roles, `auth.uid()`, `auth.role()`, `auth.jwt()`, keys referencing `auth.users`, a trigger on
`auth.users`, enum columns, CHECK constraints, foreign keys between tables, `pgcrypto` or
`uuid-ossp` functions with or without the `extensions.` prefix),
when the user runs `rlsentry attack --migrations <dir>`,
then the copy builds, every table in `public` is seeded with 5 fake rows, every table is
attacked, and the report comes out with exit 0 or 1.

### A migration needs something the copy does not have

Given a migration that uses a piece rlsentry does not provide (for example `storage.buckets`),
when the user runs the attack,
then nothing is attacked, no report is printed, the message names the migration file, the line
and the missing object (`migration 002_broken.sql failed at line 2: relation "storage.buckets"
does not exist`), the copy is torn down, and the command exits 2.

### A table cannot be filled with fake rows

Given a table that ends up with no rows after seeding (a NOT NULL column of a type the generator
cannot fill, such as `point` or a domain type; an empty enum; a CHECK no generated value meets;
a foreign key to such a table),
when the user runs the attack,
then the run stops with exit 2 and no report, naming each such table and why
(`could not seed public.spots: no fake value for column(s) here (point)`). An empty table is
never reported `protected`.

### A table can be filled only in part

Given a table where some but not all of the 5 fake rows can be inserted, or where migrations put
rows of their own,
when the user runs the attack,
then the table is attacked, and its report carries a note such as
`seeded 2 of 5 rows; skipped: ...`.

### A migration tries to reach the machine running rlsentry

Given a migration that tries to run a program or touch a file on the host (`copy ... to
program`, `copy ... to '<file>'`, `copy ... from` a file or program, `lo_export`,
`pg_read_file`, granting itself `pg_execute_server_program`, `alter role postgres superuser`,
an untrusted extension such as `adminpack` or `file_fdw`), or a psql meta-command such as `\!`,
when the user runs the attack,
then that statement fails, the run exits 2 naming the file and line, and nothing on the host is
created, read or run. The same holds for migration code that runs later: triggers fired while
seeding or restoring, and the functions rlsentry's own checks call.

### Point it at a live project

Given a target that is not a copy rlsentry built itself, such as
`rlsentry attack --target https://x.supabase.co`,
when the user runs it,
then it refuses with `refusing --target ...: attack mode only attacks a copy it builds itself
from migrations ... Nothing was sent.`, opens no network connection, starts nothing, and exits 2.

### Point it at a folder with no migrations

Given a folder with no `.sql` file (or a path that is not a folder),
when the user runs the attack,
then it exits 2 saying so.

## Rules

- Migrations are the folder's `*.sql` files in filename order. Each file runs in one
  transaction on a connection of its own, as the Supabase CLI applies them; so a new enum value
  is not usable in the file that adds it (anon-probe, T-03).
- rlsentry splits each file into statements itself, as psql and the Supabase CLI split them
  (quotes, `E''` strings, dollar quotes, nested comments, `BEGIN ATOMIC` bodies), and sends each
  to the server as it is. Nothing in a file is run by a client: a psql meta-command is a syntax
  error (anon-probe, T-03).
- A failure names the file and the line: the line of the error's position when PostgreSQL gives
  one, else the failing statement's first line; plus PostgreSQL's message and hint
  (anon-probe, T-03).
- A migration with its own `begin; ... commit;` commits early: statements before its `commit`
  stay applied if a later statement in the file fails. The run still exits 2 (anon-probe, T-03;
  left as it is).
- Migrations, seeding and restoring run as the non-superuser role `postgres`, which owns what
  they create, may create roles, bypasses RLS, and has only what hosted Supabase's `postgres`
  role has. Trusted extensions (for example `citext`, `hstore`) may be created; `pgcrypto`,
  `uuid-ossp` and `pg_stat_statements` are already installed in `extensions` (anon-probe, T-04).
- The search path is `"$user", public, extensions`, for migrations and seeding and for
  PostgREST's requests alike (anon-probe, T-03).
- Every statement on the `postgres` connection that rlsentry itself sends has a 30 s statement
  timeout, so a migration function that never returns stops the run instead of hanging it.
  Migrations themselves have no timeout (anon-probe, T-04).
- Seeding: 5 rows per table, in foreign-key order, including the tables in other schemas that
  `public` tables reference (such as `auth.users`). Values come from the column type, enum
  labels, CHECK constants (strings; numbers n, n+1, n-1; at most 50 tries per row) and the
  referenced table's keys. Columns with a default, identity or generated columns are left to
  the database. A foreign-key cycle is broken by leaving a nullable key null. A nullable column
  of an unsupported type is left null (anon-probe, T-01, T-03).
- Rows that migrations or their triggers put in a table are kept, and fake rows are still
  added. A table counts as seeded if it has any row (anon-probe, T-03).
- `--target` is parsed and refused before anything else is imported or started; no option
  turns a URL into something rlsentry attacks (anon-probe, T-01).
- The auth stand-in: schema `auth` with `auth.users` (a subset of Supabase's columns, those its
  starter triggers read; no token or secret columns) and `auth.uid()`, `auth.role()`,
  `auth.jwt()` reading `request.jwt.claims`, as Supabase defines them (anon-probe, T-03).

## Last changed by

anon-probe (T-01, T-03, T-04).
