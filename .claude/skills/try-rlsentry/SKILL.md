---
name: try-rlsentry
description: Use to run rlsentry the way a user does (attack the lab, a migrations folder, a refused live target, an interrupted run) and keep a transcript as evidence.
---

# Try rlsentry

**Surface**: a command-line tool, `rlsentry attack`. No server of its own: each run builds a
throwaway PostgreSQL + PostgREST on random 127.0.0.1 ports, attacks it as anon, removes it.

**Run**
- Install once from the repository root: `pip install -e '.[test]'`.
- Needs PostgreSQL (`initdb`, `postgres` on PATH or under `/usr/lib/postgresql/<v>/bin`) and
  `postgrest` on PATH. As root it runs PostgreSQL as the `postgres` OS user, data under `/tmp`.
  Inside the copy, migrations run as the database role `postgres` (not a superuser, as on
  hosted Supabase); the superuser is `supabase_admin`.
- Run markers live in `~/.local/state/rlsentry` (override with `RLSENTRY_STATE_DIR`).

**Drive**: `bash .claude/skills/try-rlsentry/try.sh docs/tasks/<slug>/evidence/<name>` does,
in order, and fails on the first step that does not give the expected exit code:

| User action | Command | Expected |
|---|---|---|
| attack the lab | `rlsentry attack --lab` (and `--json`) | exit 1, `9 exposed operation(s) in 8 table(s).`: each verdict kind, value search on `lab_value_policy` |
| attack a clean migrations folder | `rlsentry attack --migrations <dir>` | exit 0 |
| attack a Supabase-style app | `rlsentry attack --migrations tests/fixtures/supabase_app` | exit 1, every table "seeded 5 rows" |
| a migration needing `storage` | `rlsentry attack --migrations tests/fixtures/broken` | exit 2 naming the file, line and `storage.buckets` |
| a table the generator cannot fill | `rlsentry attack --migrations tests/fixtures/unseedable_point` | exit 2 naming the table and column, no report |
| a migration that runs a host program | `copy ... to program 'touch <file>'` in a migration | exit 2 naming the file and line; the file is not created |
| point it at a live project | `rlsentry attack --target https://x.supabase.co` | exit 2, refused, nothing sent |
| press Ctrl-C mid-run | SIGINT while the attack waits on a slow policy | exit 2, no process or run dir left |

Single actions by hand: the commands above; exit codes are 0 nothing exposed, 1 exposed,
2 could not build/attack (or refused, or interrupted).

**Observe**: the script writes `transcript.txt` (each command, its output and exit code) and
`report.json` into the evidence directory, plus a residue check (rlsentry run dirs and
PostgreSQL/PostgREST processes before and after).

**Known limits**: "nothing was sent" for `--target` is shown here only by the refusal message
and timing; the socket-level proof is `tests/test_guard.py`. The docker backend is not driven
by this skill.
