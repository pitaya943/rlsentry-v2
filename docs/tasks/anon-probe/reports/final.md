# anon-probe: final report

By my own check, every scenario of the brief (S-1 to S-10) is met on the local backend at
`73ba666`; the Docker backend is proven only against a stand-in daemon (`tests/fakedocker.py`),
because the real images never ran here; the open findings listed under Not done are left for
you to decide.

[PR into main: #10](https://github.com/pitaya943/rlsentry-v2/pull/10) · [tracking issue #2](https://github.com/pitaya943/rlsentry-v2/issues/2) ·
brief: [brief.md](../brief.md) · design: [design.md](../design.md) · plan: [plan.md](../plan.md) ·
trail: [trail.tsv](../trail.tsv) · spec: [docs/spec/index.md](../../../spec/index.md)

Trail rows below link to `trail.tsv` at `73ba666` (row N is line N of the file).

## 1. What was done

`rlsentry attack --migrations <dir>` (or `--lab`) builds a throwaway PostgreSQL 16 + PostgREST
12.2.3 on 127.0.0.1 from a project's Supabase migrations, seeds 5 fake rows per table, and
really reads, inserts, updates and deletes every `public` table as the anon role through
PostgREST. Each table and operation gets `EXPOSED` (confirmed by the copy's superuser seeing
the rows read or changed, with the row as evidence) or `protected` (only when PostgreSQL's own
server log for that very request shows row-level security or a missing grant refused it);
anything else stops the run with exit 2 rather than guess. Migrations run as a non-superuser
`postgres` role like hosted Supabase's, so migration SQL cannot reach the host. `--target <url>`
is refused before anything is sent, and the copy is torn down on success, failure, Ctrl-C and,
by the next run's sweep, `kill -9`. The copy runs as local processes or as Docker containers
(`--backend auto|docker|local`), and an 8-table lab shows every verdict kind.

## 2. How to try it

Everything here was run by me for this report at `73ba666` on Linux as root, local backend,
unless marked `not run`. Transcripts: [evidence/final-try/transcript.txt](../evidence/final-try/transcript.txt)
(the project's `try-rlsentry` script), [evidence/final-try/extra.txt](../evidence/final-try/extra.txt)
(cases the tests do not cover), [evidence/final-try/suite.txt](../evidence/final-try/suite.txt).

1. **Get the code** (`not run` as written; I used a worktree of the same commit):
   `git clone https://github.com/pitaya943/rlsentry-v2 && cd rlsentry-v2 && git checkout task/anon-probe`
2. **Have the servers.** Python 3.10+, and either PostgreSQL 16 (`initdb`, `postgres` on `PATH`
   or under `/usr/lib/postgresql/16/bin`) plus PostgREST 12.2.3 (`postgrest` on `PATH`), or a
   local Docker daemon. Installing these was `not run`: they were preinstalled here (PostgREST
   by the cloud environment's setup script, pinned by sha256). As root, PostgreSQL runs as the
   OS user `postgres`, which must exist.
3. **Install:** `python3 -m venv .venv && .venv/bin/pip install -e .` then put `.venv/bin` on
   `PATH`. `rlsentry --help` shows the `attack` command.
4. **Attack the lab:** `rlsentry attack --lab`. With no Docker daemon, standard error first says
   `docker unavailable (...); using the local backend`. Then 8 tables, each with READ, INSERT,
   UPDATE, DELETE lines; e.g. `lab_value_policy` shows `INSERT: EXPOSED - anon inserted a row
   (HTTP 201), row 2 of the value search, with status = "pending" from the insert policy's
   constants`. Last line `9 exposed operation(s) in 8 table(s).`, exit 1, about 2.3 s.
5. **JSON:** `rlsentry attack --lab --json > report.json`: one record per table; its outcomes equal
   `rlsentry/lab/expected.json` exactly (checked).
6. **A clean project:** a folder with one file
   `create table profiles (id bigint generated always as identity primary key, email text not null); alter table profiles enable row level security;`
   → all four `protected`, each naming why (`anon has no INSERT policy on profiles`), exit 0.
7. **A Supabase-style app:** `rlsentry attack --migrations tests/fixtures/supabase_app` →
   7 tables seeded with 5 rows each, `3 exposed operation(s) in 7 table(s).`, exit 1.
8. **Something the copy lacks:** `rlsentry attack --migrations tests/fixtures/broken` →
   `migration 002_broken.sql failed at line 2: relation "storage.buckets" does not exist`, exit 2,
   no report.
9. **A live project:** `rlsentry attack --target https://x.supabase.co` → `refusing --target ...
   Nothing was sent.`, exit 2.
10. **A migration that attacks the host:** a migration with `copy (select 1) to program 'touch
    /some/dir/pwned';` → exit 2, `permission denied to COPY to or from an external program`, and
    the file is not created.
11. **Ctrl-C:** start a run on a table whose read policy sleeps (`using ((select true from
    pg_sleep(30)))`) and press Ctrl-C → `interrupted (SIGINT); the copy was torn down`, exit 2,
    no PostgreSQL/PostgREST process or `/tmp/rlsentry-run-*` left.
12. **Docker:** `rlsentry attack --backend docker --lab` here → exit 2, `no Docker daemon
    answers`. On a machine with a daemon: `not run` (see Not done).

Worth trying, not covered by the tests (all in `extra.txt`):
- **A view over a protected table** (`create view secrets_v as select * from secrets;`): the
  report lists only `secrets` (all protected, exit 0). The view is not attacked, although a view
  runs as its owner and is the classic anon leak.
- **A policy that trusts a header anon can send** (`with check (current_setting('request.headers',
  true)::json ->> 'x-secret' = 'open-sesame')`): `INSERT: protected (7 rows tried)`, exit 0,
  although anon could insert by sending that header.
- **A NOT NULL column of a domain type** (`create domain email as text check (value like
  '%@%')`): exit 2, `no fake value for column(s) e (email)`.

## 3. Decisions I made

Made without asking, from the trail (the full list is the trail itself):

- **The order of the tickets:** T-05 (Docker) moved after T-02 and T-03, because extracting the
  backend interface rewrites `sandbox.py`, which both change ([row 50](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L50)).
- **Verifier findings folded forward instead of reopening merged tickets:** T-01's unseeded-table
  and quoting findings into T-03 ([row 32](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L32)),
  T-02's F1-F4 into T-04 ([row 65](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L65)),
  T-03's "migrations run as superuser" into T-04, raising T-04 to high risk ([row 90](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L90)).
- **Only dependency:** `psycopg[binary]`; HTTP and the HS256 JWT use the standard library ([row 33](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L33)).
- **An interrupted run exits 2, not 130** ([row 34](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L34)).
- **The channel takes a port, never a URL, and ignores proxy settings**; the nonce check also
  requires both servers to be the ones started ([rows 36-37](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L36)).
- **UPDATE/DELETE go by primary key, then without a filter**, verdict from the superuser's
  before/after; that is the only way a write-only policy is reached ([row 52](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L52)).
- **Restore = one snapshot after seeding, every table rewritten after each write attempt**;
  sequences not restored ([rows 54-55](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L54)).
- **Migrations are split by rlsentry and sent through psycopg, not psql**, so `\!` cannot run on
  the host ([row 82](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L82)).
- **Any unexpected exception exits 2 with one line, no traceback** ([row 85](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L85)).
- **Cluster superuser renamed `supabase_admin`; migrations, seeding and restore run as a
  non-superuser `postgres`**; untrusted extensions stop the run ([rows 95-97](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L95)).
- **Value search runs after any refused first insert, also on tables with no insert policy**,
  and counts the first row toward the 50 ([row 102](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L102));
  candidate order in [row 103](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L103).
- **`lab_value_policy.status` defaults to `'draft'`**, so the row a form sends is refused ([row 107](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L107)).
- **30 s statement timeout on the `postgres` connection only**; migrations have none ([row 126](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L126)).
- **Docker:** PostgREST shares the db container's network namespace ([row 130](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L130));
  a daemon not on this machine is refused ([row 131](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L131));
  `--backend` defaults to `auto`, announced on stderr ([row 135](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L135));
  data directory is a tmpfs, no `size=` ([rows 144](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L144), [154](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L154));
  teardown waits 10 s for a cut-off `docker run` ([rows 145](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L145), [153](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L153)).
- **The RLS oracle:** a `protected` write needs PostgreSQL's own jsonlog + auto_explain account of
  the request, matched by an `X-Rlsentry-Request` header; rlsentry's own policy evaluation can
  only take `protected` away ([rows 170-175](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L170));
  a policy false only inside PostgREST's request therefore exits 2 ([row 175](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L175));
  reads are unchanged: a GET 42501 is protected without the log ([row 177](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L177)).
- **The log is read through the server** (`pg_current_logfile` + `pg_read_binary_file` on the
  superuser connection) on both backends; no log gives exit 2 ([rows 190-191](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L190)).
- **Left for you, deliberately:** findings listed under Not done, each with its trail row where
  one exists ([115](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L115), [119](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L119), [127](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L127), [167](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L167), [178](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L178), [183](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L183)).

The owner decided: two backends, attacks through PostgREST only, white-box value candidates
(D-1 to D-3, [row 23](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L23)),
and option 1 on [#8](https://github.com/pitaya943/rlsentry-v2/issues/8) ([row 92](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L92)).

## 4. Not done or in doubt

### The gap: the real Docker images never ran

There is no Docker daemon in this environment and Docker Hub answers 429 to anonymous pulls. The
whole Docker backend, including the in-database log read added when T-06 was merged with T-05,
is proven only against `tests/fakedocker.py` (local processes standing in for containers).
Still unproven on a real daemon: that `postgres:16` ships `auto_explain` and accepts the `-c`
settings through its entrypoint, that `pg_current_logfile('jsonlog')` works on its tmpfs data
directory, and that `--tmpfs` suppresses the image's anonymous volume (shown only from Moby's
source). The verifier showed that if any of these differs, every write ends in exit 2, never a
false `protected` ([PR #9 verdict at 8700a40](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7142908520)).
The check that would prove it is `tests/test_docker.py::test_lab_on_a_real_docker_daemon_matches_expected_and_leaves_nothing`,
skipped here. Because `auto` is the default, on a machine with a daemon a plain `rlsentry attack`
runs on this unproven path.

### The fix-round history

| Ticket | Verdicts | Outcome |
|---|---|---|
| T-01 | [FAIL 120acb0](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7104577361) → [PASS 5d96138](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7105018174) | passed on fix round 1; merged [a735dd2](https://github.com/pitaya943/rlsentry-v2/commit/a735dd2) |
| T-02 | [PASS 79c65be](https://github.com/pitaya943/rlsentry-v2/pull/4#issuecomment-7105914932) | passed first time; merged [7e1d75f](https://github.com/pitaya943/rlsentry-v2/commit/7e1d75f) |
| T-03 | [FAIL 01b0f6a](https://github.com/pitaya943/rlsentry-v2/pull/5#issuecomment-7107879892) → [PASS 8ce5136](https://github.com/pitaya943/rlsentry-v2/pull/5#issuecomment-7109764058) | passed on fix round 1; merged [aa76ba2](https://github.com/pitaya943/rlsentry-v2/commit/aa76ba2) |
| T-04 | [FAIL 5f82d22](https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7112028786) → [FAIL 7408659](https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7113386234) → [FAIL 47467b7](https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7114871846) → [FAIL 981f8f8](https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7116794096) | **used up its three fix rounds**; [#8](https://github.com/pitaya943/rlsentry-v2/issues/8) went to you; you chose option 1: T-04 merged at 981f8f8 as [eac2097](https://github.com/pitaya943/rlsentry-v2/commit/eac2097) with D7-D9 open, and T-06 was added to fix them |
| T-05 | [FAIL 6658f77](https://github.com/pitaya943/rlsentry-v2/pull/7#issuecomment-7112406573) → [FAIL b7f56ea](https://github.com/pitaya943/rlsentry-v2/pull/7#issuecomment-7115969418) → [PASS e6c9782](https://github.com/pitaya943/rlsentry-v2/pull/7#issuecomment-7139562554) | passed on fix round 2; merged [5041907](https://github.com/pitaya943/rlsentry-v2/commit/5041907) |
| T-06 | [FAIL c3cb785](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7134436890) → [FAIL ffa829d](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7136341651) → [FAIL 30393ee](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7138303905) → [PASS 2559b10](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7139911308) → merged with T-05 → [PASS 8700a40](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7142908520) | passed on fix round 3, the last; passed again after its merge with T-05; merged [a6a094c](https://github.com/pitaya943/rlsentry-v2/commit/a6a094c) |

So 11 of 17 verdicts were FAIL. The code you are asked to merge is the state each final PASS saw;
no ticket was merged on a FAIL except T-04, by your decision, and its open defects were then
closed by T-06's PASS.

### The recurring class: a verdict not backed by a real attack

The same mistake came back in almost every ticket: a verdict (or exit code) that claimed more
than the attack showed.
- T-01: a table that could not be seeded read `READ: protected` (folded into T-03).
- T-02: a 5xx branch with no test, "not attempted" read `protected`, a unique first column made an
  open UPDATE read `protected` (F1-F4, folded into T-04).
- T-03: an unexpected exception exited 1, the code for "exposed" (D3).
- T-04: a 2xx insert that wrote nothing read `EXPOSED` with the sent row as evidence; class-22
  errors from triggers read `protected` (D4); a trigger raising 42501 read `protected` (D5);
  then CHECK, domain, ALWAYS-trigger and replica-aware refusals (D7). Each round inferred
  "refused by RLS" from the error, and the table's own code could always forge the error.
- T-06 round 0: re-evaluating policies outside PostgREST's real context (`session_user`,
  `current_query()`, `pg_trigger_depth()`) read `protected` (D1, D2); later rounds: guards on the
  `protected` path that no test could break (D3, D4, V10).

What ended it was structural: `protected` for a write now needs PostgreSQL's own log entry
naming the C function that refused (which SQL cannot forge), and rlsentry's own reasoning may
only take a `protected` away. This is the class to watch in every later task; it fits
`shilaycow-correct` (it happened far more than twice).

### Open findings

Checked against the verdicts; each link is where it was found or last confirmed. "Me" means I
reproduced it for this report.

Verdicts that may be wrong (false `protected` or a needless exit 2):
- **Partial cross-table trigger writes.** A trigger writing to another RLS table only for some
  values gets `protected` for those values, while anon can write the others ([PR #9 fix-1 verdict](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7136341651); trail [row 165](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L165)).
- **Policies reading request headers anon can choose** read `protected` when rlsentry does not send
  that header ([same verdict](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7136341651); me: `extra.txt` `hdr`).
- **Primary-key text round trip.** The by-key filter is built from Python's text of the key, so a
  key that does not round-trip (jsonb `0.10000000000000000001`) gives exit 2 on a protected table
  ([PR #9 fix-2 verdict](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7138303905); [row 183](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L183)).
- **No UPDATE value search.** An UPDATE refused by a WITH CHECK on one value reads `protected`
  ([PR #6 verdict, Finding 3](https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7112028786); [row 115](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L115)).
- **Value search drops a constant it cannot cast instead of adapting it** (`with check (n > 0.5 and
  n < 1.5)` on an int never tries 1), so such a table reads `protected (N rows tried)`
  ([PR #6 fix-1 verdict, Finding 1](https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7113386234); [row 119](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L119)). Not on your list; still in the code (`Inspector._fits`).
- **Views are not attacked**, only tables of kind `r`/`p` in `public` ([PR #3 verdict](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7104577361); me: `extra.txt` `view`).
- **A policy false only inside PostgREST's request** (e.g. `session_user <> 'authenticator'`) now
  exits 2 instead of `protected`: the accepted cost of the oracle ([row 175](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L175)).
- **Code written against the oracle itself** (reading `pg_trigger` or the `rlsentry.caught`
  setting while it runs) can steer rlsentry's own evaluation; it can only take `protected` away
  ([row 165](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L165)).

Migrations the copy does not take:
- **Domain-typed NOT NULL columns** cannot be seeded: exit 2 ([PR #5 verdict](https://github.com/pitaya943/rlsentry-v2/pull/5#issuecomment-7107879892); me: `extra.txt` `domain`).
- **Migrations with their own `begin; ... commit;`** commit part of the file early; a later error
  still exits 2 ([PR #5 PASS verdict](https://github.com/pitaya943/rlsentry-v2/pull/5#issuecomment-7109764058); me: exit 2 in `extra.txt` `begin`, early commit not observed by me).

Hosted Supabase may differ:
- **pg-safeupdate (F6).** `lab_update_open` and `lab_delete_open` are found only by unfiltered
  writes; hosted Supabase may refuse those. Not checked: it would touch a live project
  ([PR #4 verdict](https://github.com/pitaya943/rlsentry-v2/pull/4#issuecomment-7105914932); [row 53](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L53)).

Side effects inside the copy:
- **Advisory locks and sequences survive the oracle's rollback** (`nextval`, `pg_advisory_lock`
  taken by a policy); confined to the copy; it is why `lab_value_policy`'s evidence id is 8
  ([PR #6 fix-2 verdict](https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7114871846); [PR #9 verdict](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7134436890); [rows 127](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L127), [167](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L167), [178](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L178)).
- **Request cost per table.** Every refused insert costs up to 50 requests (12 on each lab table
  with no insert policy); the brief does not bound total cost ([PR #6 verdict, Finding 4](https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7112028786)).

The machine running rlsentry:
- **Trust authentication.** Both backends start PostgreSQL with trust authentication on
  127.0.0.1, so during a run any local user can connect as the superuser `supabase_admin` (and
  from there, as a superuser can, reach the host as the server's OS user: inferred, not run) ([PR #3 PASS verdict](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7105018174); still `--auth=trust` in `backends/local.py`, `POSTGRES_HOST_AUTH_METHOD=trust` in `backends/docker.py`). Not on your list; it matters on a shared machine.
- **Early SIGINT traceback.** Ctrl-C while Python is still importing gives a traceback and exit
  130; nothing is left ([PR #3 verdicts](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7105018174)).
- **Pid reuse in the local sweep.** If a killed run's pid is reused by a live process, its marker
  and copy are never swept. The Docker sweep checks the start time and is not affected
  ([PR #3 PASS verdict](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7105018174); `backends/local.py` `_running`).

Docker backend, besides the main gap ([PR #7 verdicts](https://github.com/pitaya943/rlsentry-v2/pull/7#issuecomment-7139562554)):
- **`auto` is the default backend**, so a daemon, when present, takes the unproven path ([PR #7 first verdict](https://github.com/pitaya943/rlsentry-v2/pull/7#issuecomment-7112406573)).
- **`DOCKER_HOST=tcp://127.0.0.1:2375` is refused as remote**; `--backend docker` exits 2 (same verdict).
- **The tmpfs has no size limit**; a large seed lives in memory.
- **Ctrl-C before `docker create` reaches the daemon costs 10 s** and prints a "could not confirm" warning, though nothing is left.
- **A hung daemon stretches teardown** past the 10 s grace.
- **The fake docker is stricter than Moby in two places** (`rm -f` of a missing container exits 1;
  a `--rm` container that never started is kept). Harmless today; a future change reading `rm`'s
  exit code would be tested against the wrong behaviour.
- **`--rlsentry-backend docker` breaks 6 tests outside `test_verdicts.py`**, and makes the
  real-daemon test run against the fake ([PR #9 verdict at 8700a40](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7142908520)). Developer tooling only.
- **Docker start-up errors lose the server log**: with `logging_collector=on` the error text goes
  to files inside the container, and `docker logs` shows little (same verdict). The local backend
  has the same effect since T-06.
- **The log route is unproven on a real `postgres:16`** (see the gap above).

Smaller:
- The nonce tests do not directly show that no request reached an unverified server; the order is
  guarded only through the dead-server test ([PR #3 PASS verdict](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7105018174)).
- The repository's `README.md` is still the one-line placeholder; how to run rlsentry is only in
  `.claude/skills/try-rlsentry/SKILL.md` and the spec.
- `design.md` still says "DRAFT, in discussion" at its top although D-1 to D-3 were decided; the
  spec now records what was built.

### Where the spec and the brief or design disagree

The code and the verified tests win; the spec follows the code. Each one is for you to accept or
send back:
1. Design D-1 makes `docker` the default; the CLI default is `auto` (docker when it can run,
   else local, said on stderr).
2. Brief: "Nothing is stored between runs except a report file the user names." There is no
   report-file option: the report goes to standard output. During a run the local backend writes
   a marker under `~/.local/state/rlsentry` (removed at teardown); the Docker backend keeps pulled
   images.
3. Design §3 step 5 and the brief: rows that cannot be generated are skipped and noted. Code: a
   table left with **no** row stops the run with exit 2 (partial seeding is still noted). Decided
   in T-03 after T-01's verdict.
4. Design §4: value search starts when an insert was refused with 42501. Code: after any refused
   first insert, and the first row counts toward the 50.
5. Brief Assumptions: value candidates include "values visible in readable rows". Code: values in
   the seeded rows, read as superuser, whether anon can read them or not.
6. Design §4: a write's `protected` rests on a 42501 or a 2xx that changed nothing. Code: also
   needs PostgreSQL's own log account of the request and rlsentry's own evaluation agreeing
   (T-06); otherwise exit 2.
7. Design §4: UPDATE/DELETE by the seeded primary key only. Code: by key, then without a filter;
   UPDATE one column at a time, key columns last.
8. Design §4: a snapshot before each destructive attempt, swapped back after. Code: one snapshot
   of every table after seeding, every table restored after each write attempt; sequences not
   restored.
9. Design §3: migrations applied (implicitly as the superuser). Code: as the non-superuser
   `postgres`; the superuser is `supabase_admin`; untrusted extensions stop the run (T-04).
10. Brief S-10 and design §6: exit 2 = could not build or attack. Code also uses 2 for the
    refused `--target`, an interrupted run and any unexpected error.
11. Design §6: `run(source: MigrationsDir | Lab)`. Code: `run(migrations, label, backend)`
    (internal only).

## Scenarios

| Scenario | Met | Evidence |
|---|---|---|
| S-1 Readable table is caught | met | `test_lab.py::test_exposed_read_shows_count_and_a_seeded_row`; `lab_rls_off` in [transcript](../evidence/final-try/transcript.txt); [PR #3 PASS](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7105018174) |
| S-2 Protected table is not a false alarm | met | `lab_no_policy`, `lab_owner_only` all protected (`test_lab_verdicts_match_expected`); clean folder exit 0; `protected` rests on PostgreSQL's log ([PR #9 PASS 8700a40](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7142908520)) |
| S-3 "RLS on but wrong" is caught | met | `lab_using_true` READ EXPOSED; [PR #3 PASS](https://github.com/pitaya943/rlsentry-v2/pull/3#issuecomment-7105018174) |
| S-4 Each write operation is tried for real | met | `lab_insert_only`, `lab_update_open`, `lab_delete_open`; `test_writes.py`; [PR #4 PASS](https://github.com/pitaya943/rlsentry-v2/pull/4#issuecomment-7105914932), [PR #9 PASS](https://github.com/pitaya943/rlsentry-v2/pull/9#issuecomment-7142908520). Write-only policies found only unfiltered (pg-safeupdate doubt above) |
| S-5 Policies that accept chosen values are caught | met | `lab_value_policy` EXPOSED with source; `protected (N rows tried)`; `test_verdicts.py::test_value_search_*`. Recall limits above (no UPDATE search, uncastable constants) |
| S-6 Migrations of a real project are accepted | met | `supabase_app` exit 1, every table seeded; `broken` exit 2 naming file, line, `storage.buckets`; `test_migrations.py`; [PR #5 PASS](https://github.com/pitaya943/rlsentry-v2/pull/5#issuecomment-7109764058). Domain columns and views are gaps |
| S-7 Never attacks a live project | met | `test_guard.py::test_target_is_refused_before_any_connection` (sockets blocked); `--target` in transcript |
| S-8 Nothing is left behind | met (local); fake only (docker) | `test_teardown.py`, Ctrl-C step and residue `none` in transcript; docker: `test_docker.py` on the fake ([PR #7 PASS](https://github.com/pitaya943/rlsentry-v2/pull/7#issuecomment-7139562554)) |
| S-9 The lab shows every verdict | met | `test_lab_verdicts_match_expected` against `expected.json`; my `report.json` equals it |
| S-10 Machine-readable report and exit codes | met | `test_json_report_matches_schema`; exits 0/1/2 in transcript; `test_unexpected.py` |

Suite at `73ba666`, fresh venv, local backend: `235 passed, 1 skipped` ([suite.txt](../evidence/final-try/suite.txt)); the skip is the real-daemon test. There is no CI on this repository.

## Tickets and risk

| Ticket | Final risk | Signal that set it | Verification |
|---|---|---|---|
| T-01 sandbox, guard, read, report | high | the live-target guard and teardown are the brief's Critical areas ([row 29](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L29)) | fresh verifier, 2 verdicts |
| T-02 writes | high | mutating requests through the guard ([row 29](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L29)) | fresh verifier, 1 verdict |
| T-03 migrations and seeding | high | the copy's data model: roles, auth stand-in ([row 29](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L29)) | fresh verifier, 2 verdicts |
| T-04 value search, full lab | high (planned medium) | raised after T-03's verdict: it changes which role runs every migration ([row 90](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L90)) | fresh verifier, 4 verdicts, all FAIL; merged by your decision |
| T-05 Docker backend | high | process and container lifetime: teardown is a Critical area ([row 29](https://github.com/pitaya943/rlsentry-v2/blob/73ba666/docs/tasks/anon-probe/trail.tsv#L29)) | fresh verifier, 3 verdicts; real daemon never ran |
| T-06 RLS oracle | high | decides every `protected` verdict and runs migration-authored expressions ([ticket](../tickets/T-06.md)) | fresh verifier, 5 verdicts incl. the merge |

No ticket was verified lightly: all six were high risk and each got an independent verifier for
every Ready head. The light spot is the Docker path, verified only on the fake.

## 5. Verification

The independent verdict on the pull request into `main` is posted as a comment on that pull
request.
