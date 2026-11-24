# The throwaway copy and its backends

Each run builds its own copy of the database, runs it on this machine (as local processes or
Docker containers), lets only the attacker's anon channel reach it, and destroys it however the
run ends.

## Scenarios

### Run with whatever this machine has

Given a machine with no Docker daemon that answers (or no `docker` CLI, a daemon that is not on
this machine, or an image that cannot be pulled) but with PostgreSQL and PostgREST installed,
when the user runs `rlsentry attack` without `--backend`,
then it says on standard error `docker unavailable (...); using the local backend` and the run
goes ahead locally.

### Run on Docker

Given a machine where a local Docker daemon answers and `postgres:16` and
`postgrest/postgrest:v12.2.3` are present or can be pulled,
when the user runs `rlsentry attack` with `--backend docker` (or without `--backend`),
then the copy runs as two containers labelled `rlsentry.run=<run id>`, both ports published on
127.0.0.1 only, and the containers are gone afterwards. Shown on a real daemon (Docker 29.9,
Linux, overlayfs) by `python3 -m pytest -q --rlsentry-backend docker`: the lab, the verdict and
answer suites, Ctrl-C and `kill -9` (real-docker). Not shown on Docker Desktop, rootless Docker
or a remote daemon.

### Ask for a backend this machine cannot run

Given `--backend docker` on a machine with no daemon (or `--backend local` without PostgreSQL or
PostgREST),
when the user runs the attack,
then it exits 2 saying what is missing. With `auto` and neither backend available, the message
names both reasons.

### Nothing is left behind after a normal run or a failure

Given any run, including one whose build or a migration fails,
when it ends,
then no PostgreSQL or PostgREST process, run directory, run marker or container from it is left.

### Press Ctrl-C mid-run

Given a run in progress,
when the user presses Ctrl-C (SIGINT) or the run gets SIGTERM,
then the copy is torn down, it prints `interrupted (SIGINT); the copy was torn down`, and exits
2.

### A killed run is cleaned up by the next one

Given a run that was killed with `kill -9` and left its copy running,
when the user starts the next run on the same backend,
then that run first removes what the dead run left, and leaves alone what live runs (or, on
Docker, other machines) own.

### The attacker only ever reaches the copy

Given a run,
when the attacker sends any request,
then it goes to 127.0.0.1 on the port of the PostgREST this run started, ignoring any proxy
settings in the environment, and never follows a redirect (a 3xx stops the run with exit 2,
whatever migration code made PostgREST answer); and before the first request the run nonce is read back and both
servers are checked to be the ones started. If the nonce is missing or different, or a server
has died, the run stops with exit 2 before sending anything.

## Rules

- The copy is PostgreSQL 16 and PostgREST 12.2.3 on random free ports, listening on 127.0.0.1
  only. PostgREST serves schema `public` with `anon` as its anonymous role and a JWT secret made
  for this run (anon-probe, T-01).
- Every HTTP request rlsentry makes (each attacking request, and the wait for PostgREST to
  answer before the attack) goes through one opener that uses no proxy and follows no redirect
  (anon-probe, T-01, T-07).
- `--backend auto|docker|local`, default `auto`: docker when it can run here, else local, said on
  standard error (anon-probe, T-05).
- Local backend: `initdb` and `postgres` from `PATH` or `/usr/lib/postgresql/<v>/bin`,
  `postgrest` from `PATH`. As root, PostgreSQL runs as the unprivileged OS user `postgres`, with
  its run directory under `/tmp`; otherwise under the user's temp directory. Each run writes a
  marker naming its run directory and processes under `~/.local/state/rlsentry`
  (`$XDG_STATE_HOME/rlsentry`, or `RLSENTRY_STATE_DIR`); it is removed at teardown (anon-probe,
  T-01).
- Docker backend: images pinned by tag (`postgres:16`, `postgrest/postgrest:v12.2.3`); both
  containers `--rm`, labelled with the run id and an owner (host, pid, start time); PostgREST
  shares the database container's network namespace; the data directory is a tmpfs, so a run
  creates no volume and no network; pulled images are kept. Only a daemon on this machine is used
  (`unix://` or `npipe://`); any other `DOCKER_HOST`, `tcp://127.0.0.1` included, is refused as
  remote. The JWT secret is passed through the docker client's environment, never on a command
  line (anon-probe, T-05).
- Teardown runs in `finally`, on SIGINT and SIGTERM, and every run starts with a sweep of its own
  backend's leftovers from runs whose rlsentry process is gone (that covers `kill -9`). Each
  backend sweeps only its own kind (anon-probe, T-01, T-05).
- Local teardown stops PostgreSQL before PostgREST. The sweep signals a recorded pid only if its
  command line still names that run's directory (anon-probe, T-01).
- Docker teardown removes the run's containers by label and looks again until none is left. When
  a `docker run` was cut off (by Ctrl-C or its 120 s timeout), it waits up to 10 s for a
  container the daemon may still create, then, if it cannot confirm, says so on standard error
  with the command to remove them (anon-probe, T-05).
- Waiting for PostgreSQL to accept connections and for PostgREST to answer: up to 60 s each
  (anon-probe, T-05).
- The copy's superuser is `supabase_admin`; its connection searches `pg_catalog` only, so a
  migration's function named like a built-in is never called by it. It sets the copy up, writes
  the nonce, reads rows to confirm what attacks did, and reads the server's log. Everything that
  runs migration-authored code goes through the role `postgres` (anon-probe, T-04, T-06).
- The server logs, for PostgREST's (`authenticator`) sessions only, every statement, errors with
  the C function that raised them, and each statement's plan (auto_explain), as jsonlog in the
  data directory. rlsentry reads it over the superuser connection (`pg_current_logfile`,
  `pg_read_binary_file`), the same way on both backends. None of these settings can be changed
  or read by the role `postgres`. A server with no such log gives no write a `protected`
  verdict (exit 2) (anon-probe, T-06).
- Two runs at once get separate copies and do not sweep each other's (anon-probe, T-01, T-05).
- An interrupted run exits 2, not 130. The exception is a Ctrl-C in the first moment, while
  Python is still importing and before the copy exists: that prints a `KeyboardInterrupt`
  traceback and exits 130, with nothing left behind (anon-probe, T-01; left open).
- On Docker, a Ctrl-C before `docker run` has reached the daemon costs the full 10 s wait and
  prints the "could not confirm" warning, though nothing is left (anon-probe, T-05; left open).

- How the backends are tested: `--rlsentry-backend local` (the default) runs the suite on local
  processes and never touches Docker; `fakedocker` runs it on the stand-in `tests/fakedocker.py`,
  which can be made to fail in ways a real daemon cannot be; `docker` runs it on a real daemon,
  which `tests/realdocker.py` starts when none answers (as root, when `dockerd` is installed)
  and fills with the two pinned images, pulled from Docker Hub, else `mirror.gcr.io`, else
  `public.ecr.aws`, and tagged under the pinned names. Only `docker` runs the tests marked
  `real_docker`, and there they fail, never skip, when the daemon cannot be made ready. Under
  `docker`, each copy the suites build is checked in the daemon's event log (real-docker).

## Last changed by

anon-probe (T-01, T-05, T-06, T-07); real-docker (T-01, T-02).
