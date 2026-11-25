# Brief: real-docker — prove the Docker backend on a real daemon, repeatably

Status: draft, not approved.

A chore task, outside the numbered chain in `docs/spec/roadmap.md` (whose next task is
`lovable-target`). It closes the gap recorded in issue #11 and fixes #15 item 7.

## Goal

Today the Docker backend is proven, in the test suite, only against a stand-in daemon. The owner
showed by hand on 2026-11-24 (#11, comment 7147273353) that it works on a real daemon in this
cloud environment, but nothing repeats that check.

After this task, one documented test command, run in this environment, starts a real Docker
daemon if none is running, makes sure both images are present (falling back to a mirror when
Docker Hub refuses), and runs against the real daemon: the lab check, the verdict and answer
suites, and the interrupted and killed runs the owner tried by hand. The stand-in daemon stays
available under its own name, and the whole suite passes on it too.

## Out of scope

- Issue #15 items other than 7 (default backend, `DOCKER_HOST` over TCP, tmpfs size, Ctrl-C cost
  before `docker create`, hung daemon, the fake's two extra strictnesses, lost start-up log),
  unless one blocks a scenario here; then it is logged in the trail.
- Issues #12, #13, #14.
- A mirror fallback inside rlsentry itself: a user's `rlsentry attack` still pulls only the names
  it pins. The fallback lives in the test tooling.
- Docker Desktop on macOS, rootless Docker, remote daemons: not available here.
- The branch `spike/rls-ordering`: kept untouched (the roadmap's `live-probe` refers to it).
- A GitHub Actions workflow. Owner's choice: a later task of its own (the bot cannot push
  under `.github/`; the workflow will call this task's real-Docker command).

## Scenarios

Area for all: [The throwaway copy and its backends](../../spec/throwaway-copy.md).

- **S-1 A real daemon is brought up when none answers.** *(new, test tooling)* Given a fresh
  session of this environment where `dockerd` is installed but not running, when the developer
  runs the real-Docker test command, then a daemon is started and answers before any test needs
  it, and the output says it was started and where its log is. Run again, the command uses the
  daemon already running and does not start a second one.
- **S-2 A missing daemon is a failure, not a skip.** *(new, test tooling)* Given the real-Docker
  test command on a machine where no daemon answers and one cannot be started (not root, or no
  `dockerd`), when it runs, then the real-daemon tests fail with the reason, instead of being
  skipped.
- **S-3 Images come from a mirror when Docker Hub refuses.** *(new, test tooling)* Given
  `postgres:16` or `postgrest/postgrest:v12.2.3` is not present and Docker Hub refuses the pull
  (as with its 429), when the real-Docker test command prepares the images, then it pulls each
  from `mirror.gcr.io`, else from `public.ecr.aws`, tags it under the name rlsentry asks for, and
  says which registry each image came from. If all three refuse, the run fails naming each
  registry's answer.
- **S-4 The lab runs on the real daemon and leaves nothing.** *(changes "Run on Docker": drops
  its Unverified note)* Given the real-Docker test command, when the lab check runs, then the lab
  gives the expected verdict for every table and operation, the database's data directory is not
  a volume, and no labelled container is left.
- **S-5 The verdict and answer suites run on the real daemon.** *(new, test tooling)* Given the
  real-Docker test command, when the verdict and answer suites run, then every copy they build is
  a pair of containers on the real daemon (not the stand-in), and they pass with the same results
  as on the local backend.
- **S-6 Interrupted and killed runs on the real daemon leave nothing.** *(changes "Press Ctrl-C
  mid-run" and "A killed run is cleaned up by the next one": now shown on a real daemon)* Given a
  run on the real daemon, when it gets SIGINT while its copy is up, then it exits 2 and leaves no
  labelled container or volume; and when a run is killed with `kill -9`, then the next run on the
  real daemon removes what it left and itself leaves nothing.
- **S-7 The stand-in daemon keeps its own name, and the whole suite passes on it.** *(changes
  test tooling; #15 item 7)* Given the test option that selects the stand-in daemon, when the
  whole suite runs with it, then every test passes (today 6 fail), and the real-daemon tests do
  not run against the stand-in.
- **S-8 The default test command is unchanged.** *(keeps behaviour)* Given the project's default
  test command with no backend option, when it runs, then it starts no daemon and pulls no image.
- **S-9 Issue #11 is settled.** *(record)* Given the scenarios above pass, when the task's pull
  request is opened, then #11 is closed with links to the evidence, or left open listing exactly
  what is still unproven; and the spec's "Run on Docker" scenario no longer says Unverified.

## How to try it

1. In a fresh session of this environment: `pkill dockerd` (if any), then the real-Docker test
   command → it says it started the daemon; the lab, verdict, answer and interrupt tests pass.
2. Run it again → it says the daemon was already running.
3. `docker ps -a --filter label=rlsentry.run` → empty.
4. The stand-in command → the whole suite passes.
5. Simulate a Docker Hub refusal (the tooling's switch for it) with the images removed → it says
   it pulled from `mirror.gcr.io`.
6. `rlsentry attack --backend docker --lab` → `9 exposed operation(s) in 8 table(s).`, exit 1.

## Critical areas

- **Teardown on Docker.** A labelled container or volume left on a real daemon is the failure
  this task exists to catch; any change to `rlsentry/backends/docker.py` is high risk.
- **Verdict code.** This task should not change it. If a real-daemon run disagrees with the
  local backend, that is a finding, logged in the trail and raised with the owner, not "fixed" in
  the test.

## Assumptions

- **Where dockerd is started (owner's choice: a helper in the repo).** A
  script in the repository, called by the test tooling when the real-Docker option is given. It
  does nothing when a daemon already answers, starts `dockerd` in the background only as root and
  only when the binary exists, waits up to 60 s for it, and leaves it running after the tests.
  Not the environment's setup script: that runs only when a container is built fresh (gone
  after a resume), may not start background daemons, and is not versioned with the code.
- **Option names (owner's choice).** `--rlsentry-backend docker` comes to mean the real daemon;
  `--rlsentry-backend fakedocker` selects the stand-in. Anyone running the old command gets the
  real daemon.
- **Default test command (owner's choice).** The configured `python3 -m pytest -q` stays local-only and
  the real-daemon tests skip there, with a reason that names the real-Docker command. The
  harness's verification runs both commands for this task (the real-Docker one is named in the
  plan).
- **Image integrity.** Mirror images are trusted as caches of Docker Hub and are not pinned by
  digest, the same trust rlsentry already gives a tag; the tooling prints each image's digest.
- **Time.** Image pulls happen once per container; after that the real-Docker command should
  add no more than a few minutes to the suite. No hard limit is enforced.
- **Leftovers.** The daemon, its images and its `/var/lib/docker` stay after the run (not
  labelled `rlsentry.run`, so not "left behind" in rlsentry's sense).
- **#11 closure.** #11 is closed once S-4 to S-6 pass here; what this environment cannot show
  (Docker Desktop, remote daemons, a hung daemon) is listed in the closing comment, with the
  hung daemon and TCP points already tracked in #15.
- **A product bug found on the real daemon** is fixed in this task when small and inside the
  Docker backend, with a test that fails without the fix; otherwise it goes to the owner.
