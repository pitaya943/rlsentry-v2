# Final report: real-docker

By my own check, every scenario in the [brief](../brief.md) (S-1 to S-9) is met. One
command, `python3 -m pytest -q --rlsentry-backend docker`, now starts a real Docker daemon here
if none answers, gets both images (with a mirror fallback that was really needed: Docker Hub
answered 429 during this task), and runs the whole suite on it: 268 passed, every copy the
suites built seen on the real daemon, nothing left behind.

Base for every link: branch `task/real-docker`. Evidence files are in [`../evidence/`](../evidence/).

## What was done

- `tests/realdocker.py` is new. It starts `dockerd` when no daemon answers (only as root, only
  when the binary exists) and leaves it running. It then makes `postgres:16` and
  `postgrest/postgrest:v12.2.3` present, pulling from Docker Hub, else `mirror.gcr.io`, else
  `public.ecr.aws`, and tagging the result under the pinned name.
  ([#17](https://github.com/pitaya943/rlsentry-v2/pull/17))
- The test option is now `--rlsentry-backend local|fakedocker|docker`, and `docker` means the
  real daemon.
  - Tests marked `real_docker` run only under `docker`, and fail (never skip) when the daemon
    cannot be made ready.
  - Under `docker`, each copy the suites build is checked in the daemon's own event log.
- Ctrl-C and `kill -9` on the real daemon are now tests.
  ([#18](https://github.com/pitaya943/rlsentry-v2/pull/18))
- The tests that broke under the stand-in option pass. ([#19](https://github.com/pitaya943/rlsentry-v2/pull/19))
  - They were 5, not 6: the real-daemon test, plus 4 local-backend tests that now name their
    backend.
  - A race already in the stand-in was also fixed: it wrote its state file non-atomically.
- `rlsentry/` itself is unchanged. The spec's "Run on Docker" scenario no longer says
  Unverified.

## How to try it

Every step below was run for this report on 2026-11-24/25, in this cloud environment, as root.

1. Get the branch and install:
   ```bash
   git clone https://github.com/pitaya943/rlsentry-v2 && cd rlsentry-v2 && git checkout task/real-docker
   ```
   ```bash
   pip install -e '.[test]'
   ```
   PostgreSQL 16 and PostgREST 12.2.3 are already installed in this environment (its setup
   script installs PostgREST); the local-backend steps need them.
2. With no daemon running (`pkill dockerd`), run `python3 tests/realdocker.py` twice.
   - The first run says `started dockerd (29.9.3), log: /tmp/rlsentry-dockerd.log` and names
     the registry each image came from.
   - The second run says `using the Docker daemon already running`.
   - Record: [T-01-start-and-mirror.txt](../evidence/T-01-start-and-mirror.txt). In that run,
     Docker Hub refused PostgREST with 429, and it came from `mirror.gcr.io`.
3. `python3 -m pytest -q --rlsentry-backend docker` gives about 269 passed in about 10 minutes.
   The run closes with:
   - `real Docker: started dockerd (29.9.3), log: /tmp/rlsentry-dockerd.log`, or on a later run
     `using the Docker daemon already running`;
   - one line per image naming where it came from;
   - `real Docker: N copies built without a named backend, each seen created on the real daemon`.

   Record, from no daemon and then again:
   [fix-1-documented-command.txt](../evidence/fix-1-documented-command.txt). Before fix round 1
   the daemon and image lines were missing under `-q`
   ([T-03-whole-suite-docker.txt](../evidence/T-03-whole-suite-docker.txt)).
4. `docker ps -a --filter label=rlsentry.run` shows nothing.
5. `python3 -m pytest -q --rlsentry-backend fakedocker` gives 263 passed, 5 skipped. The skips
   are the real-daemon tests, and their reason names the command in step 3.
   Record: [T-03-whole-suite-fakedocker.txt](../evidence/T-03-whole-suite-fakedocker.txt).
6. `python3 -m pytest -q` (the default) gives 263 passed, 5 skipped, and no daemon was started.
   Record: [T-03-whole-suite-local.txt](../evidence/T-03-whole-suite-local.txt).
7. Show the mirror fallback by hand. Keep the layers under a spare tag, then drop the pinned tag:
   ```bash
   docker tag postgres:16 spare/postgres:16 && docker rmi postgres:16
   ```
   ```bash
   RLSENTRY_TEST_REFUSE_REGISTRY=docker.io python3 tests/realdocker.py
   ```
   It says `postgres:16: pulled from mirror.gcr.io`. Drop the tag again and run it with
   `docker.io,mirror.gcr.io` refused, and it says `public.ecr.aws`.
   Record: [try-it-mirror-fallback.txt](../evidence/try-it-mirror-fallback.txt).
8. `rlsentry attack --backend docker --lab` prints `9 exposed operation(s) in 8 table(s).`,
   exits 1, and leaves 0 labelled containers.
   Record: [try-it-lab-on-real-docker.txt](../evidence/try-it-lab-on-real-docker.txt).

Worth trying beyond the tests:
- Run step 3 with Docker Hub really rate-limiting (not run on purpose; it happened in step 2).
- Run step 3 on a laptop with Docker Desktop (not run: not available here).
- Ctrl-C the whole pytest run while the real-daemon tests are going, then run step 4 (not run).

## Decisions I made

From [trail.tsv](../trail.tsv):
- **Built all three tickets myself, one after another.** They all touch `tests/conftest.py`
  (pitfall 5), and each is smaller than a builder's brief would be.
- **All tickets rated medium, with no per-ticket verification.** No ticket changes `rlsentry/`;
  the brief's critical areas (teardown on Docker, verdict code) are exercised, not changed.
- **The ECR fallback for PostgREST is `public.ecr.aws/supabase/postgrest`.** There is no
  `public.ecr.aws/postgrest` repository, and Supabase's copy has the same image ID
  (729bf65c733b) as Docker Hub's.
- **Real-daemon tests skip under `local` and `fakedocker` even when a daemon answers.** That is
  what S-8 and S-7 need.
- **A daemon that is not ready fails the test in its call phase.** A setup-phase failure would
  read as an "error", that is, broken tooling, not as the failed check S-2 asks for.
- **S-5 is shown per copy, through the daemon's event log.** Counting containers at the end
  would not catch a copy that ran elsewhere.
- **The real interrupt and kill tests are new tests,** not the stand-in tests parametrised. The
  stand-in tests read the fake's own state.
- **The 4 local-backend tests name `--backend local`.** They check the local marker, pids and
  run directory; the docker versions of the same checks already existed.
- **Fixed the stand-in's non-atomic state write inside this task.** It was already there
  before, but it made S-7 depend on luck.
  ([run 1](../evidence/T-03-whole-suite-fakedocker-run1.txt): 1 failed, 1 error.)
- **#15 item 7 was 5 failures on main, not 6.**
  ([T-03-before-on-main.txt](../evidence/T-03-before-on-main.txt))

## Not done or in doubt

- **The default test command stays local-only (D3).** The harness's `test_command`, and so
  every future gate, does not run the real-daemon check. Someone has to run the real-Docker
  command, or a CI workflow has to (deferred by the owner, D5).
- **Not shown here:** Docker Desktop on macOS, rootless Docker, a remote daemon, and a hung
  daemon. The last two are already tracked as #15 items 5 and 2.
- **Mirror images are trusted as caches of Docker Hub and are not pinned by digest.** The image
  IDs match across all three registries today; nothing enforces that.
- **The daemon, its images and `/var/lib/docker` stay after a run,** and the daemon log is
  `/tmp/rlsentry-dockerd.log`.
- **S-1's "started when none answers" path is covered by stub tests and two recorded runs.**
  The test on the real daemon accepts either "started" or "already running", because it cannot
  stop the daemon in the middle of the suite.
- **The real-daemon tests assume no other rlsentry run is using the daemon at the same time.**
  The Ctrl-C and kill tests assert that no labelled container exists at all.
- **Other #15 items (1–6, 8), and #12–#14:** untouched, as the brief says.

## Verification

The independent verdict is posted as a comment on this pull request.

**Fix round 1.** Verdict 1
([FAIL](https://github.com/pitaya943/rlsentry-v2/pull/20#issuecomment-7149315062)) found that
the documented command did not print what S-1 and S-3 say it prints.
- **Cause:** the command uses `-q`, and the lines were report-header lines, which `-q` hides. No
  test looked at the command's output.
- **Fix:** the lines now also close the run, and a new test runs the documented command and
  checks its output.

## Scenarios

| Scenario | Met | Evidence |
|---|---|---|
| S-1 daemon brought up when none answers, reused after | yes (after fix round 1) | [fix-1-documented-command.txt](../evidence/fix-1-documented-command.txt), `test_the_documented_command_says_what_it_did_with_the_daemon_and_images`, [T-01-start-and-mirror.txt](../evidence/T-01-start-and-mirror.txt), `test_starts_dockerd_when_no_daemon_answers_and_reuses_it_after`, [T-03-whole-suite-docker.txt](../evidence/T-03-whole-suite-docker.txt) ("no dockerd before"), [#17 Ready](https://github.com/pitaya943/rlsentry-v2/pull/17#issuecomment-7147792406) |
| S-2 missing daemon fails, not skips | yes | `test_with_the_docker_option_a_daemon_that_cannot_answer_fails_the_real_tests`, mutant M3 ([T-01-mutants.txt](../evidence/T-01-mutants.txt)) |
| S-3 mirror fallback | yes (after fix round 1) | `test_the_documented_command_says_what_it_did_with_the_daemon_and_images` (registry per image under `-q`), stub tests (gcr, ECR, all refuse); real-daemon test; [try-it-mirror-fallback.txt](../evidence/try-it-mirror-fallback.txt); a real Hub 429 in [T-01-start-and-mirror.txt](../evidence/T-01-start-and-mirror.txt) |
| S-4 lab on the real daemon, no volume, nothing left | yes | `test_lab_on_a_real_docker_daemon...`, [T-01-real-option.txt](../evidence/T-01-real-option.txt), [try-it-lab-on-real-docker.txt](../evidence/try-it-lab-on-real-docker.txt) |
| S-5 verdict and answer suites on the real daemon | yes | [T-02-suites-on-real-docker.txt](../evidence/T-02-suites-on-real-docker.txt) (137 passed, 156 copies witnessed), mutants W1 and W2 ([T-02-mutants.txt](../evidence/T-02-mutants.txt)) |
| S-6 Ctrl-C and kill -9 on the real daemon leave nothing | yes | `test_sigint_mid_run_on_a_real_daemon...`, `test_a_killed_run_on_a_real_daemon...`, mutants W3 and W4 |
| S-7 the whole suite passes on the stand-in | yes | [T-03-before-on-main.txt](../evidence/T-03-before-on-main.txt) → [T-03-whole-suite-fakedocker.txt](../evidence/T-03-whole-suite-fakedocker.txt), [#19 Ready](https://github.com/pitaya943/rlsentry-v2/pull/19#issuecomment-7148818260) |
| S-8 default command starts no daemon, pulls nothing | yes | `test_without_the_docker_option_real_tests_skip_and_no_daemon_or_pull_is_asked_for` (default and fakedocker), mutant M4, [T-03-whole-suite-local.txt](../evidence/T-03-whole-suite-local.txt) |
| S-9 #11 settled; spec no longer says Unverified | yes, #11 closed when this PR is opened | [throwaway-copy.md](../../../spec/throwaway-copy.md) "Run on Docker"; the closing comment on #11 lists what stays unproven |

## Tickets

| Ticket | Pull request | Risk | Signal that set it |
|---|---|---|---|
| T-01 helper, options, marker | [#17](https://github.com/pitaya943/rlsentry-v2/pull/17) | medium | test tooling only; `rlsentry/` unchanged |
| T-02 suites on the real daemon; Ctrl-C and kill -9 | [#18](https://github.com/pitaya943/rlsentry-v2/pull/18) | medium | test tooling only; exercises Docker teardown (critical area) without changing it |
| T-03 whole suite on the stand-in | [#19](https://github.com/pitaya943/rlsentry-v2/pull/19) | medium | tests and the stand-in only |

No ticket had its own verification: the verdict on this pull request is the only independent
check.
