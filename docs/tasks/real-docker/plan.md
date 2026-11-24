# Plan: real-docker

Brief: [brief.md](brief.md), approved at aea2c48. Tracking issue: #16.

## Facts found before planning (2026-11-24, this environment)

- `dockerd` 29.9.3 is installed and starts as root in about 2 s (overlayfs, cgroup v1).
- Docker Hub answered **429** for both `postgres:16` and `postgrest/postgrest:v12.2.3`.
- Mirrors that serve the same images (same image ID on both):
  - `postgres:16`: `mirror.gcr.io/library/postgres:16`, `public.ecr.aws/docker/library/postgres:16`
    (image 07abc3f43c93).
  - `postgrest/postgrest:v12.2.3`: `mirror.gcr.io/postgrest/postgrest:v12.2.3`,
    `public.ecr.aws/supabase/postgrest:v12.2.3` (image 729bf65c733b). There is no
    `public.ecr.aws/postgrest/...` repository; Supabase's ECR copy is byte-identical.

## Shape

- `tests/realdocker.py`: the helper. `ensure()` makes a daemon answer (starts `dockerd`
  detached, as root, only when none answers and the binary exists; waits up to 60 s; leaves
  it running) and makes both pinned tags present (Docker Hub, then `mirror.gcr.io`, then
  `public.ecr.aws`; `docker tag` to the pinned name; prints registry and image ID). Runnable
  on its own: `python3 tests/realdocker.py`. `RLSENTRY_TEST_REFUSE_REGISTRY=docker.io` makes
  it treat a registry as refusing, to show the fallback.
- `tests/conftest.py`: `--rlsentry-backend local|fakedocker|docker`. `docker` calls
  `realdocker.ensure()` once per session; a `real_docker` marker selects the tests that need
  the real daemon: they skip under `local`/`fakedocker` (reason names the command) and fail
  under `docker` if `ensure()` failed (reason given).
- The real-Docker command: `python3 -m pytest -q --rlsentry-backend docker`.

## Tickets (in order; each builds on the one before)

| Ticket | Scenarios | Risk | Touches |
|---|---|---|---|
| T-01 helper, option names, marker | S-1 S-2 S-3 S-4 S-8 | medium | tests/realdocker.py (new), tests/conftest.py, tests/test_docker.py (real test only) |
| T-02 real daemon under the suites; interrupt and kill on real Docker | S-5 S-6 | medium | tests/conftest.py, tests/test_verdicts.py, tests/test_answers.py, tests/test_docker.py |
| T-03 whole suite passes on the stand-in | S-7 | medium | the tests that fail under the stand-in today |
| Finish: spec, #11, report | S-9 | low | docs/spec/throwaway-copy.md, docs/spec/roadmap.md |

Risk: no ticket changes rlsentry's own code (`rlsentry/`); the brief's critical areas are
teardown on Docker and verdict code. If a real-daemon run shows a product bug, that ticket
becomes high and is designed and verified on its own.

All three touch `tests/conftest.py`, so they run one after another (pitfall 5), not in
parallel.
