# Plan: anon-probe

Five tickets. T-01 is the shared groundwork and the first runnable slice; T-02, T-03 and
T-05 can then run in parallel (they touch different modules); T-04 needs T-02 and T-03.

```
T-01 ─┬─> T-02 (writes) ──┐   (re-cut: T-05 runs after T-02 and T-03, see trail)
      ├─> T-03 (real migrations + seeding) ─┴─> T-04 (value search, full lab = S-9)
      └─> T-05 (docker backend)
```

| Ticket | Scenarios | Areas | Risk |
|---|---|---|---|
| T-01 | S-1, S-3, S-7, S-8, S-10 | package, cli, sandbox (local backend), channel, attacker (read), report, lab (first tables) | high |
| T-02 | S-2, S-4 | attacker (insert/update/delete), sandbox (restore, superuser confirmation), lab tables | high |
| T-03 | S-6 | sandbox (auth stand-in, migration errors), seed | high |
| T-04 | S-5, S-9 | attacker (value search), sandbox (policy/constraint constants), lab completion | medium |
| T-05 | (D-1 a; S-8 for docker) | sandbox backend: docker | high |
| T-06 | S-2, S-4, S-5 | attacker (RLS oracle), sandbox (Inspector policy evaluation) | high |

The integration test against the lab, compared to `lab/expected.json`, grows with each
ticket. By T-04 it is S-9's proof.

`test_command` is set in T-01 (`python3 -m pytest -q`).

T-06 was added after T-04 used its three fix rounds (issue #8, owner chose option 1):
T-04 merged at 981f8f8 with D7-D9 open, and T-06 replaces error-based inference of
"refused by RLS" with evaluating anon's policies directly.
