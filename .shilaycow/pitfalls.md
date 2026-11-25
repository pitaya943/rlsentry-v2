# Pitfalls

What earlier tasks got wrong that the next one could get wrong again. Read before planning or
building. Each entry: what happened, how to avoid it, how many times, and its sources (the
tracking issues it came from; a source listed here is already folded in).

## 1. A verdict not backed by the copy's own account

- **What happened:** a verdict was inferred from a signal that code inside the copy can also
  produce: `protected` from PostgREST error codes (PR #6, T-04, 3 fix rounds, #8 to the owner);
  policies re-evaluated outside the real request and a `RAISE LOG`-forged plan accepted (PR #9,
  T-06); redirects set by migration code followed, READ decided from the HTTP body alone
  (PR #10, T-07).
- **How to avoid:** before writing a verdict, list every way code in the attacked target can
  produce the same signal. Accept only evidence from the copy itself (the superuser connection,
  or entries PostgreSQL's C code writes to the server log, correlated to the request); anything
  else exits 2. Test each verdict against a migration written to fake it.
- **Times:** 3 (about 8 defects).
- **Sources:** #2.

## 2. Mutants credited as killed by a crash or by timing

- **What happened:** on PR #9, a kill was timing luck (the log was usually written before it was
  read), and another was counted as killed by a JSON crash. Both hid untested guards.
- **How to avoid:** a mutant table records, for each kill, whether a test asserting the verdict
  failed. Run without `-x`. For a crash kill, write a non-crashing variant and kill that.
- **Times:** 2.
- **Sources:** #2.

## 3. A test double more lenient than the real thing

- **What happened:** on PR #7, `tests/fakedocker.py` accepted `rm` without `-f`, `ps` without
  `-a`, and so on, so tests could not fail where a real daemon would.
- **How to avoid:** for every flag or behaviour the code relies on, the double refuses what the
  real thing refuses, citing the real source. Where the real thing never runs, say so as a gap.
- **Times:** 1.
- **Sources:** #2.

## 4. An in-place mutant runner breaks the worktree when interrupted

- **What happened:** T-05 fix 2: a container restart left a mutant applied in
  `rlsentry/backends/docker.py`.
- **How to avoid:** run every mutant in a throwaway `git worktree` of HEAD, never by editing the
  checkout.
- **Times:** 1.
- **Sources:** #2.

## 5. Tickets in parallel on the same module

- **What happened:** T-05 and T-06 both rewrote `rlsentry/sandbox.py`. T-06's PASS on the old
  base did not cover the merge, which needed its own builder, verifier and design decision.
- **How to avoid:** when planning, give tickets that touch the same module an order, or plan the
  integration as its own step. A PASS covers only the head it judged.
- **Times:** 1.
- **Sources:** #2.

## 6. Builder leftovers outside the worktree

- **What happened:** `/root/rlsentry-mutants3/`, and `/verdicts-docker.txt` from a command that
  lost its `cd`; the safety check would not let them be deleted.
- **How to avoid:** write scratch output only inside the worktree or the session scratchpad,
  with absolute paths.
- **Times:** 2.
- **Sources:** #2.
- **Correct:** none possible at count 2 (task real-docker, trail): the leftovers are written by
  builder sessions outside the repository, where no check in the repository runs.

## Guarded

(none yet)
