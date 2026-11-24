# The lab

A set of deliberately vulnerable demo tables shipped with rlsentry, so anyone can run it and see
each kind of verdict without a project of their own.

## Scenarios

### Attack the lab

Given rlsentry installed,
when the user runs `rlsentry attack --lab`,
then the copy is built from `rlsentry/lab/001_lab.sql`, the report shows the verdicts below,
ending `9 exposed operation(s) in 8 table(s).`, and the command exits 1. On the local backend
it took about 2.3 s here.

| Table | The mistake it shows | READ | INSERT | UPDATE | DELETE |
|---|---|---|---|---|---|
| `lab_rls_off` | RLS never enabled | EXPOSED | EXPOSED | EXPOSED | EXPOSED |
| `lab_using_true` | `for select to anon using (true)` | EXPOSED | protected | protected | protected |
| `lab_insert_only` | `for insert to anon with check (true)` | protected | EXPOSED | protected | protected |
| `lab_update_open` | `for update to anon using (true)`, no read policy | protected | protected | EXPOSED (without a filter) | protected |
| `lab_delete_open` | `for delete to anon using (true)`, no read policy | protected | protected | protected | EXPOSED (without a filter) |
| `lab_value_policy` | `with check (status = 'pending')`, status defaults to `'draft'` | protected | EXPOSED (value search, source `policy`) | protected | protected |
| `lab_owner_only` | correct `auth.uid() = user_id` policies (done right) | protected | protected | protected | protected |
| `lab_no_policy` | RLS on, no policy | protected | protected | protected | protected |

### Get the lab report as JSON

Given rlsentry installed,
when the user runs `rlsentry attack --lab --json`,
then each table's outcomes are exactly those in `rlsentry/lab/expected.json`.

## Rules

- `rlsentry/lab/expected.json` holds the expected outcome of every lab table and operation. The
  test suite asserts the report matches it exactly, on the local backend and on the stand-in
  Docker daemon, and pins the whole text report; it is the regression suite for every verdict
  kind (anon-probe, T-01, T-04).
- Each lab table is named for the mistake it demonstrates, and the SQL comment above it says
  what that mistake is (anon-probe, T-01, T-02, T-04).
- `lab_update_open` and `lab_delete_open` are exposed only by a write without a filter, because
  they have no read policy. Hosted Supabase may refuse unfiltered writes (pg-safeupdate); this
  was not checked, as it would mean touching a live project (anon-probe, T-02).

## Last changed by

anon-probe (T-01, T-02, T-04).
