# rlsentry roadmap

rlsentry verifies Supabase row-level security by trying access, instead of
warning about configuration. Each line is one task, one pull request into main.
Status: DRAFT, proposed in task `anon-probe`, not yet approved.

1. **anon-probe** — command-line scan of one live project with the anon key:
   per-table read / write verdicts, non-destructive write probe, CI exit code.
   First because the verdict model, report format and write-safety rules are
   what everything after builds on.
2. **ci-local** — run the same scan against a local Supabase started from the
   repository's migrations, so a pull request that opens a table fails before
   it ships. Includes a GitHub Action.
3. **authenticated-probe** — create two throwaway users and check that user A
   cannot read or change user B's rows (the `authenticated` role, `using (true)`
   for logged-in users, missing `auth.uid()` checks).
4. **expectations** — a small file in the user's repo saying which tables are
   meant to be public (e.g. a product catalogue), so intended exposure is not
   reported as a failure.
5. **more-surfaces** — storage buckets and RPC functions callable by anon.
