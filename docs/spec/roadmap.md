# rlsentry roadmap

rlsentry is a research and teaching tool that verifies Supabase row-level
security by attacking it as an anonymous visitor would, instead of warning about
configuration. Each line is one task, one pull request into main.
Approved by the owner with the `anon-probe` brief (brief-approved at 0186693).

The later tasks have no approved scenarios yet: each one's brief writes them, so
no area lists a Not yet built section.

1. **anon-probe** (attack mode) — a user points rlsentry at a project's
   migrations (or the bundled lab) and gets, per table and operation, what an
   anonymous visitor really read, inserted, updated or deleted in a throwaway
   copy, with evidence; live targets are refused. Pull request into main:
   [#10](https://github.com/pitaya943/rlsentry-v2/pull/10).
2. **lovable-target** — the owner builds an app in Lovable the way an
   inexperienced user would (prompt recorded for reproducibility); its
   migrations become a lab target; a write-up of what rlsentry finds. Owner
   does the Lovable part by hand.
3. **live-probe** — non-destructive probing of a live project with the anon
   key (constraint-violation inference; design and spike evidence from
   `anon-probe`'s `live-probe-notes.md` and `spike/rls-ordering`).
4. **authenticated-attack** — two throwaway users in the copy; user A against
   user B's rows.
5. **ci-gate** — GitHub Action running attack mode on a pull request's
   migrations.
6. **more-surfaces** — storage buckets and RPC functions callable by anon.

Order after anon-probe: kept. Nothing in anon-probe showed a later task needs
another first. Two things it found bear on the next tasks without re-ordering
them:
- **lovable-target** will run on real app migrations, where anon-probe stops
  with exit 2 on what it does not build: a `storage` schema, domain-typed NOT
  NULL columns, and it does not attack views. Each of these, if the Lovable app
  uses it, becomes part of that task's scope rather than a reason to move
  `more-surfaces` earlier.
- **live-probe** inherits an open question: whether hosted Supabase refuses
  unfiltered UPDATE/DELETE (pg-safeupdate), which is the only route by which
  anon-probe finds write-only policies (PR #4 verdict, F6).
