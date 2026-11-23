# rlsentry roadmap

rlsentry is a research and teaching tool that verifies Supabase row-level
security by attacking it as an anonymous visitor would, instead of warning about
configuration. Each line is one task, one pull request into main.
Status: DRAFT, proposed in task `anon-probe`, not yet approved.

1. **anon-probe** (attack mode) — build a throwaway copy from a project's
   migrations, really read / insert / update / delete as anon, report with
   evidence; ships a lab of vulnerable demo schemas. First because the verdict
   model, the live-target guard and the throwaway copy are what everything after
   builds on.
2. **lovable-target** — the owner builds an app in Lovable the way an
   inexperienced user would (prompt recorded for reproducibility); its
   migrations become a lab target; a write-up of what rlsentry finds. Owner
   does the Lovable part by hand.
3. **live-probe** — non-destructive probing of a live project with the anon
   key (constraint-violation inference; design and spike evidence from
   `anon-probe` design §live-probe notes and `spike/rls-ordering`).
4. **authenticated-attack** — two throwaway users in the copy; user A against
   user B's rows.
5. **ci-gate** — GitHub Action running attack mode on a pull request's
   migrations.
6. **more-surfaces** — storage buckets and RPC functions callable by anon.
