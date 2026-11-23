# Design: anon-probe (attack mode)

Status: DRAFT, in discussion with the owner. Decisions still open are marked **D-n**.
Brief: `brief.md` (approved at 0186693). Earlier live-probe research: `live-probe-notes.md`.

## 1. Frame

```
cli ─> run(source) ─> Sandbox.build(migrations | lab)        owns: the copy's lifetime
                       │   postgres + REST layer on 127.0.0.1:<random port>
                       │   Supabase roles + auth stand-in, migrations applied, fake rows
                       ▼
                     Attacker(sandbox.anon_channel())         owns: every attacking request
                       │   per table: read, insert, update, delete, value search
                       ▼
                     Findings ─> report (text | json) ─> exit code
                     Sandbox.teardown()  (always: finally + signal handler + stale sweep)
```

| Part | Owns | Never |
|---|---|---|
| `cli` | arguments, exit code | builds or attacks anything itself |
| `sandbox` | starting, seeding and destroying the copy; the superuser connection | hands its superuser connection to the attacker |
| `attacker` | all requests made as anon; verdicts | sees a URL or credentials that the sandbox did not create |
| `seed` | the fake rows (from column types, constraints, enums) | runs as anon |
| `report` | rendering findings | decides verdicts |

## 2. The live-target guard (S-7, critical)

The guard is structural, not a check that could be skipped:

- `Attacker` takes an `AnonChannel`. The only constructor of `AnonChannel` is
  `Sandbox.anon_channel()`, and only a `Sandbox` that has reached the `running` state
  can call it. No code path turns a user-supplied URL into a channel.
- The channel's address is `127.0.0.1:<port>` and the port belongs to a process the
  sandbox started. Before the first attacking request, the channel reads a per-run
  nonce table (`rlsentry_run.nonce`, created by the sandbox as superuser, readable only
  by superuser) through the sandbox's own superuser connection, on the same port. If
  the nonce is missing or different, the run aborts with exit 2.
- `--target <url>` exists only so the refusal in S-7 has a clear message. It is parsed,
  refused, and nothing is sent.
- A test greps the source tree. Only `sandbox.py` may construct `AnonChannel`, and
  `attacker.py` must import no HTTP client except through the channel.

## 3. Sandbox (S-6, S-8)

Build steps:
1. Start PostgreSQL 16 and the REST layer (**D-1**).
2. As superuser, create the Supabase roles (`anon`, `authenticated`, `service_role`,
   `authenticator`). Apply Supabase's default privileges: new tables in `public` are granted
   to `anon` and `authenticated`. That default is what makes RLS-off tables exposed.
3. Install the auth stand-in: schema `auth`, table `auth.users (id uuid pk, email, ...)`,
   and functions `auth.uid()`, `auth.role()`, `auth.jwt()` reading `request.jwt.claims`.
   This matches how Supabase defines them. Extensions `pgcrypto` and `uuid-ossp`.
4. Apply migrations in filename order, each in its own transaction. On error: name the
   file, the statement and the missing object (`schema "storage" does not exist`),
   tear down, exit 2 (S-6).
5. Seed fake rows (`seed`): 5 per table, in foreign-key order, including
   `auth.users`. Values come from type, CHECK, enum and FK targets. Rows the generator
   cannot satisfy for a table are skipped and noted in the report.
6. Write the nonce and switch to `running`.

Teardown (S-8): every process/container gets the label `rlsentry.run=<id>`.
Teardown runs in `finally`, on SIGINT/SIGTERM, and at the start of every run as a
sweep of stale labelled resources. That last one covers `kill -9`.

## 4. Attacker (S-1..S-5)

Requests go through the REST layer with an anon JWT signed by the sandbox's per-run
secret, the same path a browser holding the anon key takes.

| Operation | Attack | EXPOSED when | Evidence |
|---|---|---|---|
| read | `GET /<t>?select=*` | ≥1 row returned | count + first row |
| insert | `POST /<t>` with a fresh fake row | 2xx | the row created |
| update | `PATCH /<t>?<pk>=eq.<seeded pk>` changing one non-key column | ≥1 row changed (checked afterwards as superuser) | before/after |
| delete | `DELETE /<t>?<pk>=eq.<seeded pk>` | row gone (checked as superuser) | the deleted pk |

Update and delete success is confirmed through the superuser connection, not the
REST layer's response. RLS can make an update silently affect 0 rows, and the
response alone cannot tell "denied" from "no match".

Each operation runs against a fresh state: the sandbox restores the table after each
destructive attempt (snapshot via `CREATE TABLE ... AS` before, swap back after), so one
operation's success cannot hide another's.

Value search (S-5): when insert was rejected by a policy (`42501` row-level security),
try up to 50 candidate rows (brief default). Candidates combine (a) seeded values,
(b) constants appearing in that table's policy expressions and CHECK constraints, read
from `pg_policies` / `pg_constraint` by the sandbox, (c) enum labels, (d) `null`. On
the first 2xx: EXPOSED, evidence = the accepted row. Otherwise: `protected (N rows tried)`.

(b) uses white-box knowledge an outside attacker would not have. It is acceptable
here because it only speeds up finding a row an attacker could also find by guessing.
The report says which candidate source succeeded.

## 5. Lab (S-9)

`rlsentry/lab/*.sql`, written by us. Each table is named for what it demonstrates:

| Table | Mistake | Expected |
|---|---|---|
| `lab_rls_off` | RLS never enabled | read, insert, update, delete EXPOSED |
| `lab_using_true` | `for select using (true)` | read EXPOSED |
| `lab_insert_only` | `for insert with check (true)` | insert EXPOSED only |
| `lab_update_open` | `for update using (true)` | update EXPOSED (+ read if a select policy exists) |
| `lab_delete_open` | `for delete using (true)` | delete EXPOSED |
| `lab_value_policy` | `with check (status = 'pending')` | insert EXPOSED via value search |
| `lab_owner_only` | correct `auth.uid() = user_id` policies | all protected |
| `lab_no_policy` | RLS on, no policies | all protected |

The lab's expected verdicts live next to it as `expected.json`. The integration
test asserts that the report matches it exactly. That test is S-9's proof and the
regression suite for every verdict.

## 6. Interfaces

```python
class Op(Enum): READ, INSERT, UPDATE, DELETE
class Outcome(Enum): EXPOSED, PROTECTED

@dataclass(frozen=True)
class OpResult: op: Op; outcome: Outcome; basis: str; evidence: dict | None; tries: int = 1
@dataclass(frozen=True)
class TableFinding: schema: str; table: str; results: dict[Op, OpResult]; notes: list[str]
@dataclass(frozen=True)
class RunReport: source: str; findings: list[TableFinding]; started_at: str; rlsentry_version: str

def run(source: MigrationsDir | Lab) -> RunReport     # raises BuildError -> exit 2
```

Exit codes: 0 nothing exposed, 1 something exposed, 2 could not build or attack (S-10).
JSON = `RunReport` as is; its schema is checked in a test (S-10).

## 7. Proof per scenario

| Scenario | Proof |
|---|---|
| S-1..S-5, S-9 | Integration: run on the lab, compare to `expected.json` (fails today: there is no code) |
| S-6 | Integration: a migrations folder using `auth.uid()` and `references auth.users` builds; one using `storage.buckets` exits 2 naming `storage` |
| S-7 | Unit: `--target https://x.supabase.co` exits 2 with no socket opened (a socket-level guard in the test) + the source-tree test from §2 |
| S-8 | Integration: send SIGINT mid-run, then assert no labelled process/container is left; run once with an injected build failure, same assertion |
| S-10 | JSON schema test; exit-code tests for each of 0/1/2 |

## 8. Decisions (owner, 2026-11-23)

- **D-1 How the copy runs: two backends behind one `Backend` interface.**
  `docker` (default): images `postgres:16` and `postgrest/postgrest:v12.2.3`, pinned.
  `local`: `postgres` / `initdb` / `pg_ctl` and `postgrest` found on PATH or under
  `/usr/lib/postgresql/<v>/bin`. When run as root, the local backend runs the server
  as an unprivileged OS user (PostgreSQL refuses root), with its data directory under
  that user's temp directory. `--backend auto` tries docker and falls back to local.
  The test suite runs on `local` and also runs on `docker` when a daemon answers.
  The unattended environment has no running Docker daemon and Docker Hub rate-limits
  anonymous pulls (429 seen).
- **D-2 Attacks go through the REST layer** (PostgREST) with an anon JWT. Never SQL
  `SET ROLE` for an attack. SQL is only for the sandbox's own setup and checks.
- **D-3 White-box value candidates allowed** (§4 b). The report names the candidate
  source that succeeded.

Environment fact (2026-11-23): PostgreSQL 16 is preinstalled in the cloud image;
PostgREST is not. The PostgREST release asset is reachable over the network.
