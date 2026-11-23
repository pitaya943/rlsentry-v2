# Design: anon-probe

Status: DRAFT. The owner moved this task to attack mode (see trail). The attack-mode
design will replace this file. Everything below is kept as **live-probe notes**
for roadmap task 3; its facts F1-F8 still hold.

## 1. Facts this design rests on

Proven by spike `spike/rls-ordering` (commit 57705a2), PostgreSQL 16.15, run as
role `anon` with `SET ROLE`:

| # | Fact | Evidence |
|---|---|---|
| F1 | On INSERT, row-level `WITH CHECK` runs before NOT NULL / constraint checks (`ExecWithCheckOptions` before `ExecConstraints`). A blank row with `pk = null` returns `42501` when the policy rejects it and `23502` when it lets it through. No row is written in either case. | spike.sql cases 1-4 |
| F2 | The same ordering holds for UPDATE. A row anon cannot update at all gives `UPDATE 0`, not an error. | spike3.sql U1-U3 |
| F3 | A missing GRANT gives `42501 permission denied for table`, which is distinguishable from an RLS rejection (`new row violates row-level security policy`). | spike.sql case 5 |
| F4 | An explicit `null` overrides a column default, so `pk = null` fails even when the pk has `default gen_random_uuid()`. | spike.sql case 1 |
| F5 | `GENERATED ALWAYS` identity pk: error `428C9` is raised before RLS, so it tells us nothing. | spike.sql case 6 |
| F6 | **A BEFORE INSERT trigger that fills the pk makes the probe insert succeed. A row is written.** A two-row batch with a duplicate explicit pk stops a trigger that only fills nulls. A trigger that always overwrites the pk defeats both guards. | spike.sql case 7; spike2.sql A, B |
| F7 | `INSERT ... RETURNING` also has to pass the SELECT policy, so a write-only table would look protected. The probe must not ask for the row back. | spike2.sql C, D |
| F8 | **A value-dependent policy (`with check (status = 'pending')`) rejects the blank row but accepts the right value.** A blank-row rejection does not prove anon cannot write. | spike2.sql E |

Not yet proven (PostgREST was not available in the spike session):

| # | Claim the design needs | How to settle it |
|---|---|---|
| P1 | PostgREST maps the Postgres error to a JSON body carrying `code` (`23502`, `42501`, ...). | First ticket: run against real PostgREST |
| P2 | `Prefer: tx=rollback` plus `Prefer: handling=strict` is refused *before* executing when the server does not allow rollback, so asking can never write. | Same |
| P3 | What Supabase's hosted PostgREST is configured to do with `tx=rollback` by default. | Same; then a manual check against a throwaway Supabase project |
| P4 | `GET /rest/v1/` with the anon key returns the OpenAPI description, with pk columns marked. | Same |

If P2 is false, the fallback (B) is dropped and the design still holds.

## 2. Frame

```
cli ──> scanner ──> discovery ──┐
                    read_probe ─┼──> PostgrestClient ──HTTPS──> project /rest/v1
                    write_probe ┘
        scanner ──> report (text | json)        (never sees row values)
```

| Part | Owns | Does not |
|---|---|---|
| `cli` | arguments, exit code | any HTTP |
| `PostgrestClient` | the anon headers, rate limiting, timeouts, turning HTTP into `Response(status, code, message, headers)` | interpret verdicts |
| `discovery` | the table list: name, columns, pk, identity | probe |
| `read_probe` | the READ verdict | keep row values after it returns (only counts and pk values for the update probe, in memory) |
| `write_probe` | the WRITE verdict and **all** mutating requests | no other module may send POST/PATCH/DELETE |
| `report` | rendering | receive row values; its input type has no field for them (S-6) |

One owner for mutation is the main safety property. `PostgrestClient` exposes
`get()` publicly and `mutate()` only to `write_probe`. A test asserts that no
other module calls it.

## 3. Interfaces

```python
class Verdict(Enum):  EXPOSED, PROTECTED, UNKNOWN

@dataclass(frozen=True)
class TableInfo:  name: str; columns: list[str]; pk: list[str]; pk_identity_always: bool

@dataclass(frozen=True)
class ReadResult: verdict: Verdict; visible_rows: int | None; capped: bool; basis: str
@dataclass(frozen=True)
class WriteResult: verdict: Verdict; basis: str; residue: str | None   # see 5.4

@dataclass(frozen=True)
class TableReport: table: TableInfo; read: ReadResult; write: WriteResult

def scan(url: str, anon_key: str, tables: list[str] | None) -> ScanReport
```

`basis` is a short, fixed phrase saying what the verdict rests on, e.g.
`"policy rejected a blank row"`. Exit codes: `0` clean, `1` something EXPOSED,
`2` could not scan (S-9). UNKNOWN alone exits `0` but is listed. **OPEN** (Q3).

## 4. Read probe (S-1, S-2, S-3, S-6, S-7)

`GET /rest/v1/<t>?select=<pk>&limit=1` with `Prefer: count=exact` and `Range: 0-999`
(capped). It selects only the pk, so no row content crosses the wire beyond the key.

| Response | Verdict | basis |
|---|---|---|
| 200, count > 0 | EXPOSED | `N rows visible` (`1000+` when capped) |
| 200, count = 0 | PROTECTED | `no rows visible` (**an empty table that anyone can read looks the same**, see Q2) |
| 401 / 42501 | PROTECTED | `no read permission` |
| other | UNKNOWN | the error code |

## 5. Write probe (S-4, S-5)

### 5.1 Insert, by inference (method A)
Precondition: the table has a pk that is not `GENERATED ALWAYS` (else UNKNOWN, F5).

Request: `POST /rest/v1/<t>` with `Prefer: return=minimal` (F7). The body is a two-row
batch with the same random pk in both rows, every column omitted except the pk set
to `null`... (**OPEN detail**: the duplicate guard (F6) needs an explicit pk, while the
null guard needs `null`. The builder sends `[{pk: null}, {pk: X}, {pk: X}]`. A null
from the first row fails F1. If a trigger fills it, the duplicate X fails. The whole
statement is atomic (spike.sql case 9).)

| Postgres code | Verdict | basis |
|---|---|---|
| 23502 / 23505 | EXPOSED | `row passed the policy, stopped by a constraint` |
| 42501 permission denied | PROTECTED | `no insert permission` |
| 42501 row-level security | PROTECTED* | `policy rejected a blank row` (see Q1, F8) |
| 2xx | EXPOSED + residue | see 5.4 |
| other | UNKNOWN | the code |

### 5.2 Value-shaped retry (proposal for Q1)
Only when the read probe is EXPOSED and the blank row was RLS-rejected: fetch one
visible row (all columns, kept in memory only), set its pk to null, and send that
as the first row of the same guarded batch. This passes a value-based policy
that real rows pass. No value is logged or reported.

### 5.3 Rollback fallback (method B)
Used only when P2 is proven and the project is shown to honour it: the same
guarded batch with `Prefer: tx=rollback, handling=strict`. It covers tables 5.1 cannot
(identity pk, no pk). Otherwise those tables are UNKNOWN.

### 5.4 When a probe row gets through (F6)
A 2xx on a guarded insert means a trigger defeated both guards. The verdict is
EXPOSED, and the report says in plain words that a probe row may now exist,
naming the table and the pk the request carried so the owner can delete it.
This contradicts the brief's S-4 promise as written; see Q4.

### 5.5 Update
Only when the read probe returned at least one pk: `PATCH /rest/v1/<t>?<pk>=eq.<v>`
with body `{pk: null}` and `return=minimal`. `23502` means EXPOSED, `42501` means
PROTECTED, and 0 rows affected means PROTECTED (`policy hides the row from update`)
(F2). Delete is not probed: no constraint makes it fail safely. The report says
`delete: not tested`.

WRITE verdict = the worse of insert and update (EXPOSED > UNKNOWN > PROTECTED).

## 6. Discovery and errors (S-8, S-9)
`GET /rest/v1/` (OpenAPI, P4) gives tables, columns and pk. When it fails or is empty,
the user names tables with `--table` and pk detection falls back to a column called
`id`. 401 / 403 / DNS / TLS failure on the first request gives exit 2 with the reason.

## 7. Proof per scenario

| Scenario | Proven by |
|---|---|
| S-1..S-5, S-7 | Integration tests against real Postgres + PostgREST with the fixture tables from the spike (including the trigger and value-policy tables), asserting verdicts and **row counts before = after** |
| S-6 | A test that seeds a unique marker string in every fixture row and asserts it appears in neither the text nor the JSON output |
| S-8 | JSON schema test |
| S-9 | Test with a wrong key, asserting exit 2 |
| P3 | Manual run against a throwaway hosted Supabase project, recorded |

Test infra: real Postgres 16 and PostgREST v12 in CI (GitHub Actions service
containers); `test_command: pytest` set in this task's PR.

## 8. Open questions for the owner
- **Q1** Blank-row RLS rejection (F8): `protected` with its basis shown, plus the 5.2 retry when readable?
- **Q2** Empty readable table: `protected (no rows visible)`?
- **Q3** Should UNKNOWN fail the run?
- **Q4** S-4 cannot be guaranteed against a pk-overwriting trigger (F6): accept "guarded + residue reported", or make the write probe opt-in?
