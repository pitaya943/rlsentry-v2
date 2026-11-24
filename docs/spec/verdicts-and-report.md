# Verdicts and the report

For every table and every operation, rlsentry gives a verdict that rests on a real request made
as anon, and prints it with its basis and evidence, as text or JSON, with an exit code a script
can act on.

## Scenarios

### A table anyone can read is caught

Given a table with RLS off (Supabase's default grants give anon everything),
when the user runs the attack,
then the report marks it `READ: EXPOSED - anon read 5 row(s)` with the count and the first row
as evidence, and the command exits 1. Its `INSERT`, `UPDATE` and `DELETE` are `EXPOSED` too,
each with the row it created, the row before and after, or the deleted key.

### "RLS on but wrong" is caught

Given a table with RLS on and a policy `for select to anon using (true)`,
when the user runs the attack,
then it is marked `READ: EXPOSED`, and the operations no policy allows are `protected`.

### A protected table is not a false alarm

Given a table with RLS on and no policy for anon, or policies that check the row's owner
(`auth.uid() = user_id`),
when the user runs the attack,
then all four operations are `protected`, each basis says what refused it (`anon has no INSERT
policy on ...`, or `refused by anon's UPDATE policies on ...: "owner edits"`), and if no table
has anything exposed the command exits 0.

### Each write operation is tried for real

Given a table anon may insert into but not update or delete,
when the user runs the attack,
then the report marks `INSERT: EXPOSED` with the row it created, read back as superuser, and
`UPDATE: protected`, `DELETE: protected`, each confirmed by the superuser seeing no row changed.
The same holds for a table that only allows update, or only delete.

### A write-only policy is found without a filter

Given a table whose only policy lets anon update (or delete) any row, with no read policy,
when the user runs the attack,
then the write by primary key reaches no row (a filter needs a SELECT policy too), and the
write without a filter changes every row; the report marks `UPDATE: EXPOSED - anon changed 5
row(s) with PATCH without a filter` (or `DELETE: EXPOSED ...`).

### A policy that accepts only chosen values is caught

Given a table whose insert policy accepts only rows with a particular value (for example
`with check (status = 'pending')`, while the column defaults to `'draft'`),
when the user runs the attack,
then the first row is refused, value search tries rows built from the table's own definitions,
and the report marks `INSERT: EXPOSED`, naming the row number, the value and its source
(`row 2 of the value search, with status = "pending" from the insert policy's constants`), with
the accepted row and `"source": "policy"` as evidence.

### Nothing value search tries is accepted

Given a table whose insert policy accepts nothing anon can send,
when the user runs the attack,
then the report marks `INSERT: protected (N rows tried)`, N at most 50.

### A refusal that is not row-level security's never reads protected

Given a write refused by something other than RLS or a grant: a CHECK or domain CHECK, a
trigger (even one raising error 42501 with RLS's exact message), a unique or foreign key, a
policy or trigger that raises an error, or a 2xx that wrote nothing,
when the user runs the attack,
then rlsentry clears the way and tries again where it can (removes the seeded row an accepted
insert collides with on a unique key; removes the rows referencing a row whose delete a foreign
key stopped; tries the next column after a refused update), and the verdict is `EXPOSED` if a
write then lands. Otherwise the run stops with exit 2, naming the table and operation:
`... got no answer from row-level security, so it is neither exposed nor protected (...)`.

### Row-level security refuses while the table's own code also runs

Given a table whose policy refuses anon's write, with ordinary triggers that shape the row, or a
trigger that writes to another table whose RLS refuses that row,
when the user runs the attack,
then the operation is `protected`, and the basis names the policy, or the other table
(`row-level security on table "audit" refuses the row posts writes there`).

### A missing grant reads protected

Given a table whose privileges anon lacks for an operation (the grant revoked),
when the user runs the attack,
then that operation is `protected`, and the basis names the missing grant.

### Get the report as JSON

Given any run that completes,
when the user adds `--json`,
then they get one record per table with `schema`, `table`, `notes` and, per operation, `op`,
`outcome`, `basis`, `evidence` (or null) and `tries`, plus the run's `source`, `started_at` and
`rlsentry_version`. The output validates against `rlsentry/report.schema.json`.

### Use the exit code

Given any run,
when it ends,
then the exit code is `0` if nothing is exposed, `1` if any operation on any table is exposed,
and `2` if the copy could not be built or attacked, the target was refused, the run was
interrupted, or something failed unexpectedly (`the run failed unexpectedly (Type: message);
the copy was torn down`, no traceback).

## Rules

- **READ** is `GET /<table>?select=*`. `EXPOSED` if at least one row comes back; `protected` if
  0 rows, or a 42501 refusal. Evidence: the count and the first row (anon-probe, T-01).
- **INSERT** first sends a fresh fake row unlike every seeded one. `EXPOSED` only if the
  superuser then sees a new row; the evidence is that row as stored, not the row sent
  (anon-probe, T-02, T-04).
- **Value search** runs after any refused first insert. Candidates, in order: the constants that
  anon's permissive INSERT (or ALL) policies compare a column with (all such columns at once,
  then one at a time), CHECK constants, enum labels, values in the seeded rows, and null for
  nullable columns. A constant goes only to a column named in its own AND/OR term, and only if
  that column's type can hold it (an explicit cast). At most 50 rows per table, the first row
  included. White-box on purpose: it only finds sooner what an attacker could find by guessing
  (design D-3; anon-probe, T-04).
- A refused candidate whose values the table's row type cannot hold (a 22xxx answer, checked by
  reading the row into the row type with no trigger or policy) counts toward the rows tried and
  is no answer either way (anon-probe, T-04).
- **UPDATE** sets one column at a time to a value the target row does not hold: columns with a
  default included, identity and generated columns never, key columns last. It goes first by the
  first seeded row's primary key, then without a filter. There is no value search for UPDATE
  (anon-probe, T-02, T-04).
- **DELETE** goes by the first seeded row's primary key, then without a filter (anon-probe,
  T-02).
- UPDATE and DELETE are `EXPOSED` only when the superuser sees rows changed or gone afterwards;
  the REST answer alone never decides. Evidence: the row before and after, or the number of rows
  deleted and the first one's key (anon-probe, T-02).
- **protected for a write** needs all of: the refusal is a 42501, or a 2xx UPDATE/DELETE that
  changed nothing; PostgreSQL's own account of that very request says row-level security's
  WITH CHECK (`ExecWithCheckOptions`) or a missing grant (`aclcheck_error`) refused it, or that
  the write's plan reached no row while target rows exist; and rlsentry's own evaluation of
  anon's policies (permissive OR'd, restrictive AND'd, for `anon` and PUBLIC, under the claims
  and request settings PostgREST made) agrees. If any part is missing or they disagree, the run
  stops with exit 2. rlsentry's own evaluation can take a `protected` away, never give one
  (anon-probe, T-06).
- A write refused by RLS on another table, inside a trigger of the attacked table, is
  `protected`, naming that table. A nested UPDATE refused by another table's WITH CHECK stops the
  run instead (anon-probe, T-06).
- An unfiltered UPDATE whose policy refuses some new rows but not others is `protected` when the
  write goes through with only those rows dropped; otherwise exit 2 (anon-probe, T-06).
- A 5xx from the REST layer, an operation that could not be attempted (no column to set, no fake
  row), and an operation with only unclean answers all stop the run with exit 2, naming the
  table and operation (anon-probe, T-01, T-04).
- Each write operation starts from the seeded state: after every INSERT, UPDATE and DELETE
  attempt, every table is put back from a snapshot taken after seeding. Sequences are not put
  back, so ids in evidence can skip numbers (anon-probe, T-02, T-06).
- The text report lists tables by name; per operation one line `OP: verdict - basis`, an
  `evidence:` line for `EXPOSED`, `(N rows tried)` after `INSERT: protected`, the table's seeding
  note, and a last line `N exposed operation(s) in M table(s).` (anon-probe, T-01, T-04).
- The report goes to standard output; messages and errors to standard error. When the run stops
  with exit 2, no report is printed (anon-probe, T-01).

## Last changed by

anon-probe (T-01, T-02, T-04, T-06).
