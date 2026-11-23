"""Break each T-04 property one edit at a time; run the full suite isolated (T-03's iso.sh),
stopping at the first failure; record which test failed.
Run from anywhere in a checkout, as root: python3 docs/tasks/anon-probe/evidence/T-04-mutants/mutants.py [N ...]"""
import re
import subprocess
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[5]  # the checkout this file is in
ISO = str(Path(__file__).resolve().parents[1] / "T-03-mutants" / "iso.sh")
AT, SB, SD = "rlsentry/attacker.py", "rlsentry/sandbox.py", "rlsentry/seed.py"

MUTANTS = [
    # F1: a 5xx on any operation is exit 2
    ("5xx not caught (>= 600)", AT, "if resp.status >= 500:", "if resp.status >= 600:"),
    # the class: anything but an RLS answer never reads protected
    ("READ: a non-RLS answer reads protected", AT,
     "        raise _unclean(table, Op.READ, [_answer(resp)])",
     "        return OpResult(Op.READ, Outcome.PROTECTED, _answer(resp), None)"),
    ("INSERT: non-RLS answers ignored", AT,
     "        if unclean:\n            raise _unclean(table, Op.INSERT, unclean)",
     "        if False:\n            raise _unclean(table, Op.INSERT, unclean)"),
    ("UPDATE/DELETE: non-RLS answers ignored", AT,
     "        if unclean:\n            raise _unclean(table, op, unclean)",
     "        if False:\n            raise _unclean(table, op, unclean)"),
    ("INSERT: any 4xx counts as RLS's refusal", AT,
     '    return _code(resp) == "42501"', '    return 400 <= resp.status < 500'),
    # F3: not attempted is exit 2
    ("UPDATE with no settable column reads protected", AT,
     '            raise AttackError(f"{table}: UPDATE not attempted: no column anon could set")',
     '            return OpResult(Op.UPDATE, Outcome.PROTECTED, "not attempted", None, tries=0)'),
    ("UPDATE with no differing value reads protected", AT,
     "        if not answers:\n            raise AttackError(",
     "        if False:\n            raise AttackError("),
    ("UPDATE writes values already there", AT,
     "                if body and not self._db.would_change(table, *next(iter(body.items())), target):",
     "                if False:"),
    # F4: unique columns last
    ("UPDATE: column order ignores unique", AT,
     "order = sorted(values, key=lambda c: (c in key, c in unique))",
     "order = sorted(values, key=lambda c: (c in key,))"),
    # FK-409 delete
    ("DELETE: no retry without referencing rows", AT,
     "                        and self._db.detach_references(table)):",
     "                        and False):"),
    # CHECK-rejected / unique-colliding insert
    ("INSERT: no room made on a unique collision", AT,
     "            if self._db.make_room(table, constraint, row):", "            if False:"),
    # value search (S-5)
    ("no value search", AT, "        for source, change in [(None, {})] + self._candidates(table, base):",
     "        for source, change in [(None, {})]:"),
    ("no bound on value search", AT, "            if tried == MAX_INSERT_ROWS:", "            if False:"),
    ("source not named in evidence", AT, '                    evidence["source"] = source\n', ""),
    ("no policy constants", AT, '            pairs = [(c, v) for s, c, v in sources if s == source]',
     '            pairs = [(c, v) for s, c, v in sources if s == source and s != "policy"]'),
    ("no CHECK constants", AT, '            pairs = [(c, v) for s, c, v in sources if s == source]',
     '            pairs = [(c, v) for s, c, v in sources if s == source and s != "check"]'),
    ("no enum labels", AT, '            pairs = [(c, v) for s, c, v in sources if s == source]',
     '            pairs = [(c, v) for s, c, v in sources if s == source and s != "enum"]'),
    ("no seeded values", AT, '            pairs = [(c, v) for s, c, v in sources if s == source]',
     '            pairs = [(c, v) for s, c, v in sources if s == source and s != "seeded"]'),
    ("no null", AT, '            pairs = [(c, v) for s, c, v in sources if s == source]',
     '            pairs = [(c, v) for s, c, v in sources if s == source and s != "null"]'),
    ("no all-columns-at-once candidate", AT,
     "                changes.insert(0, {c: v for c, v in reversed(pairs)})", "                pass"),
    ("numbers: no n+1", SB, "numbers += [str(v), str(v + 1), str(v - 1)]", "numbers += [str(v), str(v - 1)]"),
    ("policies of other commands used", SB, " and tablename = %s and cmd in ('INSERT', 'ALL')\"",
     " and tablename = %s\""),
    # host safety: migration-authored code never runs as the superuser
    ("migrations run as the superuser", SB,
     '            with psycopg.connect(host="127.0.0.1", port=port, user="postgres", dbname="postgres",',
     '            with psycopg.connect(host="127.0.0.1", port=port, user=SUPERUSER, dbname="postgres",'),
    ("postgres role is a superuser", SB, "create role postgres login createrole bypassrls;",
     "create role postgres login superuser;"),
    ("seeding on the superuser's connection", SB,
     '        seeded = seed(self._app, [("public", t) for t in self.tables])',
     '        seeded = seed(self._conn, [("public", t) for t in self.tables])'),
    ("restore on the superuser's connection", SB,
     "        with self._app.transaction():\n            # replica: no FK checks or triggers while the tables are briefly empty\n            self._app.execute(\"set local session_replication_role = replica\")",
     "        with self._conn.transaction():\n            # replica: no FK checks or triggers while the tables are briefly empty\n            self._conn.execute(\"set local session_replication_role = replica\")"),
    ("superuser connection searches public", SB, '                                   options="-c search_path=pg_catalog")',
     '                                   )'),
    ("no default grants on postgres's tables", SB,
     "alter default privileges for role postgres in schema public grant all on tables to anon, authenticated, service_role;\n", ""),
    ("postgres cannot create roles", SB, "create role postgres login createrole bypassrls;",
     "create role postgres login bypassrls;"),
    ("postgres does not bypass RLS", SB, "create role postgres login createrole bypassrls;",
     "create role postgres login createrole;"),
    ("pg_stat_statements not installed", SB, "create extension pg_stat_statements with schema extensions;\n", ""),
    ("postgres has no rights on auth.users", SB, "grant all on auth.users to postgres;\n", ""),
    ("postgres cannot create in public", SB, "grant all on schema public to postgres;\n", ""),
    ("one search path: PostgREST's dropped", SB,
     "            f'db-extra-search-path = \"{SCHEMAS_ON_PATH}\"\\n'\n", ""),
]


def main(only=None):
    for i, (desc, rel, old, new) in enumerate(MUTANTS, 1):
        if only and i not in only:
            continue
        path = WT / rel
        src = path.read_text()
        assert src.count(old) == 1, f"M{i} {desc}: pattern found {src.count(old)} times"
        try:
            path.write_text(src.replace(old, new))
            run = subprocess.run([ISO, "python3", "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                                  "-rfE"], capture_output=True, text=True, timeout=1800)
            failed = [l.split(" ")[1] for l in run.stdout.splitlines()
                      if l.startswith(("FAILED", "ERROR"))]
            counts = [l for l in run.stdout.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
            summary = counts[-1].strip("= ") if counts else run.stderr[-200:]
            if not failed:
                summary = "SURVIVED: " + summary
            print(f"M{i:02d} {desc}\n     {summary}")
            for f in failed[:3]:
                print(f"       {f}")
            sys.stdout.flush()
        finally:
            path.write_text(src)


if __name__ == "__main__":
    main({int(a) for a in sys.argv[1:]} or None)
