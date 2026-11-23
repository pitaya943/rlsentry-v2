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
     "        if unclean or not last:  # protected rests", "        if not last:  # protected rests"),
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
    ("UPDATE: no other column after a 409", AT,
     "                unclean.append(answers[-1])\n", "                unclean.append(answers[-1])\n                break\n"),
    ("UPDATE: key columns not last", AT,
     "        bodies = [{c: values[c]} for c in sorted(values, key=lambda c: c in key)]",
     "        bodies = [{c: values[c]} for c in sorted(values, key=lambda c: c not in key)]"),
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
    ("restore on the superuser's connection", SB, "    def restore(self) -> None:\n",
     "    def restore(self) -> None:\n        self._app, self._conn = self._conn, self._app\n"
     "        try:\n            return self._restore()\n        finally:\n"
     "            self._app, self._conn = self._conn, self._app\n\n    def _restore(self) -> None:\n"),
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
    # fix round 1 (PR #6 verdict D1-D3, Findings 1-2); G and H are the verifier's
    ("G: policies for any role used", SB, " and roles && array['anon', 'public']::name[] and permissive",
     " and permissive"),
    ("H: detach: self-references skipped", SB, "                if itself:\n", "                if itself:\n                    continue\n"),
    ("candidates not checked against the column's type", SB,
     "        try:\n            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL(\"select %s::{}\")",
     "        return True\n        try:\n            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL(\"select %s::{}\")"),
    ("column names matched inside string literals", SB,
     """                             + re.escape(name.replace('"', '""')) + '"', code):""",
     """                             + re.escape(name.replace('"', '""')) + '"', term):"""),
    ("a candidate the column cannot hold (22xxx) is unclean", AT,
     '            if str(_code(resp)).startswith("22") and not self._db.holds(table, row):',
     '            if False:'),
    ("2xx insert that wrote nothing reads EXPOSED", AT,
     "            if 200 <= resp.status < 300 and not created:  # e.g. a trigger returned null",
     "            if False:"),
    ("seeding that kept no row gives no reason", SD, "    if inserted and not rows:\n", "    if False:\n"),
    ("delete compares with the rows before the references were cleared", AT,
     "                    before = self._db.rows(table)  # references cleared: compare with that\n", ""),
    # fix round 2 (PR #6 verdict D4), and the verifier's i and j from that verdict
    ("any 22xxx is a rejected candidate (no check that the value is what failed)", AT,
     '            if str(_code(resp)).startswith("22") and not self._db.holds(table, row):',
     '            if str(_code(resp)).startswith("22"):'),
    ("protected without any answer from RLS", AT,
     "        if unclean or not last:  # protected rests", "        if unclean:  # protected rests"),
    ("i: CHECK constants not checked against the column's type", SB,
     """            out += [("check", c, v) for c, v in _constants(expr, columns)
                    if self._fits(columns[c][0], v)]""",
     """            out += [("check", c, v) for c, v in _constants(expr, columns)]"""),
    ("j: insert evidence is the row sent", AT, '                evidence = {"row": created[0]}',
     '                evidence = {"row": row}'),
    # fix round 3 (PR #6 verdict D5, D6; the verifier's h1-h10, h3 = M45)
    ('h1: holds() always False', SB, '        try:\n            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")',
     '        return False\n        try:\n            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")'),
    ('h2: holds() always True', SB, '        try:\n            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")',
     '        return True\n        try:\n            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")'),
    ('h4: holds() commits', SB, '        try:\n            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")',
     '        try:\n            with self._app.transaction():\n                self._app.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")'),
    ('h5: holds() as superuser', SB, '        try:\n            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")',
     '        try:\n            with self._conn.transaction(force_rollback=True):\n                self._conn.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")'),
    ("h6: holds() replaced by 'the row is a candidate'", AT, 'and not self._db.holds(table, row):',
     'and source is not None:'),
    ('h7: _fits as superuser', SB, '            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL("select %s::{}").format(sql.SQL(typ)), [value])',
     '            with self._conn.transaction(force_rollback=True):\n                self._conn.execute(sql.SQL("select %s::{}").format(sql.SQL(typ)), [value])'),
    ('_fits commits', SB, '            with self._app.transaction(force_rollback=True):\n                self._app.execute(sql.SQL("select %s::{}").format(sql.SQL(typ)), [value])',
     '            with self._app.transaction():\n                self._app.execute(sql.SQL("select %s::{}").format(sql.SQL(typ)), [value])'),
    ('h8: would_change as superuser', SB, "        with self._app.transaction(force_rollback=True):  # a cast can run a domain's CHECK\n            return self._app.execute(",
     "        with self._conn.transaction(force_rollback=True):  # a cast can run a domain's CHECK\n            return self._conn.execute("),
    ('would_change commits', SB, "        with self._app.transaction(force_rollback=True):  # a cast can run a domain's CHECK\n            return self._app.execute(",
     "        with self._app.transaction():  # a cast can run a domain's CHECK\n            return self._app.execute("),
    ('h9: fake_row as superuser', SB, 'return fake_row(self._app, "public", table)',
     'return fake_row(self._conn, "public", table)'),
    ('h10: update_values as superuser', SB, 'return update_values(self._app, "public", table)',
     'return update_values(self._conn, "public", table)'),
    ('as_anon as superuser', SB, '            with self._app.transaction(force_rollback=True):\n                self._app.execute("set local session_replication_role = replica")\n                self._app.execute("set local role anon")\n                self._app.execute("select set_config(\'request.jwt.claims\', %s, true)",\n                                  [json.dumps({"role": "anon", "iss": "rlsentry"})])\n                return None, self._app.execute(statement, params).rowcount',
     '            with self._conn.transaction(force_rollback=True):\n                self._conn.execute("set local session_replication_role = replica")\n                self._conn.execute("set local role anon")\n                self._conn.execute("select set_config(\'request.jwt.claims\', %s, true)",\n                                  [json.dumps({"role": "anon", "iss": "rlsentry"})])\n                return None, self._conn.execute(statement, params).rowcount'),
    ('make_room as superuser', SB, '        with self._app.transaction():\n            self._app.execute("set local session_replication_role = replica")  # no cascades\n            cur = self._app.execute(',
     '        with self._conn.transaction():\n            self._conn.execute("set local session_replication_role = replica")  # no cascades\n            cur = self._conn.execute('),
    ('no statement timeout on the postgres connection', SB, 'options=f"-c statement_timeout={STATEMENT_TIMEOUT}")',
     ')'),
    ('D5: a 42501 trusted without sending it again', AT, '            return state == "42501"',
     '            return True'),
    ('D5: a 2xx that changed nothing trusted without sending it again', AT, '            return state in (None, "42501") and changed == 0',
     '            return True'),
    ('D5: the write sent again with the triggers on', SB, '                self._app.execute("set local session_replication_role = replica")\n                self._app.execute("set local role anon")',
     '                self._app.execute("set local role anon")'),
    ('D5: the write sent again as postgres, not anon', SB, '                self._app.execute("set local role anon")\n',
     ''),
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
