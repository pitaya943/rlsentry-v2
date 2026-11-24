"""Break each T-06 property one edit at a time, each on a throwaway copy of this checkout (never
the checkout itself), and run the full suite there isolated by T-03's iso.sh, stopping at the
first failure. Run as root from anywhere: python3 .../T-06-mutants/mutants.py [N ...]
Copies go under $MUTANT_DIR (default ~/rlsentry-mutants; not /tmp, which iso.sh replaces)."""
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

WT = Path(__file__).resolve().parents[5]  # the checkout this file is in
ISO = "docs/tasks/anon-probe/evidence/T-03-mutants/iso.sh"
AT, SB, CH = "rlsentry/attacker.py", "rlsentry/sandbox.py", "rlsentry/channel.py"
ORACLE = ("    def rls_refusal(", "    def _oid(")  # the oracle's methods, for edits across them

MUTANTS = [
    # D9 v1, v5, v6 (PR #6 verdict), as edits to the oracle that replaced the resend
    ("v1: no JWT claims", CH,
     '            "request.jwt.claims": json.dumps(claims, separators=(",", ":"), sort_keys=True),\n', ""),
    ("v5: no answer from the oracle (an error) counts as RLS's", SB,
     "        except psycopg.Error:\n            return None", "        except psycopg.Error:\n            return 'error'"),
    ("v6a: a 2xx that changed nothing is never asked about", AT,
     "        if _refused(resp) or (200 <= resp.status < 300 and op is not Op.INSERT):",
     "        if _refused(resp):"),
    ("v6b: no row reached is not RLS's answer", SB,
     '                        return f"row-level security lets it reach no row ({using.describe()})"',
     "                        return None"),
    # where and how the oracle runs
    ("oracle on the superuser connection", SB, "self._app.", "self._conn.", ORACLE),
    ("oracle commits", SB, "transaction(force_rollback=True)", "transaction()", ORACLE),
    ("oracle not as anon", SB, '        self._app.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))\n'
     '        self._app.execute("select set_config(\'search_path\'', '        self._app.execute("select set_config(\'search_path\''),
    ("claims without exp", CH,
     '        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))\n',
     '        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))\n        claims.pop("exp")\n'),
    ("no request.* settings", SB, "        for name, value in settings.items():", "        for name, value in []:"),
    ("no request.method", CH, '            "request.method": method,\n', ""),
    ("no request.path", CH, '            "request.path": "/" + urllib.parse.quote(table),\n', ""),
    ("no request.headers", CH,
     '            "request.headers": json.dumps({k.lower(): v for k, v in self._headers(_data(body)).items()}),\n', ""),
    ("no request.cookies", CH, '            "request.cookies": "{}",\n', ""),
    ("not PostgREST's search_path", SB,
     '        self._app.execute("select set_config(\'search_path\', %s, true)", [POSTGREST_SEARCH_PATH])\n', ""),
    ("headers not the ones sent", CH, '            "User-Agent": "rlsentry",\n', ""),
    # how policies combine
    ("restrictive policies OR'd", SB,
     "            permitted = any(ok for _, p, ok in passed if p)\n            restricted = [n for n, p, ok in passed if not p and not ok]",
     "            permitted = any(ok for _, p, ok in passed)\n            restricted = []"),
    ("public-role policies ignored", SB, '" and (0 = any(polroles) or exists', '" and (false or exists'),
    ("every role's policies count", SB, "pg_has_role(%s, r, 'USAGE')", "(%s is not null)"),
    ("no permissive policy lets the row through", SB,
     "            permitted = any(ok for _, p, ok in passed if p)",
     "            permitted = any(ok for _, p, ok in passed if p) or not any(p for _, p, _ in passed)"),
    ("a null policy result lets the row through", SB, 'sql.SQL("({}) is true")', 'sql.SQL("({}) is not false")'),
    ("WITH CHECK ignored (USING only)", SB,
     '"polqual" if kind == "using" else "coalesce(polwithcheck, polqual)"', '"polqual"'),
    ("SELECT policies not applied to a filtered write", SB, "        if select:\n", "        if False:\n"),
    ("USING not evaluated: every target row reached", SB,
     "                    reached = [r for r in targets if self._passes(using, r)]",
     "                    reached = targets"),
    # which rows are checked
    ("the row checked before the table's BEFORE triggers", SB,
     '    _LAST = "\\U0010ffff" * 15', '    _LAST = "\\x01"'),
    ("generated columns not computed", SB,
     'sql.SQL("({}) as {}").format(sql.SQL(gen), sql.Identifier(name)) if gen else sql.Identifier(name)',
     "sql.Identifier(name)"),
    ("grant not checked", SB, "        if missing:\n            return f\"anon has no grant", "        if False:\n            return f\"anon has no grant"),
    ("RLS off read as RLS", SB, '        if not self._rls_applies("anon", rel):\n            return None\n', ""),
    ("a reachable row's delete counts as refused", SB,
     "                        return None  # a row anon's policies let it delete was not deleted",
     "                        return 'refused'"),
    ("some refused rows count as all", SB,
     "                if refused and len(refused) == len(caught):", "                if refused:"),
    # the write in full: other code, other tables
    ("write not run in full", SB, "            return self._in_full(op, table, values, row, settings, refused) or why",
     "            return why"),
    ("refused rows not dropped from the full run", SB,
     "            if refused:\n                self._catch([rel], op, only=refused)", "            if False:\n                pass"),
    ("other tables' inserts not caught", SB, '            self._catch(others, "INSERT")\n', ""),
    ("a role bypassing RLS elsewhere is refused anyway", SB,
     "                if not self._rls_applies(role, other):\n                    continue\n", ""),
    ("elsewhere checked as anon, not the role that wrote", SB,
     '                check = self._policies(role, other, "INSERT", "check", False)',
     '                check = self._policies("anon", other, "INSERT", "check", False)'),
    ("elsewhere evaluated as anon", SB,
     '                self._app.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))\n                check',
     "                check"),
    ("no statement timeout on the postgres connection", SB, 'options=f"-c statement_timeout={STATEMENT_TIMEOUT}")', ")"),
]


def mutate(src, m):
    old, new = m[2], m[3]
    if len(m) == 5:  # every occurrence within a region
        a, b = src.index(m[4][0]), src.index(m[4][1])
        assert src.count(old, a, b) > 0
        return src[:a] + src[a:b].replace(old, new) + src[b:]
    assert src.count(old) == 1, f"{m[0]}: pattern found {src.count(old)} times"
    return src.replace(old, new)


def run(i):
    m = MUTANTS[i - 1] if i else ("none (sanity: the unmutated copy passes)", SB, "", "")
    copy = Path(os.environ.get("MUTANT_DIR", os.path.expanduser("~/rlsentry-mutants"))) / f"M{i:02d}"
    shutil.rmtree(copy, ignore_errors=True)
    shutil.copytree(WT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    subprocess.run(["git", "init", "-q", str(copy)], check=True)  # iso.sh finds the root by git
    if i:
        path = copy / m[1]
        path.write_text(mutate(path.read_text(), m))
    proc = subprocess.run([str(copy / ISO), "python3", "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           "-rfE"], capture_output=True, text=True, timeout=1800, cwd=copy)
    failed = [l.split(" ")[1] for l in proc.stdout.splitlines() if l.startswith(("FAILED", "ERROR"))]
    counts = [l for l in proc.stdout.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
    summary = counts[-1].strip("= ") if counts else proc.stderr[-200:]
    if i and not failed:
        summary = "SURVIVED: " + summary
    shutil.rmtree(copy, ignore_errors=True)
    return f"M{i:02d} {m[0]}\n     {summary}" + "".join(f"\n       {f}" for f in failed[:2])


if __name__ == "__main__":
    only = sorted({int(a) for a in sys.argv[1:]}) or [0] + list(range(1, len(MUTANTS) + 1))
    with ThreadPoolExecutor(int(os.environ.get("JOBS", "4"))) as pool:
        for line in pool.map(run, only):
            print(line, flush=True)
