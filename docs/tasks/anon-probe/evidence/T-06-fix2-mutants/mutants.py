"""T-06 fix round 2: every condition on the path that can yield `protected` (rls_refusal, _said,
_Log, the attacker's _rls_answered, and _evaluate's no-target guard), each removed or loosened on
a throwaway copy of this checkout (never the checkout itself). The full suite runs there,
isolated by T-03's iso.sh, stopping at the first failure. Survivors are argued equivalent in
mutants.txt. Run as root from anywhere: python3 .../T-06-fix2-mutants/mutants.py [N ...]
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
ORACLE = ("    def _evaluate(", "    def _oid(")  # the oracle's methods, for edits across them

MUTANTS = [
    # --- rls_refusal
    ("R1 the oracle's no answer not checked", SB,
     "        if ours is None or theirs is None or ours[:2] != theirs:",
     "        if theirs is None or ours[:2] != theirs:"),
    ("R2 PostgreSQL's no answer not checked", SB,
     "        if ours is None or theirs is None or ours[:2] != theirs:",
     "        if ours is None or ours[:2] != theirs:"),
    ("R3 the two answers need not agree (fix 1's M02)", SB,
     "        if ours is None or theirs is None or ours[:2] != theirs:",
     "        if ours is None or theirs is None:"),
    ("R4 only the kind compared, not the table (verdict V8)", SB,
     "        if ours is None or theirs is None or ours[:2] != theirs:",
     "        if ours is None or theirs is None or ours[0] != theirs[0]:"),
    # --- _said, an error
    ("S1 any ERROR, not the first (verdict V12: the last)", SB,
     '        error = next((e for e in entries if e.get("error_severity") == "ERROR"), None)',
     '        error = next((e for e in reversed(entries) if e.get("error_severity") == "ERROR"), None)'),
    ("S2 errors read only as ERROR severity: none read", SB,
     '        error = next((e for e in entries if e.get("error_severity") == "ERROR"), None)',
     '        error = None'),
    ("S3 SQLSTATE 42501 not checked (verdict V11)", SB,
     '            if error.get("state_code") != "42501":\n                return None\n', ""),
    ("S4 grant: the C function not checked", SB,
     '            if (error.get("func_name") == "aclcheck_error" and not nested',
     '            if (True and not nested'),
    ("S5 grant: a nested refusal accepted (verdict V7)", SB,
     '            if (error.get("func_name") == "aclcheck_error" and not nested',
     '            if (error.get("func_name") == "aclcheck_error"'),
    ("S6 grant: the table in the message not checked", SB,
     "                    and message == f'permission denied for table {table}'):",
     "                    and True):"),
    ("S7 check: the C function not checked (verdict V2)", SB,
     '            if (error.get("func_name") == "ExecWithCheckOptions"',
     '            if (True'),
    ("S8 check: the message's start not checked", SB,
     '                    and message.startswith("new row violates row-level security policy ")',
     "                    and True"),
    ("S9 check: the table name's quoting not checked", SB,
     """                    and ' for table "' in message and message.endswith('"')):""",
     "                    and True):"),
    ("S10 check: top level or nested not checked (verdict V1)", SB,
     "                if (refused == table) != nested:", "                if True:"),
    ("S11 an error that is not RLS's falls through to the plan", SB,
     '                    return ("check", refused)\n            return None\n',
     '                    return ("check", refused)\n'),
    # --- _said, a 2xx that changed nothing
    ("S12 an INSERT may be answered by a plan", SB,
     '        if op == "INSERT" or not entries:', "        if not entries:"),
    ("S13 no entries not checked", SB,
     '        if op == "INSERT" or not entries:', '        if op == "INSERT":'),
    ("S14 every entry read as a plan", SB,
     '        writes = [node for e in entries if e.get("func_name") == "explain_ExecutorEnd"',
     '        writes = [node for e in entries if True'),
    ("S15 any plan node, not the write", SB,
     '                  if node.get("Node Type") == "ModifyTable" and node.get("Schema") == "public"',
     '                  if True and node.get("Schema") == "public"'),
    ("S16 any schema's table of that name (verdict V6, D3)", SB,
     '                  if node.get("Node Type") == "ModifyTable" and node.get("Schema") == "public"',
     '                  if node.get("Node Type") == "ModifyTable"'),
    ("S17 any table's write (fix 1's M06)", SB,
     '                  and node.get("Relation Name") == table]', "                  ]"),
    ("S18 more than one write: the first is read", SB,
     '        if len(writes) != 1 or writes[0].get("Operation") != op.title():',
     '        if not writes or writes[0].get("Operation") != op.title():'),
    ("S19 more than one write: the last is read", SB,
     '        if len(writes) != 1 or writes[0].get("Operation") != op.title():',
     '        writes = writes[-1:]\n        if len(writes) != 1 or writes[0].get("Operation") != op.title():'),
    ("S20 the write's operation not checked", SB,
     '        if len(writes) != 1 or writes[0].get("Operation") != op.title():',
     "        if len(writes) != 1:"),
    ("S21 every child of the write, not only its source", SB,
     '        fed = [n for n in writes[0].get("Plans", []) if n.get("Parent Relationship") == "Outer"]',
     '        fed = [n for n in writes[0].get("Plans", [])]'),
    ("S22 more than one source: the first is read", SB,
     '        if len(fed) != 1 or fed[0].get("Actual Loops") != 1 or fed[0].get("Actual Rows") != 0:',
     '        if not fed or fed[0].get("Actual Loops") != 1 or fed[0].get("Actual Rows") != 0:'),
    ("S23 the source's loops not checked", SB,
     '        if len(fed) != 1 or fed[0].get("Actual Loops") != 1 or fed[0].get("Actual Rows") != 0:',
     '        if len(fed) != 1 or fed[0].get("Actual Rows") != 0:'),
    ("S24 the source's rows not read (fix 1's M05)", SB,
     '        if len(fed) != 1 or fed[0].get("Actual Loops") != 1 or fed[0].get("Actual Rows") != 0:',
     "        if len(fed) != 1:"),
    # --- _Log
    ("L1 no request id not checked", SB,
     "        if not request_id:\n            return []\n        entries = self._since_last_call()",
     "        entries = self._since_last_call()"),
    ("L2 the naming entry: any user (verdict V5)", SB,
     '                 if e.get("user") == "authenticator" and e.get("func_name") == "exec_execute_message"',
     '                 if e.get("func_name") == "exec_execute_message"'),
    ("L3 the naming entry: any C function", SB,
     '                 if e.get("user") == "authenticator" and e.get("func_name") == "exec_execute_message"',
     '                 if e.get("user") == "authenticator"'),
    ("L4 the naming entry: any statement", SB,
     """                 and "set_config('request.headers'" in (e.get("message") or "")\n""", ""),
    ("L5 the naming entry: the request id not matched (verdict V4)", SB,
     """                 and f'"{REQUEST_HEADER.lower()}":"{request_id}"' in (e.get("detail") or "")}""",
     "                 }"),
    ("L6 more than one transaction named: all read", SB,
     "        if len(named) != 1:\n            return []", "        if not named:\n            return []"),
    ("L7 the request's entries: any user", SB,
     '        return [e for e in entries if e.get("user") == "authenticator"\n'
     '                and (e.get("session_id"), e.get("vxid")) in named]',
     '        return [e for e in entries if (e.get("session_id"), e.get("vxid")) in named]'),
    ("L8 the request's entries: any transaction (fix 1's M07)", SB,
     '        return [e for e in entries if e.get("user") == "authenticator"\n'
     '                and (e.get("session_id"), e.get("vxid")) in named]',
     '        return [e for e in entries if e.get("user") == "authenticator"]'),
    ("L9 the request's entries: by session, not transaction (fix 1's M08)", SB,
     '                and (e.get("session_id"), e.get("vxid")) in named]',
     '                and e.get("session_id") in {s for s, _ in named}]'),
    ("L10 the sync line: any user", SB,
     '                if entry.get("user") == SUPERUSER and entry.get("message") == self._SYNC + token:',
     '                if entry.get("message") == self._SYNC + token:'),
    ("L11 the sync line: any token", SB,
     '                if entry.get("user") == SUPERUSER and entry.get("message") == self._SYNC + token:',
     '                if entry.get("user") == SUPERUSER and (entry.get("message") or "").startswith(self._SYNC):'),
    ("L12 the log read without waiting for the sync line (verdict V9)", SB,
     "            if time.monotonic() > deadline:\n                raise BuildError(\"the server's log",
     "            if True:\n                return entries\n            if time.monotonic() > deadline:\n"
     "                raise BuildError(\"the server's log"),
    # --- the attacker
    ("A1 a 42501 is never asked about", AT,
     "        if _refused(resp) or (200 <= resp.status < 300 and op is not Op.INSERT):",
     "        if (200 <= resp.status < 300 and op is not Op.INSERT):"),
    ("A2 a 2xx that changed nothing is never asked about (fix 1's v6a)", AT,
     "        if _refused(resp) or (200 <= resp.status < 300 and op is not Op.INSERT):",
     "        if _refused(resp):"),
    ("A3 an INSERT's 2xx asked about", AT,
     "        if _refused(resp) or (200 <= resp.status < 300 and op is not Op.INSERT):",
     "        if _refused(resp) or (200 <= resp.status < 300):"),
    # --- _evaluate
    ("E1 no target row is not checked (verdict V10)", SB,
     '                if op != "INSERT" and not targets:\n'
     '                    return None  # no row there to reach: nothing to say about the policies\n', ""),
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
