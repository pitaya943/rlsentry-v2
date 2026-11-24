"""T-07 (PR #10 fix round 1): mutants on the channel's redirects and on the READ verdict.

Each mutant is an edit on a throwaway `git worktree` of HEAD under $MUTANT_DIR (default
~/rlsentry-t07-mutants; not /tmp, which iso.sh replaces), never this checkout. The full suite
runs there without -x, isolated by T-03's iso.sh, and every failing test is labelled assert or
crash with fix round 3's classifier. Commit first. Run as root:
    python3 .../T-07/mutants.py NAME [NAME ...]   (none, D1 ..., R1 ...)
"""
import importlib.util
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
WT = HERE.parents[4]
ISO = "docs/tasks/anon-probe/evidence/T-03-mutants/iso.sh"
SB, AT, CH = "rlsentry/sandbox.py", "rlsentry/attacker.py", "rlsentry/channel.py"

_spec = importlib.util.spec_from_file_location("fix3", HERE.parent / "T-06-fix3-mutants" / "mutants.py")
_fix3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fix3)

MUTANTS = {
    # D1: the channel
    "D1": ("D1 redirects followed again (urllib's default handler)", CH,
           "urllib.request.ProxyHandler({}), _NoRedirect)", "urllib.request.ProxyHandler({}))"),
    "D2": ("D2 a 3xx answer read like any other (no stop in _send)", AT,
           "        if 300 <= resp.status < 400:", "        if False:"),
    "D3": ("D3 the wait for PostgREST follows redirects", SB,
           '            with OPENER.open(f"http://127.0.0.1:{port}/", timeout=2) as resp:',
           '            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open('
           'f"http://127.0.0.1:{port}/", timeout=2) as resp:',
           "\nimport urllib.request\n"),
    # D2: READ EXPOSED
    "R1": ("R1 READ EXPOSED without the superuser check", AT,
           "            if not self._db.holds_rows(table, resp.raw):",
           "            if False:"),
    "R2": ("R2 the superuser's rows counted as a set (except, not except all)", SB,
           " except all select pg_catalog.to_jsonb", " except select pg_catalog.to_jsonb"),
    "R3": ("R3 the superuser's rows written out under its own search path", SB,
           "            self._conn.execute(\"select pg_catalog.set_config('search_path', %s, true)\",\n"
           "                               [POSTGREST_SEARCH_PATH])\n", ""),
    # D2: READ protected
    "R4": ("R4 READ protected without the log", AT,
           "self._db.read_refused(table, resp.request_id)", "True"),
    "R5": ("R5 the read's plan: the rows that fed it not looked at", SB,
           '            return ("using", table) if fed == [0] else None',
           '            return ("using", table) if fed else None'),
    "R6": ("R6 any answer may be read protected on the log (not only [] or 42501)", AT,
           "        if (rows == [] or _refused(resp)) and self._db.read_refused(",
           "        if self._db.read_refused("),
    "R7": ("R7 a GET 42501 never protected (the grant's answer dropped)", SB,
           '        return self._said("SELECT", table, request_id) in (("grant", table), ("using", table))',
           '        return self._said("SELECT", table, request_id) in (("using", table),)'),
    "R8": ("R8 a GET 42501 protected from the body alone (trail row 177)", AT,
           "        if (rows == [] or _refused(resp)) and self._db.read_refused(table, resp.request_id):",
           "        if _refused(resp) or rows == [] and self._db.read_refused(table, resp.request_id):"),
    "R9": ("R9 READ 0 rows protected from the body alone", AT,
           "        if (rows == [] or _refused(resp)) and self._db.read_refused(table, resp.request_id):",
           "        if rows == [] or _refused(resp) and self._db.read_refused(table, resp.request_id):"),
    "R10": ("R10 the grant's refusal read from any function the log names", SB,
            '            if (error.get("func_name") == "aclcheck_error" and not nested',
            '            if (not nested'),
}


def run(name):
    m = MUTANTS.get(name, ("none (sanity: the unmutated copy passes)", SB, "", ""))
    base = Path(os.environ.get("MUTANT_DIR", os.path.expanduser("~/rlsentry-t07-mutants")))
    base.mkdir(parents=True, exist_ok=True)
    copy = base / name
    if copy.exists():
        subprocess.run(["git", "-C", str(WT), "worktree", "remove", "--force", str(copy)])
    subprocess.run(["git", "-C", str(WT), "worktree", "add", "-q", "--detach", str(copy), "HEAD"],
                   check=True)
    try:
        if name in MUTANTS:
            path = copy / m[1]
            path.write_text(_fix3.mutate(path.read_text(), m))
        args = [str(copy / ISO), "python3", "-m", "pytest", "-p", "no:cacheprovider", "--tb=short",
                "-rf"] + os.environ.get("ONLY", "").split()
        proc = subprocess.run(args, capture_output=True, text=True, timeout=3600, cwd=copy)
        (base / f"{name}.out").write_text(proc.stdout + proc.stderr)
    finally:
        subprocess.run(["git", "-C", str(WT), "worktree", "remove", "--force", str(copy)])
    counts = [l for l in proc.stdout.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
    summary = counts[-1].strip("= ") if counts else proc.stderr[-200:]
    found = _fix3.failures(proc.stdout)
    tally = f"assert {sum(h == 'assert' for _, h in found)} crash {sum(h == 'crash' for _, h in found)}"
    lines = [f"{name} {m[0]}", f"     {summary}   {tally}" if name == "none" or "failed" in summary
             else f"     SURVIVED: {summary}"]
    for test, how in found[:8]:
        lines.append(f"       {how:7} {test}")
    if len(found) > 8:
        lines.append(f"       ... {len(found) - 8} more")
    return "\n".join(lines)


if __name__ == "__main__":
    names = sys.argv[1:] or ["none"]
    with ThreadPoolExecutor(int(os.environ.get("JOBS", "3"))) as pool:
        for line in pool.map(run, names):
            print(line, flush=True)
