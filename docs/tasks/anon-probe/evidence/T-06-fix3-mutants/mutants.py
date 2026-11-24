"""T-06 fix round 3: how each of fix round 2's kills was made, and the kills that came from a
crash rather than from a test reading the verdict, made again without the crash.

Each mutant is an edit on a fresh copy of this checkout (never the checkout itself) under
$MUTANT_DIR (default ~/rlsentry-mutants3; not /tmp, which iso.sh replaces). The full suite runs
there without -x, isolated by T-03's iso.sh, so every failing test is listed with the line that
failed it; a failure whose rlsentry run says "the run failed unexpectedly" (or whose test raised
other than by an assert) is a crash, not a kill. Run as root from anywhere:
    python3 .../T-06-fix3-mutants/mutants.py NAME [NAME ...]     (NAME: R1, S14, X1, ...; none)
"""
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
WT = HERE.parents[4]  # the checkout this file is in
ISO = "docs/tasks/anon-probe/evidence/T-03-mutants/iso.sh"
SB, AT = "rlsentry/sandbox.py", "rlsentry/attacker.py"

_spec = importlib.util.spec_from_file_location("fix2", HERE.parent / "T-06-fix2-mutants" / "mutants.py")
_fix2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fix2)
MUTANTS = {m[0].split(" ")[0]: m for m in _fix2.MUTANTS}  # fix round 2's, by id

_PLAN = '        writes = [node for e in entries if e.get("func_name") == "explain_ExecutorEnd"'
_PARSE = ('                  for node in _nodes(json.loads(e["message"].partition("plan:\\n")[2])["Plan"])')
_SAFE_PARSE = ('                  for node in _nodes(_plan_or_none(e.get("message")))')
_PLAN_OR_NONE = '''

def _plan_or_none(message):
    try:
        return json.loads((message or "").partition("plan:\\n")[2])["Plan"]
    except (ValueError, KeyError, TypeError):
        return {}
'''
_FED = '        if len(fed) != 1 or fed[0].get("Actual Loops") != 1 or fed[0].get("Actual Rows") != 0:'

MUTANTS.update({
    # D4, the verdict's own mutant: a plan is any entry whose message carries one
    "X1": ("X1 a plan is any entry with a plan in its message (verdict D4)", SB, _PLAN,
           '        writes = [node for e in entries if "plan:\\n" in (e.get("message") or "")'),
    # S14 without its crash: every entry is read as a plan, a line that holds none as no plan
    "S14b": ("S14b every entry read as a plan, without the crash on one that is not", SB,
             _PLAN + "\n" + _PARSE,
             '        writes = [node for e in entries if True\n' + _SAFE_PARSE, _PLAN_OR_NONE),
    # R1 without its crash: no answer from the oracle read as agreement
    "R1b": ("R1b the oracle's no answer read as agreeing with PostgreSQL's", SB,
            "        if ours is None or theirs is None or ours[:2] != theirs:\n            return None\n"
            "        return ours[2]",
            "        if theirs is None or (ours is not None and ours[:2] != theirs):\n"
            "            return None\n        return ours[2] if ours else 'refused by row-level security'"),
    # S21 without its crash (if it had one)
    "S21b": ("S21b every child of the write, the first read", SB,
             '        fed = [n for n in writes[0].get("Plans", []) if n.get("Parent Relationship") == "Outer"]',
             '        fed = writes[0].get("Plans", [])[:1]'),
    # the fact S18 and S19 rest on: a nested statement's plan is never logged
    "N1": ("N1 auto_explain logs nested statements too (S18/S19's reason)", SB,
           "alter role authenticator set auto_explain.log_verbose = on;",
           "alter role authenticator set auto_explain.log_verbose = on;\n"
           "alter role authenticator set auto_explain.log_nested_statements = on;"),
})


def mutate(src, m):
    old, new = m[2], m[3]
    assert src.count(old) == 1, f"{m[0]}: pattern found {src.count(old)} times"
    src = src.replace(old, new)
    return src + m[4] if len(m) == 5 else src  # a helper the edit calls


def run(name):
    m = MUTANTS.get(name, ("none (sanity: the unmutated copy passes)", SB, "", ""))
    base = Path(os.environ.get("MUTANT_DIR", os.path.expanduser("~/rlsentry-mutants3")))
    base.mkdir(parents=True, exist_ok=True)
    copy = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=base))
    shutil.copytree(WT, copy, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "*.egg-info"))
    subprocess.run(["git", "init", "-q", str(copy)], check=True)  # iso.sh finds the root by git
    if name in MUTANTS:
        path = copy / m[1]
        path.write_text(mutate(path.read_text(), m))
    args = [str(copy / ISO), "python3", "-m", "pytest", "-p", "no:cacheprovider", "--tb=short",
            "-rf"] + os.environ.get("ONLY", "").split()
    proc = subprocess.run(args, capture_output=True, text=True, timeout=3600, cwd=copy)
    (copy / "pytest.out").write_text(proc.stdout + proc.stderr)
    counts = [l for l in proc.stdout.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
    summary = counts[-1].strip("= ") if counts else proc.stderr[-200:]
    lines = [f"{name} {m[0]}", f"     {summary}" if name == "none" or "failed" in summary
             else f"     SURVIVED: {summary}"]
    for test, how in failures(proc.stdout):
        lines.append(f"       {how:7} {test}")
    return "\n".join(lines)


def failures(out):
    """(test, "crash" or "assert") for each failing test, from --tb=short sections."""
    found = []
    for head, body in re.findall(r"^_+ (\S+) _+\n(.*?)(?=^_+ \S+ _+\n|^={3,} )", out, re.S | re.M):
        crash = ("failed unexpectedly" in body
                 or not re.search(r"^E\s+(AssertionError|assert )", body, re.M))
        found.append((head, "crash" if crash else "assert"))
    return found


if __name__ == "__main__":
    if sys.argv[1:2] == ["--classify"]:  # again, from the outputs a run left: --classify DIR ...
        for d in sys.argv[2:]:
            print(d, *[f"\n       {how:7} {test}" for test, how in failures(Path(d, "pytest.out").read_text())])
        sys.exit()
    names = sys.argv[1:] or ["none"]
    with ThreadPoolExecutor(int(os.environ.get("JOBS", "3"))) as pool:
        for line in pool.map(run, names):
            print(line, flush=True)
