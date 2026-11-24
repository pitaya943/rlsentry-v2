"""T-06 merged with T-05: fix round 3's mutants, the T-05 mutants on code the merge changed, and
the merge's own (the server's log read through the server, on every backend).

Each mutant is an edit on a throwaway `git worktree` of HEAD under $MUTANT_DIR (default
~/rlsentry-merge-mutants; not /tmp, which iso.sh replaces), never this checkout. The full suite
runs there without -x (but for T-05's two slow ones), isolated by T-03's iso.sh, and every
failing test is labelled assert or crash as in fix round 3. Commit first. Run as root:
    python3 .../T-06-merge/mutants.py NAME [NAME ...]   (none, R1 ... N1, T05-07 ..., G1 ...)
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
SB = "rlsentry/sandbox.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_fix3 = _load("fix3", HERE.parent / "T-06-fix3-mutants" / "mutants.py")
_t05 = _load("t05", HERE.parent / "T-05-mutants" / "mutants.py")
MUTANTS = dict(_fix3.MUTANTS)
SLOW = {}
for i, (desc, rel, old, new) in enumerate(_t05.MUTANTS, 1):
    MUTANTS[f"T05-{i:02d}"] = (f"T05-{i:02d} {desc}", rel, old, new)
    if desc in _t05.SLOW:
        SLOW[f"T05-{i:02d}"] = _t05.SLOW[desc]

MUTANTS.update({
    # without the log, rlsentry falls back on its own reading of the policies
    "G1": ("G1 no server log: the oracle's own reading taken as PostgreSQL's", SB,
           "        theirs = self._said(op, table, request_id)\n",
           "        theirs = self._said(op, table, request_id)\n"
           "        if theirs is None and ours is not None and self._log._read() is None:\n"
           "            theirs = ours[:2]\n"),
    # the log is never read: nothing PostgreSQL says reaches rlsentry
    "G2": ("G2 the server's log never read", SB,
           '        return self._conn.execute(\n            "select pg_read_binary_file(',
           '        return None\n        return self._conn.execute(\n            "select pg_read_binary_file('),
    # the evidence settings left off the server's command line
    "G3": ("G3 the logging settings not given to the backend", SB,
           '"full_page_writes": "off", **_EVIDENCE_LOG})', '"full_page_writes": "off"})'),
    # the log's lines re-read from the start on every call (offset not kept)
    "G4": ("G4 the offset read so far not kept", SB,
           "            self._offset += len(chunk)\n", ""),
})


def run(name):
    m = MUTANTS.get(name, ("none (sanity: the unmutated copy passes)", SB, "", ""))
    base = Path(os.environ.get("MUTANT_DIR", os.path.expanduser("~/rlsentry-merge-mutants")))
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
                "-rf", *SLOW.get(name, [])] + os.environ.get("ONLY", "").split()
        proc = subprocess.run(args, capture_output=True, text=True, timeout=3600, cwd=copy)
        out = proc.stdout + proc.stderr
        (base / f"{name}.out").write_text(out)
    finally:
        subprocess.run(["git", "-C", str(WT), "worktree", "remove", "--force", str(copy)])
    counts = [l for l in proc.stdout.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
    summary = counts[-1].strip("= ") if counts else proc.stderr[-200:]
    if SLOW.get(name):
        summary += " (stopped at the first failure: -x)"
    found = _fix3.failures(proc.stdout)
    tally = f"assert {sum(h == 'assert' for _, h in found)} crash {sum(h == 'crash' for _, h in found)}"
    lines = [f"{name} {m[0]}", f"     {summary}   {tally}" if name == "none" or "failed" in summary
             else f"     SURVIVED: {summary}"]
    for test, how in found[:6]:
        lines.append(f"       {how:7} {test}")
    if len(found) > 6:
        lines.append(f"       ... {len(found) - 6} more")
    return "\n".join(lines)


if __name__ == "__main__":
    names = sys.argv[1:] or ["none"]
    with ThreadPoolExecutor(int(os.environ.get("JOBS", "3"))) as pool:
        for line in pool.map(run, names):
            print(line, flush=True)
