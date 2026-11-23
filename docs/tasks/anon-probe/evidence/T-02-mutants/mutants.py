"""T-02 mutants: break one claimed property at a time; some test must fail."""
import subprocess, sys
from pathlib import Path
# Run from the repository root. Set ISO to a wrapper (e.g. a private pid namespace + /tmp)
# when another rlsentry run shares the machine; empty runs pytest directly.
import os, shlex
ISO = shlex.split(os.environ.get("ISO", ""))
A, S, K = "rlsentry/attacker.py", "rlsentry/sandbox.py", "rlsentry/attack.py"
CONFIRM = "            if not gone:\n                continue\n"
M = [
 ("update trusts 2xx instead of superuser", A, CONFIRM,
  "            if op is Op.UPDATE and 200 <= resp.status < 300 and not gone:\n"
  "                return OpResult(op, Outcome.EXPOSED, 'HTTP 2xx', None)\n" + CONFIRM),
 ("delete trusts 2xx instead of superuser", A, CONFIRM,
  "            if op is Op.DELETE and 200 <= resp.status < 300 and not gone:\n"
  "                return OpResult(op, Outcome.EXPOSED, 'HTTP 2xx', None)\n" + CONFIRM),
 ("no restore at all", K, "                sandbox.restore()", "                pass"),
 ("no restore after INSERT", K, "                sandbox.restore()", "                op is Op.INSERT or sandbox.restore()"),
 ("no restore after UPDATE", K, "                sandbox.restore()", "                op is Op.UPDATE or sandbox.restore()"),
 ("no restore after DELETE", K, "                sandbox.restore()", "                op is Op.DELETE or sandbox.restore()"),
 ("restore leaves updated values (re-inserts nothing)", S,
  '                self._conn.execute(sql.SQL("delete from {}").format(target))\n', ""),
 ("insert verdict: 2xx judged protected", A,
  "        if 200 <= resp.status < 300:\n            created", "        if False:\n            created"),
 ("update/delete: no unfiltered attempt", A,
  '        attempts.append(("without a filter", None))\n', ""),
 ("update/delete: no by-key attempt", A,
  '            attempts.append(("by primary key", {k: f"eq.{before[0][k]}" for k in key}))\n',
  "            pass\n"),
 ("insert evidence = the row sent, not the row created", A,
  '{"row": created[0] if created else row}', '{"row": row}'),
 ("update evidence: after = before", A,
  '"after": next((r for r in new if same(r)), new[0])}', '"after": gone[0]}'),
 ("delete evidence: count always 1", A, '"rows_deleted": len(gone)', '"rows_deleted": 1'),
 ("delete evidence: wrong key", A, '{k: gone[0][k] for k in key}', '{k: gone[-1][k] for k in key}'),
 ("auth.uid() always a fixed user", S,
  "  select coalesce(nullif(current_setting('request.jwt.claim.sub', true), ''),",
  "  select coalesce('00000000-0000-0000-0000-000000000001',"),
 ("unfillable table attacked anyway (no AttackError)", A,
  '            raise AttackError(f"{table}: no fake row can be made, so it cannot be attacked")', "            pass"),
]
TESTS = ["tests/test_lab.py", "tests/test_writes.py"]
only = sys.argv[1:]
for i, (name, f, old, new) in enumerate(M):
    if only and str(i) not in only: continue
    p = Path(f); orig = p.read_text()
    assert orig.count(old) == 1, name
    p.write_text(orig.replace(old, new))
    try:
        r = subprocess.run([*ISO, "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rf", *TESTS],
                           capture_output=True, text=True)
    finally:
        p.write_text(orig)
    print("   ", (r.stdout.strip().splitlines() or ["<no output>"])[-1], r.stderr.strip()[-200:])
    failed = [l.split(" - ")[0].replace("FAILED ", "") for l in r.stdout.splitlines() if l.startswith("FAILED")]
    print(f"M{i:02d} {name}: {'KILLED' if failed else 'SURVIVED'} ({len(failed)} failed)")
    for t in failed: print("     ", t)
