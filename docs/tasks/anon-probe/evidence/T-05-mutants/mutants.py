"""Break each T-05 property one edit at a time; run the full suite isolated (T-03's iso.sh);
record which tests fail. Run from anywhere in a checkout, as root:
  python3 docs/tasks/anon-probe/evidence/T-05-mutants/mutants.py [N ...]"""
import re
import subprocess
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[5]  # the checkout this file is in
ISO = str(WT / "docs/tasks/anon-probe/evidence/T-03-mutants/iso.sh")
DK, BK, SB = "rlsentry/backends/docker.py", "rlsentry/backends/__init__.py", "rlsentry/sandbox.py"

MUTANTS = [
    ("db port published on every interface", DK,
     """"-p", f"127.0.0.1:{self._ports['db']}:5432",""", """"-p", f"{self._ports['db']}:5432","""),
    ("REST port published on every interface", DK,
     """"-p", f"127.0.0.1:{self._ports['rest']}:3000",""", """"-p", f"{self._ports['rest']}:3000","""),
    ("no --rm", DK, 'argv = ["run", "-d", "--rm", "--name", name,', 'argv = ["run", "-d", "--name", name,'),
    ("no run label", DK, '"--label", f"{RUN_LABEL}={self._run_id}", "--label"', '"--label"'),
    ("postgres image not pinned", DK, 'DB_IMAGE = "postgres:16"', 'DB_IMAGE = "postgres"'),
    ("postgrest image not pinned", DK, 'REST_IMAGE = "postgrest/postgrest:v12.2.3"',
     'REST_IMAGE = "postgrest/postgrest:latest"'),
    ("no startup sweep (any backend)", SB, "            self._backend.sweep()\n", ""),
    ("docker sweep removes nothing", DK, "        if stale:\n", "        if False:\n"),
    ("sweep removes live runs' containers too", DK, "if cid and not _owner_alive(owner)]", "if cid]"),
    ("sweep: a reused pid counts as the owner", DK,
     "    return _process_key(int(pid)) == start", "    return _process_key(int(pid)) is not None"),
    ("teardown removes nothing", DK, "        if listed.stdout.split():\n            _docker(\"rm\"",
     "        if False:\n            _docker(\"rm\""),
    ("teardown by name only, not by label", DK,
     """        listed = _docker("ps", "-a", "-q", "--filter", f"label={RUN_LABEL}={self._run_id}")\n        if listed.stdout.split():\n            _docker("rm", "-f", "-v", *listed.stdout.split())""",
     """        if self._started:\n            _docker("rm", "-f", "-v", *self._started)"""),
    ("no teardown when the build fails", SB,
     "        except BaseException:\n            self.teardown()\n            raise",
     "        except BaseException:\n            raise"),
    ("auto does not fall back", BK, "            why = err\n", "            raise BuildError(str(err)) from None\n"),
    ("daemon absence not detected", DK, "        if version.returncode != 0:\n", "        if False:\n"),
    ("remote daemon accepted", DK, "        if not host.startswith(_LOCAL_SCHEMES):\n", "        if False:\n"),
    ("pull failure not detected", DK, "                if pull.returncode != 0:\n", "                if False:\n"),
    ("nonce not checked", SB, "        if row is None or row[0] != self._nonce:\n", "        if False:\n"),
    ("docker alive() always true", DK, "        if not self._started:\n            return True\n",
     "        return True\n"),
    ("published ports not checked", DK, "        if published != wanted:\n", "        if False:\n"),
    ("JWT secret on the command line", DK, 'for arg in ("-e", name)), REST_IMAGE]',
     'for arg in ("-e", f"{name}={env[name]}")), REST_IMAGE]'),
    ("docker run not atomic w.r.t. signals", DK,
     "        with signals_blocked():  # a signal now would leave `docker run` half done\n            run = _docker(",
     "        if True:\n            run = _docker("),
    ("docker cluster ignores the sandbox's superuser", DK,
     '"-e", f"POSTGRES_USER={superuser}", ', ""),
    ("local cluster ignores the sandbox's superuser", "rlsentry/backends/local.py",
     '"-U", superuser, "--auth=trust"', '"-U", "postgres", "--auth=trust"'),
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
            run = subprocess.run([ISO, "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rfE"],
                                 capture_output=True, text=True, timeout=1800)
            failed = [l.split(" ")[1] for l in run.stdout.splitlines() if l.startswith(("FAILED", "ERROR"))]
            counts = [l for l in run.stdout.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
            summary = counts[-1].strip("= ") if counts else run.stderr[-200:]
            if not failed:
                summary = "SURVIVED: " + summary
            print(f"M{i:02d} {desc}\n     {summary}")
            for f in failed[:4]:
                print(f"       {f}")
            sys.stdout.flush()
        finally:
            path.write_text(src)


if __name__ == "__main__":
    main({int(a) for a in sys.argv[1:]} or None)
