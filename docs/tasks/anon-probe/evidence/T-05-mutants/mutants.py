"""Break each T-05 property one edit at a time; run the full suite isolated (T-03's iso.sh);
record which tests fail. Each mutant runs in a throwaway `git worktree` of HEAD next to this
checkout, never in the checkout itself, so an interrupted run leaves nothing changed here.
Commit first: the copies are made from HEAD. Run from anywhere in a checkout, as root:
  python3 docs/tasks/anon-probe/evidence/T-05-mutants/mutants.py [N ...]"""
import re
import subprocess
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[5]  # the checkout this file is in
ISO = WT / "docs/tasks/anon-probe/evidence/T-03-mutants/iso.sh"
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
    ("teardown removes nothing", DK, "                if left:\n                    _docker(\"rm\"",
     "                if False:\n                    _docker(\"rm\""),
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
    ("a cut-off docker run is not waited for", DK, "        self._unsettled.add(name)\n", ""),
    ("docker cluster ignores the sandbox's superuser", DK,
     '"-e", f"POSTGRES_USER={superuser}", ', ""),
    ("local cluster ignores the sandbox's superuser", "rlsentry/backends/local.py",
     '"-U", superuser, "--auth=trust"', '"-U", "postgres", "--auth=trust"'),
    ("data directory not a tmpfs (an anonymous volume per run)", DK, '            "--tmpfs", PGDATA,\n', ""),
    ("teardown that cannot reach the daemon says nothing", DK,
     'print(f"rlsentry: could not confirm', '(lambda *a, **k: None)(f"rlsentry: could not confirm'),
    ("log of a gone container is silently empty", DK,
     'return "(no log: the container is gone, removed by --rm when it exited)"', 'return ""'),
    ("teardown looks once: no wait for a cut-off docker run", DK,
     "                if not left and not self._unsettled:\n", "                if not left:\n"),
    ("teardown looks once: never looks again after rm", DK,
     "                    _docker(\"rm\", \"-f\", *left)\n", "                    _docker(\"rm\", \"-f\", *left)\n                    break\n"),
    ("teardown rm without -f (verifier B11)", DK, '                    _docker("rm", "-f", *left)', '                    _docker("rm", *left)'),
    ("sweep rm without -f (verifier B12)", DK, '            _docker("rm", "-f", *stale)', '            _docker("rm", *stale)'),
    ("a container once seen stays unsettled (verifier B07)", DK, "                self._unsettled -= set(left)\n", ""),
    ("teardown ps without -a", DK, 'listed = _docker("ps", "-a", "--filter", label,', 'listed = _docker("ps", "--filter", label,'),
    ("sweep ps without -a", DK, 'listed = _docker("ps", "-a", "--filter", f"label={RUN_LABEL}",', 'listed = _docker("ps", "--filter", f"label={RUN_LABEL}",'),
    ("docker run without -d", DK, 'argv = ["run", "-d", "--rm", "--name", name,', 'argv = ["run", "--rm", "--name", name,'),
    ("context inspect without the endpoint template", DK,
     '"context", "inspect", "--format", "{{.Endpoints.docker.Host}}")', '"context", "inspect")'),
    ("inspect without the State.Running template", DK,
     '_docker("inspect", "--format", "{{.State.Running}}", *self._started)', '_docker("inspect", *self._started)'),
    ("log_tail: an unreachable daemon reads as a gone container", DK,
     '        if "No such container" in logs.stderr:\n', '        if logs.returncode != 0:\n'),
]


SLOW = {"docker run without -d": ["-x"]}  # every container start waits out RUN_TIMEOUT


def main(only=None):
    copies = WT.parent / f"{WT.name}-mutants"
    subprocess.run(["git", "-C", str(WT), "worktree", "prune"], check=True)
    for i, (desc, rel, old, new) in enumerate(MUTANTS, 1):
        if only and i not in only:
            continue
        copy = copies / f"m{i:02d}"
        if copy.exists():
            subprocess.run(["git", "-C", str(WT), "worktree", "remove", "--force", str(copy)])
        subprocess.run(["git", "-C", str(WT), "worktree", "add", "-q", "--detach", str(copy), "HEAD"], check=True)
        try:
            path = copy / rel
            src = path.read_text()
            assert src.count(old) == 1, f"M{i} {desc}: pattern found {src.count(old)} times"
            path.write_text(src.replace(old, new))
            run = subprocess.run([str(copy / ISO.relative_to(WT)), "python3", "-m", "pytest", "-q",
                                  "-p", "no:cacheprovider", "-rfE", *SLOW.get(desc, [])],
                                 capture_output=True, text=True, timeout=3600)
            failed = [l.split(" ")[1] for l in run.stdout.splitlines() if l.startswith(("FAILED", "ERROR"))]
            counts = [l for l in run.stdout.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
            summary = counts[-1].strip("= ") if counts else run.stderr[-200:]
            if SLOW.get(desc):
                summary += " (stopped at the first failure: " + " ".join(SLOW[desc]) + ")"
            if not failed:
                summary = "SURVIVED: " + summary
            print(f"M{i:02d} {desc}\n     {summary}")
            for f in failed[:4]:
                print(f"       {f}")
            sys.stdout.flush()
        finally:
            subprocess.run(["git", "-C", str(WT), "worktree", "remove", "--force", str(copy)])


if __name__ == "__main__":
    main({int(a) for a in sys.argv[1:]} or None)
