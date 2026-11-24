import contextlib
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
# The backend for runs whose test names none:
#   local       the default: local PostgreSQL and PostgREST processes; no Docker at all.
#   fakedocker  tests/fakedocker.py, one stand-in daemon for the session.
#   docker      the real Docker daemon, made ready by tests/realdocker.py (started if none
#               answers, images pulled with mirror fallback). Only this option runs the tests
#               marked `real_docker`; under the others they skip, so the default command never
#               starts a daemon or pulls an image, and the stand-in is never taken for the
#               real thing.
BACKEND = "local"
# What rlsentry is told (`--backend`): the stand-in and the real daemon are both `docker` to it.
RUN_BACKEND = "local"
REAL_DOCKER_COMMAND = "python3 -m pytest -q --rlsentry-backend docker"
# Under `docker`: what tests/realdocker.py did (for the report header), or why it could not.
REAL_DOCKER_LINES = []
REAL_DOCKER_ERROR = None


def pytest_addoption(parser):
    parser.addoption("--rlsentry-backend", choices=("local", "fakedocker", "docker"),
                     default="local",
                     help="backend for the runs a test does not give one: local processes "
                          "(default), fakedocker (tests/fakedocker.py), or docker (a real "
                          "daemon, started if none answers)")


def pytest_configure(config):
    global BACKEND, RUN_BACKEND, REAL_DOCKER_LINES, REAL_DOCKER_ERROR
    config.addinivalue_line("markers", "real_docker: needs a real Docker daemon; runs only "
                                       "with --rlsentry-backend docker")
    BACKEND = config.getoption("--rlsentry-backend")
    RUN_BACKEND = "local" if BACKEND == "local" else "docker"
    if BACKEND == "docker":
        import realdocker
        try:
            REAL_DOCKER_LINES = realdocker.ensure(say=lambda line: None)
        except realdocker.NotReady as e:
            REAL_DOCKER_ERROR = str(e)
        except (OSError, subprocess.SubprocessError) as e:
            REAL_DOCKER_ERROR = f"{type(e).__name__}: {e}"
    if BACKEND == "fakedocker":
        root = Path(tempfile.mkdtemp(prefix="fakedocker-session-"))
        config.add_cleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        docker_dir, bin_dir = install_fake_docker(root)
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
        os.environ["FAKE_DOCKER_DIR"] = str(docker_dir)
        os.environ.pop("DOCKER_HOST", None)
        os.environ.pop("FAKE_DOCKER_FAIL", None)


def pytest_report_header(config):
    if BACKEND != "docker":
        return None
    if REAL_DOCKER_ERROR:
        return [f"real Docker: NOT READY: {REAL_DOCKER_ERROR}"]
    return [f"real Docker: {line}" for line in REAL_DOCKER_LINES]


def pytest_collection_modifyitems(config, items):
    if BACKEND == "docker":
        return
    skip = pytest.mark.skip(reason=f"needs a real Docker daemon: run `{REAL_DOCKER_COMMAND}`")
    for item in items:
        if item.get_closest_marker("real_docker"):
            item.add_marker(skip)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_call(item):
    # Under `docker`, a daemon or image that could not be made ready fails the test (in its
    # call phase, so it counts as failed, not as an error): a skip here would let the
    # real-daemon check pass without having run.
    if BACKEND == "docker" and REAL_DOCKER_ERROR and item.get_closest_marker("real_docker"):
        pytest.fail(f"the real Docker daemon is not ready: {REAL_DOCKER_ERROR}", pytrace=False)


def install_fake_docker(root):
    """tests/fakedocker.py as `docker` in root/bin, its state in root/docker."""
    (root / "docker").mkdir()
    (root / "bin").mkdir()
    cli = root / "bin" / "docker"
    cli.write_text(f'#!/bin/sh\nexec {sys.executable} {Path(__file__).parent / "fakedocker.py"} "$@"\n')
    cli.chmod(0o755)
    return root / "docker", root / "bin"


@pytest.fixture
def state_dir(tmp_path):
    return tmp_path / "state"


def rlsentry(*args, state_dir, **kw):
    """Start `rlsentry` as a separate process with its own state dir; on RUN_BACKEND (local
    unless pytest is told otherwise) unless the arguments name one."""
    env = dict(os.environ, RLSENTRY_STATE_DIR=str(state_dir))
    if args[:1] == ("attack",) and "--backend" not in args:
        args = ("attack", "--backend", RUN_BACKEND, *args[1:])
    return subprocess.Popen([sys.executable, "-m", "rlsentry", *args], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)


def run_rlsentry(*args, state_dir):
    since = time.time()
    proc = rlsentry(*args, state_dir=state_dir)
    out, err = proc.communicate(timeout=120)
    if args[:1] == ("attack",) and "--backend" not in args:
        witness_real_copy(since, err)
    return proc.returncode, out, err


# Under `--rlsentry-backend docker`, every copy a test builds without naming a backend must be
# shown to have run on the real daemon (brief real-docker S-5), not merely to have been asked
# for: the real daemon's own event log must hold the creation of a container labelled with
# exactly one run id since the copy was asked for. COPIES_SEEN counts them for the summary.
COPIES_SEEN = []


def _real_runs_since(since):
    out = subprocess.run(
        ["docker", "events", "--since", f"{since:.3f}", "--until", f"{time.time():.3f}",
         "--filter", "type=container", "--filter", "event=create",
         "--filter", "label=rlsentry.run", "--format", '{{index .Actor.Attributes "rlsentry.run"}}'],
        capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, f"docker events failed: {out.stderr}"
    return set(out.stdout.split())


def witness_real_copy(since, context="", run_id=None):
    if BACKEND != "docker":
        return
    assert "FAKE_DOCKER_DIR" not in os.environ, "the stand-in daemon is on PATH"
    runs = _real_runs_since(since)
    assert len(runs) == 1, (f"expected one copy on the real daemon since {since:.3f}, the daemon "
                            f"saw runs {sorted(runs)}\n{context}")
    if run_id is not None:
        assert runs == {run_id}, (runs, run_id)
    COPIES_SEEN.extend(runs)


@contextlib.contextmanager
def copy_of(folder):
    """Sandbox(folder) on the suite's backend; under the real daemon, witnessed like a run."""
    from rlsentry.sandbox import Sandbox
    since = time.time()
    with Sandbox(folder, RUN_BACKEND) as sb:
        yield sb
    witness_real_copy(since, run_id=sb._run_id)


def pytest_terminal_summary(terminalreporter):
    if BACKEND == "docker":
        terminalreporter.write_line(
            f"real Docker: {len(COPIES_SEEN)} copies built without a named backend, each seen "
            f"created on the real daemon ({len(set(COPIES_SEEN))} distinct run ids)")


def cmdline(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
    except OSError:
        return ""


def residue():
    """Run dirs and PostgreSQL/PostgREST processes on this machine (zombies excluded)."""
    dirs = set()
    for base in {"/tmp", tempfile.gettempdir()}:
        dirs |= set(glob.glob(os.path.join(base, "rlsentry-run-*")))
    procs = set()
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            cmd = cmdline(int(entry))
            if "rlsentry-run-" in cmd or cmd.startswith(("postgres", "/usr/lib/postgresql")):
                procs.add((int(entry), cmd))
    return dirs, procs


def wait_for_marker(state_dir, pids=2, timeout=60):
    """Wait until a running rlsentry has recorded `pids` processes; return the marker."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for marker in state_dir.glob("*.json"):
            try:
                info = json.loads(marker.read_text())
            except ValueError:
                continue
            if len(info["pids"]) >= pids:
                return marker, info
        time.sleep(0.05)
    raise AssertionError("rlsentry never got its servers up")


class FakeDocker:
    """tests/fakedocker.py as `docker` on PATH (see its docstring)."""

    def __init__(self, root, monkeypatch):
        self.dir, bin_dir = install_fake_docker(root)
        self._monkeypatch = monkeypatch
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("FAKE_DOCKER_DIR", str(self.dir))
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        monkeypatch.delenv("FAKE_DOCKER_FAIL", raising=False)

    def fail(self, *modes):
        self._monkeypatch.setenv("FAKE_DOCKER_FAIL", ",".join(modes))

    def fail_now(self, *modes):
        """Break the daemon from now on, for a run already going on."""
        (self.dir / "fail").write_text(",".join(modes))

    def volumes(self):
        path = self.dir / "state.json"
        return list(json.loads(path.read_text()).get("volumes", {})) if path.exists() else []

    def containers(self):
        path = self.dir / "state.json"
        return json.loads(path.read_text())["containers"] if path.exists() else {}

    def calls(self):
        path = self.dir / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def docker(self, *args):
        return subprocess.run(["docker", *args], capture_output=True, text=True, check=True).stdout


@pytest.fixture
def fake_docker(tmp_path, monkeypatch):
    fake = FakeDocker(tmp_path, monkeypatch)
    yield fake
    (fake.dir / "fail").unlink(missing_ok=True)
    leftover = fake.containers()
    if leftover:
        subprocess.run(["docker", "rm", "-f", *leftover], capture_output=True)
