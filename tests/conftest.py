import glob
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def state_dir(tmp_path):
    return tmp_path / "state"


def rlsentry(*args, state_dir, **kw):
    """Start `rlsentry` as a separate process with its own state dir; on the local backend
    unless the arguments name one (the tests that look for its processes need it)."""
    env = dict(os.environ, RLSENTRY_STATE_DIR=str(state_dir))
    if args[:1] == ("attack",) and "--backend" not in args:
        args = ("attack", "--backend", "local", *args[1:])
    return subprocess.Popen([sys.executable, "-m", "rlsentry", *args], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)


def run_rlsentry(*args, state_dir):
    proc = rlsentry(*args, state_dir=state_dir)
    out, err = proc.communicate(timeout=120)
    return proc.returncode, out, err


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
        self.dir = root / "docker"
        self.dir.mkdir()
        bin_dir = root / "bin"
        bin_dir.mkdir()
        cli = bin_dir / "docker"
        cli.write_text(f'#!/bin/sh\nexec {sys.executable} {Path(__file__).parent / "fakedocker.py"} "$@"\n')
        cli.chmod(0o755)
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
