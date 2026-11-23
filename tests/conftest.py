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
    """Start `rlsentry` as a separate process with its own state dir."""
    env = dict(os.environ, RLSENTRY_STATE_DIR=str(state_dir))
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
