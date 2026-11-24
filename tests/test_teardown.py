"""S-8: nothing is left behind, however a run ends."""

import os
import signal
import time
from pathlib import Path

import pytest

from conftest import FIXTURES, cmdline, residue, rlsentry, run_rlsentry, wait_for_marker


def _alive(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False
    return state != "Z"


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_signal_mid_run_leaves_nothing(state_dir, sig):
    before = residue()
    proc = rlsentry("attack", "--migrations", str(FIXTURES / "slow"), state_dir=state_dir)
    marker, info = wait_for_marker(state_dir)
    time.sleep(1)  # into the attack: the anon read is now waiting on pg_sleep
    assert all(_alive(pid) for pid in info["pids"])

    proc.send_signal(sig)
    _, err = proc.communicate(timeout=60)

    assert proc.returncode == 2, err
    assert "interrupted" in err
    assert not any(_alive(pid) for pid in info["pids"])
    assert not Path(info["run_dir"]).exists()
    assert not marker.exists()
    assert residue() == before


def test_build_failure_leaves_nothing(state_dir):
    before = residue()
    code, _, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "broken"),
                                state_dir=state_dir)
    assert code == 2
    assert "002_broken.sql" in err and "storage" in err
    assert residue() == before
    assert list(state_dir.glob("*.json")) == []


def test_next_run_sweeps_a_killed_run(state_dir):
    before = residue()
    killed = rlsentry("attack", "--migrations", str(FIXTURES / "slow"), state_dir=state_dir)
    marker, info = wait_for_marker(state_dir)
    killed.kill()  # SIGKILL: no teardown can run
    killed.communicate(timeout=10)
    assert marker.exists() and Path(info["run_dir"]).exists()
    assert all(info["run_dir"] in cmdline(pid) for pid in info["pids"])

    code, _, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "clean"),
                                state_dir=state_dir)

    assert code == 0, err
    assert not any(_alive(pid) for pid in info["pids"])
    assert not Path(info["run_dir"]).exists()
    assert not marker.exists()
    assert residue() == before
