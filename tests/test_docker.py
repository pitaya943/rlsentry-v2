"""D-1 (a) and S-8 on the docker backend.

Most of them run against tests/fakedocker.py: the docker CLI and daemon played by local
PostgreSQL and PostgREST processes, so that failures a real daemon cannot be made to show
(a slow `docker run`, a flaky `rm`, a daemon that dies) can be tested. The tests marked
`real_docker`, at the end, run on a real daemon, and only with `--rlsentry-backend docker`.
"""

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from conftest import FIXTURES, residue, rlsentry, run_rlsentry
from rlsentry.sandbox import BuildError, Sandbox

PACKAGE = Path(__file__).parent.parent / "rlsentry"
EXPECTED = json.loads((PACKAGE / "lab" / "expected.json").read_text())


def _verdicts(out):
    return {f"{f['schema']}.{f['table']}": {op: r["outcome"] for op, r in f["results"].items()}
            for f in json.loads(out)["findings"]}


def _runs(fake):
    return [call[1:] for call in fake.calls() if call[0] == "run"]


def _flag_values(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


def _wait_for_containers(fake, count, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            running = [c for c in fake.containers().values() if c["status"] == "running"]
        except ValueError:  # state.json being written
            running = []
        if len(running) >= count:
            return running
        time.sleep(0.1)
    raise AssertionError("the containers never came up")


def _alive(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def test_lab_on_docker_matches_expected_and_leaves_no_container(fake_docker, state_dir):
    before = residue()
    code, out, err = run_rlsentry("attack", "--backend", "docker", "--lab", "--json", state_dir=state_dir)
    assert code == 1, err
    assert _verdicts(out) == EXPECTED
    assert len(_runs(fake_docker)) == 2  # it really ran on the docker backend
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []
    assert residue() == before


def test_docker_run_binds_127_0_0_1_only_labels_rm_and_pins_both_images(fake_docker, state_dir):
    code, _, err = run_rlsentry("attack", "--backend", "docker", "--migrations",
                                str(FIXTURES / "clean"), state_dir=state_dir)
    assert code == 0, err
    db, rest = _runs(fake_docker)

    for argv in (db, rest):
        assert "--rm" in argv
        assert not {"-P", "--publish-all", "--privileged"} & set(argv)
        assert "host" not in _flag_values(argv, "--network")
    labels = [dict(v.split("=", 1) for v in _flag_values(argv, "--label")) for argv in (db, rest)]
    assert labels[0]["rlsentry.run"] and labels[0]["rlsentry.run"] == labels[1]["rlsentry.run"]

    assert "postgres:16" in db
    assert "postgrest/postgrest:v12.2.3" in rest
    published = _flag_values(db, "-p")
    assert sorted(p.rsplit(":", 1)[1] for p in published) == ["3000", "5432"]
    assert all(re.fullmatch(r"127\.0\.0\.1:\d+:\d+", p) for p in published), published
    assert _flag_values(rest, "-p") == []  # PostgREST is reached through the db container's ports
    assert _flag_values(rest, "--network") == [f"container:{_flag_values(db, '--name')[0]}"]

    # The JWT secret never appears on a command line.
    assert not any("JWT_SECRET=" in arg for call in fake_docker.calls() for arg in call)


@pytest.mark.parametrize("fail", ["daemon", "pull", "remote"])
def test_auto_falls_back_to_local_when_docker_cannot_run(fake_docker, state_dir, fail):
    fake_docker.fail(fail)
    code, out, err = run_rlsentry("attack", "--backend", "auto", "--migrations",
                                  str(FIXTURES / "clean"), state_dir=state_dir)
    assert code == 0, err
    assert "using the local backend" in err
    assert "0 exposed operation(s) in 1 table(s)." in out
    assert _runs(fake_docker) == []
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []


def test_auto_falls_back_to_local_when_there_is_no_docker_cli(tmp_path, state_dir):
    bin_dir = Path(tempfile.mkdtemp(dir="/tmp"))  # reachable for the user PostgreSQL runs as
    bin_dir.chmod(0o755)
    (bin_dir / "postgrest").symlink_to(shutil.which("postgrest"))
    env = dict(os.environ, PATH=str(bin_dir), RLSENTRY_STATE_DIR=str(state_dir))
    run = subprocess.run([sys.executable, "-m", "rlsentry", "attack", "--migrations",
                          str(FIXTURES / "clean")], env=env, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr
    assert "docker unavailable" in run.stderr and "using the local backend" in run.stderr
    shutil.rmtree(bin_dir)


def test_auto_uses_docker_when_it_can_run(fake_docker, state_dir):
    code, _, err = run_rlsentry("attack", "--backend", "auto", "--migrations",
                                str(FIXTURES / "clean"), state_dir=state_dir)
    assert code == 0, err
    assert "using the local backend" not in err
    assert len(_runs(fake_docker)) == 2


@pytest.mark.parametrize("fail, says", [
    ("daemon", "no Docker daemon answers"),
    ("pull", "cannot pull postgres:16"),
    ("remote", "not on this machine"),
])
def test_docker_backend_that_cannot_run_exits_2(fake_docker, state_dir, fail, says):
    fake_docker.fail(fail)
    code, _, err = run_rlsentry("attack", "--backend", "docker", "--migrations",
                                str(FIXTURES / "clean"), state_dir=state_dir)
    assert code == 2
    assert says in err
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []


@pytest.mark.parametrize("fail, says", [
    ("db-exits", "postgres exited: (no log: the container is gone"),
    ("rest-run", "docker run"),
    ("wide-publish", "docker published"),
])
def test_docker_build_failure_exits_2_and_leaves_no_container(fake_docker, state_dir, fail, says):
    before = residue()
    fake_docker.fail(fail)
    code, _, err = run_rlsentry("attack", "--backend", "docker", "--migrations",
                                str(FIXTURES / "clean"), state_dir=state_dir)
    assert code == 2, err
    assert says in err
    assert len(_runs(fake_docker)) >= 1
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []
    assert residue() == before


def test_teardown_looks_again_when_docker_rm_fails(fake_docker, state_dir):
    fake_docker.fail("flaky-rm")
    code, _, err = run_rlsentry("attack", "--backend", "docker", "--migrations",
                                str(FIXTURES / "clean"), state_dir=state_dir)
    assert code == 0, err
    assert (fake_docker.dir / "rm-failed").exists()  # the first rm did fail
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []


def test_docker_migration_failure_exits_2_and_leaves_no_container(fake_docker, state_dir):
    before = residue()
    code, _, err = run_rlsentry("attack", "--backend", "docker", "--migrations",
                                str(FIXTURES / "broken"), state_dir=state_dir)
    assert code == 2
    assert "002_broken.sql" in err and "storage" in err
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []
    assert residue() == before


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_signal_mid_run_on_docker_leaves_no_container(fake_docker, state_dir, sig):
    before = residue()
    proc = rlsentry("attack", "--backend", "docker", "--migrations", str(FIXTURES / "slow"),
                    state_dir=state_dir)
    containers = _wait_for_containers(fake_docker, 2)
    time.sleep(1)  # into the attack: the anon read is now waiting on pg_sleep

    proc.send_signal(sig)
    _, err = proc.communicate(timeout=60)

    assert proc.returncode == 2, err
    assert "interrupted" in err
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []
    assert not any(_alive(pid) for c in containers for pid in c["pids"])
    assert residue() == before


def test_signal_while_docker_run_is_in_flight_leaves_no_container(fake_docker, state_dir):
    """The signal cuts `docker run` short, but the daemon creates the container anyway:
    teardown waits for it, removes it, and stops waiting as soon as it has (no full grace,
    no warning)."""
    before = residue()
    fake_docker.fail("slow-run")
    proc = rlsentry("attack", "--backend", "docker", "--migrations", str(FIXTURES / "clean"),
                    state_dir=state_dir)
    deadline = time.monotonic() + 30
    while not _runs(fake_docker):
        assert time.monotonic() < deadline, "docker run was never called"
        time.sleep(0.02)
    proc.send_signal(signal.SIGINT)
    sent = time.monotonic()
    _, err = proc.communicate(timeout=60)
    took = time.monotonic() - sent
    time.sleep(3)  # longer than the daemon takes to create a container

    assert proc.returncode == 2, err
    assert "interrupted" in err
    assert took < 6, f"teardown took {took:.1f}s: it kept waiting after the container was removed"
    assert "could not confirm" not in err
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []
    assert residue() == before


def test_docker_run_cut_off_by_its_timeout_leaves_no_container(fake_docker, tmp_path, monkeypatch, capsys):
    """The client gives up, the daemon carries on and creates the container later: teardown
    must wait for it rather than trust one look made too early."""
    from rlsentry.backends import docker

    before = residue()
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(docker, "RUN_TIMEOUT", 0.5)  # a daemon slower than the client waits
    fake_docker.fail("slow-run")  # 1.5 s to create, whatever happens to the client
    started = time.monotonic()
    with pytest.raises(BuildError, match="no answer"):
        with Sandbox(FIXTURES / "clean", backend="docker"):
            pass
    took = time.monotonic() - started
    assert took < 6, f"teardown took {took:.1f}s: it kept waiting after the container was removed"
    assert "could not confirm" not in capsys.readouterr().err
    time.sleep(3)
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []
    assert residue() == before


def test_teardown_that_cannot_reach_the_daemon_says_so(fake_docker, tmp_path, monkeypatch, capsys):
    from rlsentry.backends import docker

    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(docker, "LATE_GRACE", 0.5)
    with Sandbox(FIXTURES / "clean", backend="docker") as sb:
        run_id = sb._run_id
        fake_docker.fail_now("daemon")
    err = capsys.readouterr().err
    assert "could not confirm this run's containers are gone" in err
    assert f"label=rlsentry.run={run_id}" in err
    assert "Cannot connect to the Docker daemon" in err


def test_log_tail_says_why_there_is_no_log(fake_docker):
    from rlsentry.backends.docker import DockerBackend

    backend = DockerBackend("nolog")
    assert "the container is gone" in backend.log_tail("db")
    fake_docker.fail_now("daemon")
    said = backend.log_tail("db")
    assert "docker logs failed" in said and "Cannot connect to the Docker daemon" in said


def test_next_docker_run_sweeps_a_killed_run(fake_docker, state_dir):
    killed = rlsentry("attack", "--backend", "docker", "--migrations", str(FIXTURES / "slow"),
                      state_dir=state_dir)
    left = _wait_for_containers(fake_docker, 2)
    killed.kill()  # SIGKILL: no teardown can run
    killed.communicate(timeout=10)
    assert {c["name"] for c in left} <= set(fake_docker.containers())

    code, _, err = run_rlsentry("attack", "--backend", "docker", "--migrations",
                                str(FIXTURES / "clean"), state_dir=state_dir)

    assert code == 0, err
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []
    assert not any(_alive(pid) for c in left for pid in c["pids"])


def test_sweep_spares_live_runs_other_hosts_and_unlabelled_containers(fake_docker, state_dir):
    host = socket.gethostname()
    fake_docker.docker("run", "-d", "--name", "unlabelled", "busybox")
    fake_docker.docker("run", "-d", "--name", "other-host", "--label", "rlsentry.run=x",
                       "--label", "rlsentry.owner=elsewhere/1/1", "busybox")
    live = rlsentry("attack", "--backend", "docker", "--migrations", str(FIXTURES / "slow"),
                    state_dir=state_dir)
    try:
        live_names = {c["name"] for c in _wait_for_containers(fake_docker, 4)} - {"unlabelled", "other-host"}
        assert len(live_names) == 2
        # This pid is alive, but with another start time: a dead run whose pid was reused.
        fake_docker.docker("run", "-d", "--name", "reused-pid", "--label", "rlsentry.run=y",
                           "--label", f"rlsentry.owner={host}/{os.getpid()}/0", "busybox")
        # A dead run's container that was created but never started (its `docker run` failed):
        # only `ps -a` lists it.
        failed_start = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", "never-started", "--label", "rlsentry.run=z",
             "--label", f"rlsentry.owner={host}/{os.getpid()}/0", "--network", "container:unlabelled",
             "postgrest/postgrest:v12.2.3"],
            env=dict(os.environ, FAKE_DOCKER_FAIL="rest-run"), capture_output=True, text=True)
        assert failed_start.returncode != 0 and "never-started" in fake_docker.containers()

        code, _, err = run_rlsentry("attack", "--backend", "docker", "--migrations",
                                    str(FIXTURES / "clean"), state_dir=state_dir)
        assert code == 0, err
        assert set(fake_docker.containers()) == {"unlabelled", "other-host", *live_names}
        assert live.poll() is None
    finally:
        live.send_signal(signal.SIGINT)
        live.communicate(timeout=60)
    assert set(fake_docker.containers()) == {"unlabelled", "other-host"}


@pytest.mark.parametrize("backend", ["local", "docker"])
def test_each_backend_creates_the_cluster_with_the_superuser_the_sandbox_names(fake_docker, tmp_path,
                                                                               monkeypatch, backend):
    import psycopg
    from rlsentry.backends import select

    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    b = select(backend, "superuser-test")
    try:
        port = b.start_db("rlsentry_admin", {})
        deadline = time.monotonic() + 30
        while True:
            try:
                conn = psycopg.connect(host="127.0.0.1", port=port, user="rlsentry_admin",
                                       dbname="postgres", connect_timeout=2)
                break
            except psycopg.OperationalError:
                assert b.alive() and time.monotonic() < deadline, b.log_tail("db")
                time.sleep(0.1)
        with conn:
            assert conn.execute("select rolsuper from pg_roles where rolname = current_user").fetchone() == (True,)
    finally:
        b.stop()
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []


# design §2 on this backend: the nonce check and the running state still guard the channel.

@pytest.fixture
def docker_sandbox(fake_docker, tmp_path, monkeypatch):
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    with Sandbox(FIXTURES / "clean", backend="docker") as sb:
        yield sb


@pytest.mark.parametrize("tamper", [
    "update rlsentry_run.nonce set value = 'someone-else'",
    "delete from rlsentry_run.nonce",
])
def test_docker_first_request_is_refused_when_the_nonce_is_not_ours(docker_sandbox, tamper):
    docker_sandbox._conn.execute(tamper)
    with pytest.raises(BuildError, match="nonce"):
        docker_sandbox.anon_channel().request("GET", "profiles", {"select": "*"})


def test_docker_first_request_is_refused_when_a_container_has_stopped(docker_sandbox, fake_docker):
    rest = next(c for c in fake_docker.containers().values() if c["image"].startswith("postgrest/"))
    os.kill(rest["pids"][0], signal.SIGKILL)
    deadline = time.monotonic() + 10
    while _alive(rest["pids"][0]) and time.monotonic() < deadline:
        time.sleep(0.05)
    with pytest.raises(BuildError, match="not running"):
        docker_sandbox.anon_channel().request("GET", "profiles", {"select": "*"})


def test_docker_sandbox_answers_and_tears_down(fake_docker, tmp_path, monkeypatch):
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    with Sandbox(FIXTURES / "clean", backend="docker") as sb:
        assert sb.anon_channel().request("GET", "profiles", {"select": "*"}).status == 200
        assert len(fake_docker.containers()) == 2
    assert fake_docker.containers() == {}
    assert fake_docker.volumes() == []


# T-06 on this backend: a `protected` write rests on the server's log, PostgreSQL's own account
# of the request. The log is in the container, so the server reads it out (_Log); nothing reads
# this machine's files, which the fake shares and a real daemon does not.

_NO_WRITE_POLICY = """
create table inbox (id bigint generated always as identity primary key, note text);
alter table inbox enable row level security;
"""


@pytest.mark.parametrize("backend", ["local", "docker"])
def test_writes_rls_refuses_are_protected_on_the_servers_own_account(fake_docker, tmp_path,
                                                                    state_dir, backend):
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "001_t.sql").write_text(_NO_WRITE_POLICY)
    code, out, err = run_rlsentry("attack", "--backend", backend, "--migrations", str(folder),
                                  "--json", state_dir=state_dir)
    assert code == 0, err
    results = json.loads(out)["findings"][0]["results"]
    assert results["INSERT"]["outcome"] == "protected"
    assert "row-level security refuses the new row" in results["INSERT"]["basis"]
    for op in ("UPDATE", "DELETE"):
        assert results[op]["outcome"] == "protected"
        assert "row-level security lets it reach no row" in results[op]["basis"]
    assert len(_runs(fake_docker)) == (2 if backend == "docker" else 0)


@pytest.mark.parametrize("backend", ["local", "docker"])
def test_without_the_servers_log_nothing_is_protected(fake_docker, tmp_path, monkeypatch, backend):
    # A server that keeps no jsonlog (as an image or daemon might) gives no account of any
    # request: the same refusals as above, and the read that got 0 rows, are no answer from
    # row-level security (exit 2), never `protected`. The server's settings are given on its
    # command line, which nothing in the database (ALTER SYSTEM included) overrides, so the run
    # itself is what changes. Each operation is tried on its own: the first stops a run.
    import rlsentry.sandbox
    from rlsentry.attacker import Attacker, AttackError

    monkeypatch.setitem(rlsentry.sandbox._EVIDENCE_LOG, "log_destination", "stderr")
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "001_t.sql").write_text(_NO_WRITE_POLICY)
    with Sandbox(folder, backend=backend) as sb:
        assert sb._conn.execute("select pg_current_logfile('jsonlog')").fetchone()[0] is None
        attacker = Attacker(sb.anon_channel(), sb.inspector())
        for op in ("READ", "INSERT", "UPDATE", "DELETE"):
            with pytest.raises(AttackError, match=f"inbox: {op} got no answer from row-level security"):
                getattr(attacker, op.lower())("inbox")


# The real thing: only with `pytest --rlsentry-backend docker`, which makes a real daemon and
# both images ready (tests/realdocker.py) and fails these tests if it cannot.

@pytest.mark.real_docker
def test_lab_on_a_real_docker_daemon_matches_expected_and_leaves_nothing(tmp_path, monkeypatch):
    from rlsentry.attack import LAB, attack

    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    with Sandbox(LAB, backend="docker") as sb:
        run_id = sb._run_id
        mounts = json.loads(subprocess.run(
            ["docker", "inspect", "--format", "{{json .Mounts}}", f"rlsentry-{run_id}-db"],
            capture_output=True, text=True, check=True).stdout)
        findings = attack(sb)
    got = {f"{f.schema}.{f.table}": {op.value: r.outcome.value for op, r in f.results.items()}
           for f in findings}
    assert got == EXPECTED
    assert [m for m in mounts if m["Type"] == "volume"] == []  # the data directory is a tmpfs
    left = subprocess.run(["docker", "ps", "-a", "-q", "--filter", f"label=rlsentry.run={run_id}"],
                          capture_output=True, text=True, check=True).stdout.split()
    assert left == []
