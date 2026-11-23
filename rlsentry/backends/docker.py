"""The docker backend: the two servers as containers of pinned images (design §8 D-1).

Both containers carry `rlsentry.run=<run id>` and `rlsentry.owner=<host>/<pid>/<start time>`,
run with `--rm`, and publish ports on 127.0.0.1 only. The run creates nothing else on the
daemon: PostgREST shares the database container's network namespace (no network), and the
database's data directory is a tmpfs (no volume: the image's VOLUME would otherwise give
every run an anonymous one). Teardown removes every container carrying this run's label and
looks again until it sees none; every run starts by removing labelled containers whose
owning process is gone.

Only a daemon on this machine is used: a port published on 127.0.0.1 by a remote daemon is
that machine's loopback, and the channel would reach whatever listens on ours.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from rlsentry.backends import BuildError, Unavailable, free_port

DB_IMAGE = "postgres:16"
REST_IMAGE = "postgrest/postgrest:v12.2.3"
RUN_LABEL = "rlsentry.run"
OWNER_LABEL = "rlsentry.owner"
_LOCAL_SCHEMES = ("unix://", "npipe://")
PGDATA = "/var/lib/postgresql/data"  # the postgres image's VOLUME
RUN_TIMEOUT = 120  # seconds a `docker run` client waits for the daemon
LATE_GRACE = 10  # seconds teardown waits for a container whose `docker run` was cut off
_NO_ANSWER = 124  # _docker's return code when the client got no answer in time


class DockerBackend:
    name = "docker"

    def __init__(self, run_id: str):
        self._run_id = run_id
        self._db = f"rlsentry-{run_id}-db"
        self._rest = f"rlsentry-{run_id}-rest"
        self._started: list[str] = []
        self._unsettled: set[str] = set()  # `docker run` cut off: the daemon may still create it
        self._ports: dict[str, int] = {}

    def prepare(self) -> None:
        version = _docker("version", "--format", "{{.Server.Version}}", timeout=30)
        if version.returncode != 0:
            raise Unavailable(f"no Docker daemon answers: {_last_line(version.stderr)}")
        host = os.environ.get("DOCKER_HOST") or _docker(
            "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").stdout.strip()
        if not host.startswith(_LOCAL_SCHEMES):
            raise Unavailable(f"the Docker daemon is not on this machine ({host or 'unknown endpoint'})")
        for image in (DB_IMAGE, REST_IMAGE):
            if _docker("image", "inspect", image).returncode != 0:
                pull = _docker("pull", image, timeout=900)
                if pull.returncode != 0:
                    raise Unavailable(f"cannot pull {image}: {_last_line(pull.stderr)}")

    def sweep(self) -> None:
        listed = _docker("ps", "-a", "--filter", f"label={RUN_LABEL}",
                         "--format", '{{.ID}}\t{{.Label "%s"}}' % OWNER_LABEL)
        stale = [cid for cid, _, owner in (line.partition("\t") for line in listed.stdout.splitlines())
                 if cid and not _owner_alive(owner)]
        if stale:
            _docker("rm", "-f", *stale)

    def start_db(self, superuser: str, settings: dict[str, str]) -> int:
        # PostgREST will live in this container's network namespace: its port is published here.
        self._ports = {"db": free_port(), "rest": free_port()}
        self._run(self._db, [
            "-p", f"127.0.0.1:{self._ports['db']}:5432",
            "-p", f"127.0.0.1:{self._ports['rest']}:3000",
            "--tmpfs", PGDATA,
            "-e", f"POSTGRES_USER={superuser}", "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
            DB_IMAGE, *(arg for k, v in settings.items() for arg in ("-c", f"{k}={v}")),
        ], {})
        return self._ports["db"]

    def start_rest(self, db_user: str, settings: dict[str, str]) -> int:
        env = {"PGRST_" + k.upper().replace("-", "_"): v for k, v in {
            "db-uri": f"postgres://{db_user}@127.0.0.1:5432/postgres",
            **settings,
            "server-port": "3000",
        }.items()}
        # `-e NAME` takes the value from the docker client's environment: the JWT secret
        # stays off every command line.
        self._run(self._rest, ["--network", f"container:{self._db}",
                               *(arg for name in env for arg in ("-e", name)), REST_IMAGE], env)
        return self._ports["rest"]

    def alive(self) -> bool:
        if not self._started:
            return True
        state = _docker("inspect", "--format", "{{.State.Running}}", *self._started)
        return state.returncode == 0 and state.stdout.split() == ["true"] * len(self._started)

    def log_tail(self, server: str) -> str:
        logs = _docker("logs", "--tail", "20", self._db if server == "db" else self._rest)
        if "No such container" in logs.stderr:
            return "(no log: the container is gone, removed by --rm when it exited)"
        if logs.returncode != 0:
            return f"(no log: docker logs failed: {_last_line(logs.stderr)})"
        return (logs.stdout + logs.stderr).strip()[-800:]

    def stop(self) -> None:
        """Remove this run's containers by label, then look again until none is left. A
        container whose `docker run` was cut off may appear later: wait LATE_GRACE for it."""
        label = f"label={RUN_LABEL}={self._run_id}"
        deadline = time.monotonic() + LATE_GRACE
        while True:
            listed = _docker("ps", "-a", "--filter", label, "--format", "{{.Names}}")
            left = listed.stdout.split()
            if listed.returncode == 0:
                if not left and not self._unsettled:
                    break
                self._unsettled -= set(left)
                if left:
                    _docker("rm", "-f", *left)
            if time.monotonic() > deadline:
                why = (_last_line(listed.stderr) if listed.returncode
                       else f"still there: {', '.join(left)}" if left
                       else "a `docker run` that was cut off may still create one")
                print(f"rlsentry: could not confirm this run's containers are gone ({why}); remove them "
                      f"with: docker rm -f $(docker ps -aq --filter {label}). The next run on the "
                      "docker backend removes them too.", file=sys.stderr)
                break
            time.sleep(0.1)
        self._started.clear()
        self._unsettled.clear()

    def _run(self, name: str, args: list[str], env: dict[str, str]) -> None:
        argv = ["run", "-d", "--rm", "--name", name,
                "--label", f"{RUN_LABEL}={self._run_id}", "--label", f"{OWNER_LABEL}={_owner()}",
                *args]
        self._started.append(name)
        # Until the daemon answers, this container may or may not come into being: a signal
        # (Interrupted) or the timeout can cut the client off while the daemon carries on.
        self._unsettled.add(name)
        run = _docker(*argv, env=env, timeout=RUN_TIMEOUT)
        if run.returncode >= 0 and run.returncode != _NO_ANSWER:
            self._unsettled.discard(name)  # the daemon answered: created or refused
        if run.returncode != 0:
            raise BuildError(f"docker run {name} failed: {_last_line(run.stderr)}")
        if name == self._db:
            self._check_published()

    def _check_published(self) -> None:
        """What the daemon really published for the database container: only our two ports,
        only on 127.0.0.1."""
        wanted = {f"127.0.0.1:{port}" for port in self._ports.values()}
        port = _docker("port", self._db)
        published = {line.split(" -> ")[-1] for line in port.stdout.splitlines()}
        if port.returncode != 0 and not self.alive():
            return  # the container is already gone; _connect reports why
        if published != wanted:
            raise BuildError(f"docker published {sorted(published)}, expected {sorted(wanted)}")


def _docker(*args: str, env: dict[str, str] | None = None, timeout: float = 60) -> subprocess.CompletedProcess:
    """Run the docker CLI. A missing CLI, or one that gets no answer in time, is a failed call
    (the daemon may still carry out a request whose client was cut off)."""
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, **(env or {})})
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", "docker: command not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, _NO_ANSWER, "", f"docker {args[0]}: no answer in {timeout}s")


def _last_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[-1] if lines else "no output"


def _process_key(pid: int) -> str | None:
    """None if `pid` is not a live process; otherwise what tells it apart from a later process
    given the same pid: its kernel start time where /proc has it."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        if Path("/proc/self/stat").exists():
            return None
        try:  # no /proc (macOS): liveness only
            os.kill(pid, 0)
        except ProcessLookupError:
            return None
        except PermissionError:
            pass
        return "alive"
    except OSError:
        return None
    return None if fields[0] == "Z" else fields[19]


def _owner() -> str:
    return f"{socket.gethostname()}/{os.getpid()}/{_process_key(os.getpid())}"


def _owner_alive(owner: str) -> bool:
    """Is the rlsentry process that labelled a container still running? A container from
    another host, or with a label we cannot read, is not ours to judge: treated as alive."""
    host, pid, start = (owner.split("/") + ["", "", ""])[:3]
    if host != socket.gethostname() or not pid.isdigit():
        return True
    return _process_key(int(pid)) == start
