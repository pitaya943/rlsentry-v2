"""The local backend: `initdb`/`postgres` and `postgrest` from this machine, as child processes.

Everything a run starts is recorded in a marker file under the state dir (this backend's
"label", design §3). Every run starts by sweeping markers whose owning process is gone
(covers `kill -9`).
"""

from __future__ import annotations

import glob
import json
import os
import pwd
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from rlsentry.backends import BuildError, Unavailable, free_port, signals_blocked, unblock_signals


def state_dir() -> Path:
    if os.environ.get("RLSENTRY_STATE_DIR"):
        return Path(os.environ["RLSENTRY_STATE_DIR"])
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "rlsentry"


def sweep_stale() -> list[str]:
    """Destroy what runs whose rlsentry process is gone left behind. Returns their run ids."""
    swept = []
    for marker in sorted(state_dir().glob("*.json")):
        try:
            info = json.loads(marker.read_text())
        except (OSError, ValueError):
            continue
        if _running(info["owner_pid"]):
            continue
        for pid in info.get("pids", []):  # postgres first, as in teardown
            _stop_foreign(pid, info["run_dir"])
        shutil.rmtree(info["run_dir"], ignore_errors=True)
        marker.unlink(missing_ok=True)
        swept.append(info["run_id"])
    return swept


class LocalBackend:
    name = "local"

    def __init__(self, run_id: str):
        self._run_id = run_id
        self._marker = state_dir() / f"{run_id}.json"
        self._run_dir: Path | None = None
        self._procs: list[tuple[subprocess.Popen, signal.Signals]] = []
        self._db_port = 0

    def prepare(self) -> None:
        self._bins = _find_binaries()
        self._user = _unprivileged_user()

    def sweep(self) -> None:
        sweep_stale()

    def start_db(self, settings: dict[str, str]) -> int:
        with signals_blocked():
            base = "/tmp" if os.geteuid() == 0 else tempfile.gettempdir()
            self._run_dir = Path(tempfile.mkdtemp(prefix="rlsentry-run-", dir=base))
            self._write_marker()
        if self._user:
            os.chown(self._run_dir, self._user.pw_uid, self._user.pw_gid)

        data = self._run_dir / "data"
        init = subprocess.run(
            [self._bins["initdb"], "-D", str(data), "-U", "postgres", "--auth=trust", "-E", "UTF8",
             "--no-sync", "--no-instructions"],
            capture_output=True, text=True, **self._as_user(),
        )
        if init.returncode != 0:
            raise BuildError(f"initdb failed: {init.stderr.strip()}")

        self._db_port = free_port()
        options = {"listen_addresses": "127.0.0.1", "unix_socket_directories": "", **settings}
        self._spawn([self._bins["postgres"], "-D", str(data), "-p", str(self._db_port),
                     *(arg for k, v in options.items() for arg in ("-c", f"{k}={v}"))],
                    "db.log", signal.SIGINT)  # SIGINT = fast shutdown
        return self._db_port

    def start_rest(self, db_user: str, settings: dict[str, str]) -> int:
        port = free_port()
        conf = self._run_dir / "postgrest.conf"
        conf.write_text("".join(f'{k} = "{v}"\n' for k, v in {
            "db-uri": f"postgres://{db_user}@127.0.0.1:{self._db_port}/postgres",
            **settings,
            "server-host": "127.0.0.1",
        }.items()) + f"server-port = {port}\n")
        if self._user:
            os.chown(conf, self._user.pw_uid, self._user.pw_gid)
        self._spawn([self._bins["postgrest"], str(conf)], "rest.log", signal.SIGTERM)
        return port

    def alive(self) -> bool:
        return all(p.poll() is None for p, _ in self._procs)

    def log_tail(self, server: str) -> str:
        try:
            return (self._run_dir / f"{server}.log").read_text(errors="replace").strip()[-800:]
        except (OSError, TypeError):
            return ""

    def stop(self) -> None:
        for proc, sig in self._procs:  # postgres first: ends in-flight queries, so PostgREST can stop
            _stop_child(proc, sig)
        self._procs.clear()
        if self._run_dir is not None:
            shutil.rmtree(self._run_dir, ignore_errors=True)
        self._marker.unlink(missing_ok=True)

    def _as_user(self) -> dict:
        kw = {"cwd": str(self._run_dir), "env": {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}}
        if self._user:
            kw.update(user=self._user.pw_uid, group=self._user.pw_gid, extra_groups=[])
        return kw

    def _spawn(self, argv: list[str], log_name: str, stop_signal: signal.Signals) -> None:
        log = open(self._run_dir / log_name, "wb")
        with signals_blocked():
            proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                    start_new_session=True, preexec_fn=unblock_signals,
                                    **self._as_user())
            self._procs.append((proc, stop_signal))
            self._write_marker()
        log.close()

    def _write_marker(self) -> None:
        self._marker.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._marker.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "run_id": self._run_id,
            "owner_pid": os.getpid(),
            "run_dir": str(self._run_dir),
            "pids": [p.pid for p, _ in self._procs],
        }))
        tmp.replace(self._marker)


def _find_binaries() -> dict[str, str]:
    found, missing = {}, []
    pg_dirs = sorted(glob.glob("/usr/lib/postgresql/*/bin"),
                     key=lambda d: int(Path(d).parent.name) if Path(d).parent.name.isdigit() else 0,
                     reverse=True)
    for name in ("initdb", "postgres"):
        path = shutil.which(name) or next(
            (os.path.join(d, name) for d in pg_dirs if os.access(os.path.join(d, name), os.X_OK)), None)
        if path:
            found[name] = path
        else:
            missing.append(f"PostgreSQL ({name})")
    if shutil.which("postgrest"):
        found["postgrest"] = shutil.which("postgrest")
    else:
        missing.append("PostgREST (postgrest)")
    if missing:
        raise Unavailable("missing on this machine: " + ", ".join(missing))
    return found


def _unprivileged_user() -> pwd.struct_passwd | None:
    """PostgreSQL refuses to run as root; then run it as `postgres` (or nobody)."""
    if os.geteuid() != 0:
        return None
    for name in ("postgres", "nobody"):
        try:
            return pwd.getpwnam(name)
        except KeyError:
            continue
    raise Unavailable("running as root and no unprivileged user (postgres, nobody) to run PostgreSQL as")


def _stop_child(proc: subprocess.Popen, sig: signal.Signals) -> None:
    if proc.poll() is None:
        proc.send_signal(sig)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return ""


def _running(pid: int) -> bool:
    """Alive and not a zombie."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def _stop_foreign(pid: int, run_dir: str) -> None:
    """Stop a process from a dead run, only if its command line still names that run's dir."""
    if run_dir not in _cmdline(pid):
        return
    sig = signal.SIGINT if "postgres" in os.path.basename(_cmdline(pid).split(" ")[0]) else signal.SIGTERM
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 15
    while run_dir in _cmdline(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    if run_dir in _cmdline(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
