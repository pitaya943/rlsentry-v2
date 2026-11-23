"""How the copy's two servers run (design §8 D-1): one `Backend` interface, two backends.

A backend starts PostgreSQL 16 and PostgREST on 127.0.0.1, says whether both are still the
servers it started, and destroys everything it started. What goes into the database and the
REST layer's settings belong to the sandbox, the same for every backend.
"""

from __future__ import annotations

import signal
import socket
import sys
import threading
from contextlib import contextmanager
from typing import Protocol

SIGNALS = (signal.SIGINT, signal.SIGTERM)


class BuildError(Exception):
    """The copy could not be built (or stopped being the copy we built)."""


class Unavailable(Exception):
    """This backend cannot run here (no daemon, an image cannot be pulled, ...)."""


class Backend(Protocol):
    name: str

    def prepare(self) -> None:
        """Check this backend can run here; raise Unavailable if not. Starts nothing."""

    def sweep(self) -> None:
        """Destroy what earlier runs of this backend, whose rlsentry process is gone, left."""

    def start_db(self, superuser: str, settings: dict[str, str]) -> int:
        """Start PostgreSQL with a new cluster whose superuser is `superuser` (trust
        authentication) and these server settings, on 127.0.0.1; return its port."""

    def start_rest(self, db_user: str, settings: dict[str, str]) -> int:
        """Start PostgREST as `db_user` with these settings on 127.0.0.1; return its port."""

    def alive(self) -> bool:
        """Is every server started so far still running, and still the one we started?"""

    def log_tail(self, server: str) -> str:
        """The end of a server's log ("db" or "rest"), for error messages."""

    def stop(self) -> None:
        """Destroy everything this run started. Idempotent; never raises."""


def select(name: str, run_id: str) -> Backend:
    """The backend to run on. `auto` is docker when it can run here, otherwise local."""
    from rlsentry.backends.docker import DockerBackend
    from rlsentry.backends.local import LocalBackend

    if name == "auto":
        docker = DockerBackend(run_id)
        try:
            docker.prepare()
            return docker
        except Unavailable as err:
            why = err
        local = LocalBackend(run_id)
        try:
            local.prepare()
        except Unavailable as err:
            raise BuildError(f"neither backend can run here: docker: {why}; local: {err}") from None
        print(f"rlsentry: docker unavailable ({why}); using the local backend", file=sys.stderr)
        return local
    backend = {"docker": DockerBackend, "local": LocalBackend}[name](run_id)
    try:
        backend.prepare()
    except Unavailable as err:
        raise BuildError(f"{name} backend: {err}") from None
    return backend


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def unblock_signals() -> None:
    """preexec_fn for children started while SIGNALS are blocked: they must not inherit the mask."""
    signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGNALS)


@contextmanager
def signals_blocked():
    """Hold SIGINT/SIGTERM until the block ends, so starting a server and recording it is one step."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    old = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)
