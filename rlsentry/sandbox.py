"""The disposable copy: built, seeded, handed to the attacker as an AnonChannel, destroyed.

Everything a run starts is recorded in a marker file under the state dir (the local
backend's "label", design §3). Teardown runs in `finally`, on SIGINT/SIGTERM, and every run
starts by sweeping markers whose owning process is gone (covers `kill -9`).
"""

from __future__ import annotations

import glob
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from rlsentry.channel import AnonChannel, anon_jwt
from rlsentry.seed import fake_row, seed

_SIGNALS = (signal.SIGINT, signal.SIGTERM)

_SETUP_SQL = """
create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
create role authenticator login noinherit;
grant anon, authenticated, service_role to authenticator;
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
create schema rlsentry_run;
create table rlsentry_run.nonce (value text not null);

-- Extensions where Supabase puts them (on the search path: SEARCH_PATH below).
create schema extensions;
create extension pgcrypto with schema extensions;
create extension "uuid-ossp" with schema extensions;
grant usage on schema extensions to anon, authenticated, service_role;

-- The auth stand-in: the parts of Supabase's auth schema that migrations and policies use.
-- The functions read the claims PostgREST sets for each request, as Supabase's do.
create schema auth;
grant usage on schema auth to anon, authenticated, service_role;
-- auth.users has the columns of Supabase's own that triggers on it read.
create table auth.users (
  instance_id uuid,
  id uuid primary key default gen_random_uuid(),
  aud varchar(255) default 'authenticated',
  role varchar(255) default 'authenticated',
  email varchar(255),
  encrypted_password varchar(255),
  email_confirmed_at timestamptz,
  invited_at timestamptz,
  confirmation_sent_at timestamptz,
  recovery_sent_at timestamptz,
  last_sign_in_at timestamptz,
  raw_app_meta_data jsonb default '{}',
  raw_user_meta_data jsonb default '{}',
  is_super_admin boolean,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  phone text default null,
  phone_confirmed_at timestamptz,
  confirmed_at timestamptz generated always as (least(email_confirmed_at, phone_confirmed_at)) stored,
  banned_until timestamptz,
  is_sso_user boolean not null default false,
  deleted_at timestamptz,
  is_anonymous boolean not null default false
);
create function auth.uid() returns uuid language sql stable as $$
  select (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')::uuid
$$;
create function auth.role() returns text language sql stable as $$
  select nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'
$$;
create function auth.jwt() returns jsonb language sql stable as $$
  select nullif(current_setting('request.jwt.claims', true), '')::jsonb
$$;
"""

# Supabase's search path, for every connection: the server's default covers this process's
# connections and the migrations'; PostgREST sets its own per request (db-extra-search-path).
SEARCH_PATH = '"$user", public, extensions'


class BuildError(Exception):
    """The copy could not be built (or stopped being the copy we built)."""


class Interrupted(BaseException):
    """SIGINT or SIGTERM arrived during a run. BaseException so no `except Exception` eats it."""


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


class Sandbox:
    """Use as a context manager; `anon_channel()` is available only while running."""

    def __init__(self, migrations: Path):
        self._migrations = migrations
        self._run_id = secrets.token_hex(6)
        self._nonce = secrets.token_hex(16)
        self._jwt_secret = secrets.token_urlsafe(48)
        self._marker = state_dir() / f"{self._run_id}.json"
        self._run_dir: Path | None = None
        self._procs: list[tuple[subprocess.Popen, signal.Signals]] = []
        self._conn: psycopg.Connection | None = None
        self._old_handlers: dict = {}
        self._running = False
        self._rest_port = 0
        self.tables: list[str] = []
        self.notes: dict[str, list[str]] = {}

    # lifecycle

    def __enter__(self) -> "Sandbox":
        self._install_signal_handlers()
        try:
            sweep_stale()
            self._build()
        except BaseException:
            self.teardown()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.teardown()

    def teardown(self) -> None:
        with _signals_ignored():
            self._running = False
            if self._conn is not None:
                try:
                    self._conn.close()
                except psycopg.Error:
                    pass
                self._conn = None
            for proc, sig in self._procs:  # postgres first: ends in-flight queries, so PostgREST can stop
                _stop_child(proc, sig)
            self._procs.clear()
            if self._run_dir is not None:
                shutil.rmtree(self._run_dir, ignore_errors=True)
            self._marker.unlink(missing_ok=True)
        self._restore_signal_handlers()

    def anon_channel(self) -> AnonChannel:
        if not self._running:
            raise RuntimeError("anon_channel() needs a running sandbox")
        return AnonChannel(self._rest_port, anon_jwt(self._jwt_secret), self._verify)

    def inspector(self) -> "Inspector":
        if not self._running:
            raise RuntimeError("inspector() needs a running sandbox")
        return Inspector(self._conn)

    def restore(self) -> None:
        """Put every table back to its seeded state, so one attack cannot hide another (§4)."""
        with self._conn.transaction():
            # replica: no FK checks or triggers while the tables are briefly empty
            self._conn.execute("set local session_replication_role = replica")
            for i, table in enumerate(self.tables):
                cols = sql.SQL(", ").join(map(sql.Identifier, _stored_columns(self._conn, table)))
                target = sql.Identifier("public", table)
                self._conn.execute(sql.SQL("delete from {}").format(target))
                self._conn.execute(sql.SQL("insert into {} ({}) overriding system value select {} from {}")
                                   .format(target, cols, cols, sql.Identifier("rlsentry_run", f"seeded_{i}")))

    # build (design §3)

    def _build(self) -> None:
        bins = _find_binaries()
        self._user = _unprivileged_user()
        with _signals_blocked():
            base = "/tmp" if os.geteuid() == 0 else tempfile.gettempdir()
            self._run_dir = Path(tempfile.mkdtemp(prefix="rlsentry-run-", dir=base))
            self._write_marker()
        if self._user:
            os.chown(self._run_dir, self._user.pw_uid, self._user.pw_gid)

        data = self._run_dir / "data"
        init = subprocess.run(
            [bins["initdb"], "-D", str(data), "-U", "postgres", "--auth=trust", "-E", "UTF8",
             "--no-sync", "--no-instructions"],
            capture_output=True, text=True, **self._as_user(),
        )
        if init.returncode != 0:
            raise BuildError(f"initdb failed: {init.stderr.strip()}")

        pg_port = _free_port()
        pg = self._spawn(
            [bins["postgres"], "-D", str(data), "-p", str(pg_port),
             "-c", "listen_addresses=127.0.0.1", "-c", "unix_socket_directories=",
             "-c", f"search_path={SEARCH_PATH}",
             "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"],
            "postgres.log", signal.SIGINT,  # SIGINT = fast shutdown
        )
        self._conn = _connect(pg_port, pg, self._run_dir / "postgres.log")
        self._conn.execute(_SETUP_SQL)
        self._apply_migrations(pg_port)
        self._seed()
        self._snapshot()
        self._conn.execute("insert into rlsentry_run.nonce values (%s)", (self._nonce,))

        self._rest_port = _free_port()
        conf = self._run_dir / "postgrest.conf"
        conf.write_text(
            f'db-uri = "postgres://authenticator@127.0.0.1:{pg_port}/postgres"\n'
            'db-schemas = "public"\n'
            'db-extra-search-path = "public, extensions"\n'
            'db-anon-role = "anon"\n'
            f'jwt-secret = "{self._jwt_secret}"\n'
            'server-host = "127.0.0.1"\n'
            f"server-port = {self._rest_port}\n"
            'log-level = "error"\n'
        )
        if self._user:
            os.chown(conf, self._user.pw_uid, self._user.pw_gid)
        rest = self._spawn([bins["postgrest"], str(conf)], "postgrest.log", signal.SIGTERM)
        _wait_http(self._rest_port, rest, self._run_dir / "postgrest.log")
        self._running = True

    def _apply_migrations(self, port: int) -> None:
        """Each file in one transaction on a connection of its own, as the Supabase CLI applies
        them: split into statements here, each sent to the server as it is. Nothing in a file
        is run by a client, so a psql meta-command is a syntax error, as it is there."""
        files = sorted(self._migrations.glob("*.sql"))
        if not files:
            raise BuildError(f"no .sql migrations in {self._migrations}")
        for path in files:
            text = path.read_text()
            with psycopg.connect(host="127.0.0.1", port=port, user="postgres", dbname="postgres",
                                 autocommit=True) as conn:
                start = 0
                try:
                    with conn.transaction():
                        for start, statement in _statements(text):
                            conn.execute(statement)
                except psycopg.Error as err:
                    pos = err.diag.statement_position
                    at = start + int(pos) - 1 if pos else start
                    detail = err.diag.message_primary or str(err).splitlines()[0]
                    if err.diag.message_hint:
                        detail += f" (hint: {err.diag.message_hint})"
                    raise BuildError(f"migration {path.name} failed at line "
                                     f"{text.count(chr(10), 0, at) + 1}: {detail}") from None

    def _seed(self) -> None:
        self.tables = [r[0] for r in self._conn.execute(
            "select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace"
            " where n.nspname = 'public' and c.relkind in ('r', 'p') order by c.relname"
        )]
        seeded = seed(self._conn, [("public", t) for t in self.tables])  # + auth.users etc. they reference
        empty = [f"{s}.{t}: {r.reason}" for (s, t), r in seeded.items() if r.rows == 0]
        if empty:
            # An empty table says nothing about its policies: never attack a partial copy.
            raise BuildError("could not seed " + "; ".join(empty))
        self.notes = {t: [r.note] for (s, t), r in seeded.items() if s == "public"}

    def _snapshot(self) -> None:
        for i, table in enumerate(self.tables):
            self._conn.execute(sql.SQL("create table {} as select * from {}").format(
                sql.Identifier("rlsentry_run", f"seeded_{i}"), sql.Identifier("public", table)))

    def _verify(self) -> None:
        """Called by the channel before its first request: is this still our copy?"""
        if not self._running or any(p.poll() is not None for p, _ in self._procs):
            raise BuildError("sandbox is not running")
        row = self._conn.execute("select value from rlsentry_run.nonce").fetchone()
        if row is None or row[0] != self._nonce:
            raise BuildError("run nonce missing or different; refusing to attack")

    # processes and markers

    def _as_user(self) -> dict:
        kw = {"cwd": str(self._run_dir), "env": {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}}
        if self._user:
            kw.update(user=self._user.pw_uid, group=self._user.pw_gid, extra_groups=[])
        return kw

    def _spawn(self, argv: list[str], log_name: str, stop_signal: signal.Signals) -> subprocess.Popen:
        log = open(self._run_dir / log_name, "wb")
        with _signals_blocked():
            # The child must not inherit the blocked mask, or it would ignore our stop signal.
            proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                    start_new_session=True, preexec_fn=_unblock_signals,
                                    **self._as_user())
            self._procs.append((proc, stop_signal))
            self._write_marker()
        log.close()
        return proc

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

    def _install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return

        def handler(signum, _frame):
            raise Interrupted(signal.Signals(signum).name)

        for sig in _SIGNALS:
            self._old_handlers[sig] = signal.signal(sig, handler)

    def _restore_signal_handlers(self) -> None:
        for sig, old in self._old_handlers.items():
            signal.signal(sig, old)
        self._old_handlers.clear()


class Inspector:
    """Superuser reads the attacker uses to confirm what its requests really did (design §4).

    It holds the sandbox's superuser connection and never hands it out."""

    def __init__(self, conn: psycopg.Connection):
        self._conn = conn

    def primary_key(self, table: str) -> list[str]:
        return [r[0] for r in self._conn.execute(
            "select a.attname from pg_index i join pg_attribute a"
            " on a.attrelid = i.indrelid and a.attnum = any(i.indkey)"
            " where i.indrelid = format('public.%%I', %s::text)::regclass and i.indisprimary"
            " order by array_position(i.indkey, a.attnum)", (table,))]

    def rows(self, table: str) -> list[dict]:
        cur = self._conn.cursor(row_factory=dict_row)
        return cur.execute(sql.SQL("select * from {}").format(sql.Identifier("public", table))).fetchall()

    def fake_row(self, table: str) -> dict[str, str] | None:
        """A fresh fake row, different from every seeded one; None if one cannot be made."""
        return fake_row(self._conn, "public", table)


# helpers

_TOKEN = re.compile(r"""
    (?P<space>\s+)
  | (?P<comment>--[^\n]*)
  | (?P<block>/\*)
  | (?P<string>[eE]'(?:[^'\\]|\\.|'')*(?:'|\Z)|'(?:[^']|'')*(?:'|\Z)|"(?:[^"]|"")*(?:"|\Z))
  | (?P<dollar>\$(?:[^\W\d]\w*)?\$)
  | (?P<word>[^\W\d]\w*(?:\$\w*)*)
  | (?P<char>.)
""", re.X | re.S)


def _statements(text: str) -> list[tuple[int, str]]:
    """Split a migration into statements, each with the offset it starts at. Semicolons end a
    statement unless they are inside quotes, a dollar-quoted body, a comment, parentheses, or
    the BEGIN ... END body of a CREATE FUNCTION/PROCEDURE (as psql and the Supabase CLI split)."""
    out, start, pos, parens, depth, words = [], None, 0, 0, 0, []
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        kind, end = m.lastgroup, m.end()
        if kind == "block":  # nested /* */
            level = 1
            while level and end < len(text):
                nxt = min((i for i in (text.find("/*", end), text.find("*/", end)) if i >= 0),
                          default=len(text))
                level += 1 if text.startswith("/*", nxt) else -1
                end = nxt + 2
        elif kind == "dollar":
            close = text.find(m[0], end)
            end = len(text) if close < 0 else close + len(m[0])
        if kind in ("space", "comment", "block"):
            pos = end
            continue
        if start is None:
            start = pos
        if kind == "word":
            word = m[0].lower()
            words.append(word)
            routine = (words[0] == "create" and len(words) > 1
                       and (words[1] in ("function", "procedure")
                            or words[1:3] == ["or", "replace"] and len(words) > 3
                            and words[3] in ("function", "procedure")))
            if routine and parens == 0:
                if word == "begin" or (word == "case" and depth and words[-2] != "end"):
                    depth += 1
                elif word == "end" and depth:
                    depth -= 1
        elif m[0] == "(":
            parens += 1
        elif m[0] == ")":
            parens = max(parens - 1, 0)
        elif m[0] == ";" and parens == 0 and depth == 0:
            out.append((start, text[start:end]))
            start, words = None, []
        pos = end
    if start is not None:
        out.append((start, text[start:]))
    return out

def _stored_columns(conn: psycopg.Connection, table: str) -> list[str]:
    return [r[0] for r in conn.execute(
        "select attname from pg_attribute where attrelid = format('public.%%I', %s::text)::regclass"
        " and attnum > 0 and not attisdropped and attgenerated = '' order by attnum", (table,))]


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
        raise BuildError("missing on this machine: " + ", ".join(missing))
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
    raise BuildError("running as root and no unprivileged user (postgres, nobody) to run PostgreSQL as")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _log_tail(path: Path) -> str:
    try:
        return path.read_text(errors="replace").strip()[-800:]
    except OSError:
        return ""


def _connect(port: int, proc: subprocess.Popen, log: Path) -> psycopg.Connection:
    deadline = time.monotonic() + 30
    while True:
        if proc.poll() is not None:
            raise BuildError(f"postgres exited: {_log_tail(log)}")
        try:
            return psycopg.connect(host="127.0.0.1", port=port, user="postgres", dbname="postgres",
                                   autocommit=True, connect_timeout=2)
        except psycopg.OperationalError:
            if time.monotonic() > deadline:
                raise BuildError(f"postgres did not accept connections: {_log_tail(log)}")
            time.sleep(0.1)


def _wait_http(port: int, proc: subprocess.Popen, log: Path) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 30
    while True:
        if proc.poll() is not None:
            raise BuildError(f"postgrest exited: {_log_tail(log)}")
        try:
            with opener.open(f"http://127.0.0.1:{port}/", timeout=2) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() > deadline:
            raise BuildError(f"postgrest did not become ready: {_log_tail(log)}")
        time.sleep(0.1)


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


def _unblock_signals() -> None:
    signal.pthread_sigmask(signal.SIG_UNBLOCK, _SIGNALS)


@contextmanager
def _signals_blocked():
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    old = signal.pthread_sigmask(signal.SIG_BLOCK, _SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


@contextmanager
def _signals_ignored():
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    old = {sig: signal.signal(sig, signal.SIG_IGN) for sig in _SIGNALS}
    try:
        yield
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)
