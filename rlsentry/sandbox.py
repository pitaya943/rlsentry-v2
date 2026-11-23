"""The disposable copy: built, seeded, handed to the attacker as an AnonChannel, destroyed.

Its servers run on a backend (`rlsentry.backends`: local processes or docker containers).
Teardown runs in `finally`, on SIGINT/SIGTERM, and every run starts with the backend
sweeping what killed runs left (covers `kill -9`).
"""

from __future__ import annotations

import re
import secrets
import signal
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from rlsentry.backends import SIGNALS as _SIGNALS
from rlsentry.backends import Backend, BuildError, select
from rlsentry.channel import AnonChannel, anon_jwt
from rlsentry.seed import fake_row, seed

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


class Interrupted(BaseException):
    """SIGINT or SIGTERM arrived during a run. BaseException so no `except Exception` eats it."""


class Sandbox:
    """Use as a context manager; `anon_channel()` is available only while running."""

    def __init__(self, migrations: Path, backend: str = "local"):
        self._migrations = migrations
        self._backend_name = backend
        self._backend: Backend | None = None
        self._run_id = secrets.token_hex(6)
        self._nonce = secrets.token_hex(16)
        self._jwt_secret = secrets.token_urlsafe(48)
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
            self._backend = select(self._backend_name, self._run_id)
            self._backend.sweep()
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
            if self._backend is not None:
                self._backend.stop()
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
        pg_port = self._backend.start_db({"search_path": SEARCH_PATH, "fsync": "off",
                                          "synchronous_commit": "off", "full_page_writes": "off"})
        self._conn = _connect(pg_port, self._backend)
        self._conn.execute(_SETUP_SQL)
        self._apply_migrations(pg_port)
        self._seed()
        self._snapshot()
        self._conn.execute("insert into rlsentry_run.nonce values (%s)", (self._nonce,))

        self._rest_port = self._backend.start_rest("authenticator", {
            "db-schemas": "public",
            "db-extra-search-path": "public, extensions",
            "db-anon-role": "anon",
            "jwt-secret": self._jwt_secret,
            "log-level": "error",
        })
        _wait_http(self._rest_port, self._backend)
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
        if not self._running or not self._backend.alive():
            raise BuildError("sandbox is not running")
        row = self._conn.execute("select value from rlsentry_run.nonce").fetchone()
        if row is None or row[0] != self._nonce:
            raise BuildError("run nonce missing or different; refusing to attack")

    # signals

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


def _connect(port: int, backend: Backend) -> psycopg.Connection:
    deadline = time.monotonic() + 60
    while True:
        if not backend.alive():
            raise BuildError(f"postgres exited: {backend.log_tail('db')}")
        try:
            return psycopg.connect(host="127.0.0.1", port=port, user="postgres", dbname="postgres",
                                   autocommit=True, connect_timeout=2)
        except psycopg.OperationalError:
            if time.monotonic() > deadline:
                raise BuildError(f"postgres did not accept connections: {backend.log_tail('db')}")
            time.sleep(0.1)


def _wait_http(port: int, backend: Backend) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 60
    while True:
        if not backend.alive():
            raise BuildError(f"postgrest exited: {backend.log_tail('rest')}")
        try:
            with opener.open(f"http://127.0.0.1:{port}/", timeout=2) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() > deadline:
            raise BuildError(f"postgrest did not become ready: {backend.log_tail('rest')}")
        time.sleep(0.1)


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
