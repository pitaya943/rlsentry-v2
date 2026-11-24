"""The disposable copy: built, seeded, handed to the attacker as an AnonChannel, destroyed.

Its servers run on a backend (`rlsentry.backends`: local processes or docker containers).
Teardown runs in `finally`, on SIGINT/SIGTERM, and every run starts with the backend
sweeping what killed runs left (covers `kill -9`).
"""

from __future__ import annotations

import json
import re
import secrets
import signal
import threading
import time
import urllib.error
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from rlsentry.backends import SIGNALS as _SIGNALS
from rlsentry.backends import Backend, BuildError, select
from rlsentry.channel import OPENER, REQUEST_HEADER, AnonChannel, anon_jwt
from rlsentry.seed import fake_row, seed, update_values

_SETUP_SQL = """
create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
create role authenticator login noinherit;
grant anon, authenticated, service_role to authenticator;
grant usage on schema public to anon, authenticated, service_role;

-- Migrations, seeding and restoring run as `postgres`, shaped like hosted Supabase's: it owns
-- what migrations create and bypasses RLS, but it is not a superuser, so nothing a migration
-- says can reach the host (COPY ... PROGRAM or a server file, untrusted extensions or
-- languages, server-side large objects). The superuser (supabase_admin, as on Supabase) only
-- sets the copy up, writes the nonce and checks what attacks did.
create role postgres login createrole bypassrls;
grant anon, authenticated, service_role to postgres;
grant create, temporary on database postgres to postgres;
grant all on schema public to postgres;
grant set on parameter session_replication_role to postgres;  -- restore() turns FK checks off
alter default privileges for role postgres in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges for role postgres in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges for role postgres in schema public grant all on functions to anon, authenticated, service_role;
alter role authenticator set log_statement = 'all';  -- names the request (Evidence)
alter role authenticator set auto_explain.log_min_duration = 0;
alter role authenticator set auto_explain.log_analyze = on;
alter role authenticator set auto_explain.log_timing = off;
alter role authenticator set auto_explain.log_format = json;
alter role authenticator set auto_explain.log_verbose = on;  -- names each relation's schema
create schema rlsentry_run;
create table rlsentry_run.nonce (value text not null);
create schema rlsentry_seeded authorization postgres;  -- restore()'s copies of the seeded tables

-- Extensions where Supabase puts them (on the search path: SCHEMAS_ON_PATH below).
create schema extensions;
create extension pgcrypto with schema extensions;
create extension "uuid-ossp" with schema extensions;
create extension pg_stat_statements with schema extensions;
grant usage on schema extensions to postgres, anon, authenticated, service_role;

-- The auth stand-in: the parts of Supabase's auth schema that migrations and policies use.
-- The functions read the claims PostgREST sets for each request, as Supabase's do.
create schema auth;
grant usage on schema auth to postgres, anon, authenticated, service_role;
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
grant all on auth.users to postgres;
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

# Supabase's search path: the server's default (migrations, seeding) and PostgREST's per
# request (db-extra-search-path). The superuser's own connection searches pg_catalog only, so
# a migration's function named like a built-in is never called by it.
SCHEMAS_ON_PATH = "public, extensions"
POSTGREST_SEARCH_PATH = '"public", "public", "extensions"'  # db-schemas, then the extra path
SUPERUSER = "supabase_admin"  # the cluster's superuser: every backend creates the cluster with it
# PostgreSQL's own account of each request PostgREST makes, in a log only the sandbox reads
# (Evidence): each error with the C function that raised it, and each statement's plan with the
# rows it really reached. authenticator's settings (_SETUP_SQL) turn the logging on for its
# sessions alone; none of them can be changed by a role that is not a superuser. The log is a
# file in the cluster's data directory, read over the superuser's connection (`_Log`), so it is
# read the same way whichever backend runs the server.
_EVIDENCE_LOG = {"logging_collector": "on", "log_destination": "jsonlog", "log_directory": "log",
                 "log_rotation_age": "0", "log_rotation_size": "0",
                 "log_error_verbosity": "verbose", "shared_preload_libraries": "auto_explain"}
# For each statement on the postgres connection: a migration's function that never returns
# (a domain CHECK, a trigger) stops the run instead of hanging it.
STATEMENT_TIMEOUT = "30s"


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
        self._conn: psycopg.Connection | None = None  # superuser: setup, nonce, checks
        self._app: psycopg.Connection | None = None   # postgres: anything running migration code
        self._log: _Log | None = None
        self._columns: dict[str, list[str]] = {}
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
            for conn in (self._app, self._conn):
                if conn is not None:
                    try:
                        conn.close()
                    except psycopg.Error:
                        pass
            self._app = self._conn = None
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
        return Inspector(self._conn, self._app, self._log)

    def restore(self) -> None:
        """Put every table back to its seeded state, so one attack cannot hide another (§4)."""
        with self._app.transaction():
            # replica: no FK checks or triggers while the tables are briefly empty
            self._app.execute("set local session_replication_role = replica")
            for i, table in enumerate(self.tables):
                cols = sql.SQL(", ").join(map(sql.Identifier, self._columns[table]))
                target = sql.Identifier("public", table)
                self._app.execute(sql.SQL("delete from {}").format(target))
                self._app.execute(sql.SQL("insert into {} ({}) overriding system value select {} from {}")
                                  .format(target, cols, cols, sql.Identifier("rlsentry_seeded", f"seeded_{i}")))

    # build (design §3)

    def _build(self) -> None:
        pg_port = self._backend.start_db(SUPERUSER, {"search_path": f'"$user", {SCHEMAS_ON_PATH}',
                                                     "fsync": "off", "synchronous_commit": "off",
                                                     "full_page_writes": "off", **_EVIDENCE_LOG})
        self._conn = _connect(pg_port, self._backend)
        self._log = _Log(self._conn)
        self._conn.execute(_SETUP_SQL)
        self._apply_migrations(pg_port)
        self._app = psycopg.connect(host="127.0.0.1", port=pg_port, user="postgres",
                                    dbname="postgres", autocommit=True,
                                    options=f"-c statement_timeout={STATEMENT_TIMEOUT}")
        self._seed()
        self._snapshot()
        self._conn.execute("insert into rlsentry_run.nonce values (%s)", (self._nonce,))

        self._rest_port = self._backend.start_rest("authenticator", {
            "db-schemas": "public",
            "db-extra-search-path": SCHEMAS_ON_PATH,
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
        seeded = seed(self._app, [("public", t) for t in self.tables])  # + auth.users etc. they reference
        empty = [f"{s}.{t}: {r.reason}" for (s, t), r in seeded.items() if r.rows == 0]
        if empty:
            # An empty table says nothing about its policies: never attack a partial copy.
            raise BuildError("could not seed " + "; ".join(empty))
        self.notes = {t: [r.note] for (s, t), r in seeded.items() if s == "public"}

    def _snapshot(self) -> None:
        for i, table in enumerate(self.tables):
            self._columns[table] = _stored_columns(self._conn, table)
            self._app.execute(sql.SQL("create table {} as select * from {}").format(
                sql.Identifier("rlsentry_seeded", f"seeded_{i}"), sql.Identifier("public", table)))

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

    def __init__(self, conn: psycopg.Connection, app: psycopg.Connection, log: "_Log"):
        self._conn = conn
        self._app = app  # postgres: for anything that runs the table's own code
        self._log = log

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
        return fake_row(self._app, "public", table)

    def update_values(self, table: str) -> dict[str, str]:
        """A fresh value for every column an update can set."""
        return update_values(self._app, "public", table)

    def would_change(self, table: str, column: str, value, row: dict | None) -> bool:
        """Would setting `column` to `value` change `row` (by primary key), or any row if None?
        An update that writes the value already there changes nothing a check could see."""
        key = self.primary_key(table) if row is not None else []
        where = sql.SQL(" and ").join(
            sql.SQL("{} = %s::{}").format(sql.Identifier(k), sql.SQL(self._type(table, k)))
            for k in key) if key else sql.SQL("true")
        with self._app.transaction(force_rollback=True):  # a cast can run a domain's CHECK
            return self._app.execute(
                sql.SQL("select coalesce(bool_or({} is distinct from %s::{}), false) from {} where {}")
                .format(sql.Identifier(column), sql.SQL(self._type(table, column)),
                        sql.Identifier("public", table), where),
                [value] + [str(row[k]) for k in key]).fetchone()[0]

    def holds_rows(self, table: str, raw: bytes) -> bool:
        """Is every row of `raw` (a JSON array, as the answer carried it) a row of `table` as
        the superuser sees it, each row of the table counted once? Compared as jsonb, so as
        values (1000 is 1e3), not as Python reads them; each row is written out under
        PostgREST's search path, as the answer's were (a regclass names its table by it). Every
        name in the statement is qualified, so the path cannot bring a migration's code in."""
        with self._conn.transaction():
            self._conn.execute("select pg_catalog.set_config('search_path', %s, true)",
                               [POSTGREST_SEARCH_PATH])
            return self._conn.execute(sql.SQL(
                "select not exists (select value from"
                " pg_catalog.jsonb_array_elements(%s::pg_catalog.jsonb) except all select pg_catalog.to_jsonb(t.*) from {} as t)").format(
                sql.Identifier("public", table)), [raw.decode()]).fetchone()[0]

    def read_refused(self, table: str, request_id: str | None) -> bool:
        """Did row-level security (or a missing grant) keep every row of `table` from the GET
        PostgREST ran as `request_id`? Only PostgreSQL's own account of that request (`_said`)
        can say yes: a missing grant on this table raised by the privilege check, or the
        request's plan showing that no row of the table reached it."""
        return self._said("SELECT", table, request_id) in (("grant", table), ("using", table))

    def rls_refusal(self, op: str, table: str, values: dict | None, row: dict | None,
                    settings: dict[str, str], request_id: str | None) -> str | None:
        """Did row-level security (or a missing grant) refuse the write PostgREST ran as
        `request_id`? The reason if so, else None.

        Only PostgreSQL's own account of that request (`_said`, from the server's log) can say
        yes: the error that ended it was raised by RLS's WITH CHECK or by the privilege check,
        or, for an UPDATE or DELETE that changed nothing, its plan shows that no row reached the
        write. rlsentry's own evaluation of the policies (`_evaluate`) must then agree. It runs
        outside the request (another session, statement and trigger depth), so it can take
        that answer away but never give it."""
        ours = self._evaluate(op, table, values, row, settings)
        theirs = self._said(op, table, request_id)
        if ours is None or theirs is None or ours[:2] != theirs:
            return None
        return ours[2]

    def _said(self, op: str, table: str, request_id: str | None) -> tuple[str, str] | None:
        """What PostgreSQL said refused the request (`op` is SELECT for a GET): ("grant",
        table), ("check", the table whose WITH CHECK refused a row) or ("using", table) for no
        row reached; None for anything else. Raised in the server's C code (the function the
        log names), which nothing a migration says can do in its stead: a RAISE is logged as
        PL/pgSQL's."""
        entries = self._log.request(request_id)
        error = next((e for e in entries if e.get("error_severity") == "ERROR"), None)
        if error is not None:
            message, nested = error.get("message") or "", bool(error.get("context"))
            if error.get("state_code") != "42501":
                return None
            if (error.get("func_name") == "aclcheck_error" and not nested
                    and message == f'permission denied for table {table}'):
                return ("grant", table)
            if (error.get("func_name") == "ExecWithCheckOptions"
                    and message.startswith("new row violates row-level security policy ")
                    and ' for table "' in message and message.endswith('"')):
                refused = message.rpartition(' for table "')[2][:-1]
                # the request's own row is checked at its top level; a row the table's code
                # writes elsewhere (a trigger: fp2) is checked inside that code
                if (refused == table) != nested:
                    return ("check", refused)
            return None
        if op == "INSERT" or not entries:
            return None
        # auto_explain's own entries (explain_ExecutorEnd: a RAISE is logged as PL/pgSQL's),
        # one per statement PostgREST sent: nested ones are not logged (superuser-only setting)
        plans = [json.loads(e["message"].partition("plan:\n")[2])["Plan"] for e in entries
                 if e.get("func_name") == "explain_ExecutorEnd"]
        if op == "SELECT":
            # PostgREST's read is the one aggregate (json_agg) over the table, with no filter
            # of its own: only the policies' USING can keep a row from it. No row fed it.
            fed = [n.get("Actual Rows") for p in plans if p.get("Node Type") == "Aggregate"
                   for n in p.get("Plans", []) if n.get("Parent Relationship") == "Outer"]
            return ("using", table) if fed == [0] else None
        writes = [node for plan in plans for node in _nodes(plan)
                  if node.get("Node Type") == "ModifyTable" and node.get("Schema") == "public"
                  and node.get("Relation Name") == table]
        if len(writes) != 1 or writes[0].get("Operation") != op.title():
            return None
        fed = [n for n in writes[0].get("Plans", []) if n.get("Parent Relationship") == "Outer"]
        # No row came out of the scan below PostgREST's own write, though the target rows were
        # there (_evaluate checks): only the scan's quals drop rows, which are PostgREST's
        # filter and the policies' USING. A rule cannot add its own: PostgREST's RETURNING
        # refuses a conditional INSTEAD rule, and an unconditional one replaces the write.
        if len(fed) != 1 or fed[0].get("Actual Loops") != 1 or fed[0].get("Actual Rows") != 0:
            return None
        return ("using", table)

    def _evaluate(self, op: str, table: str, values: dict | None, row: dict | None,
                  settings: dict[str, str]) -> tuple[str, str, str] | None:
        """rlsentry's own reading of anon's policies for this write, as (what refused, the
        table, why), or None if they do not refuse it. Decided from the policies as PostgreSQL
        combines them, for every row the write reaches (`row` picks one by primary key, as the
        attack's filter did; None means every row).

        The rows are the ones PostgreSQL checks: the target rows against USING, and the new row
        (after defaults and BEFORE ROW triggers) against WITH CHECK, caught by a trigger of ours
        that fires after the table's own and drops the row. The policies run as anon with
        PostgREST's settings for the request (`settings`, from the channel), on the `postgres`
        connection, rolled back, under the statement timeout. Any error means no answer.
        Then the write is run in full, without the rows the policies refuse (PostgreSQL stops
        at the first), and with the inserts it makes into other RLS tables caught the same way:
        if it goes through, the refusal was the policies' (one of another table's included: a
        trigger writing elsewhere); if not, something else refused it too, and that is no answer."""
        rel, filtered = self._oid(table), row is not None
        needs = ([(op, None)] if op == "DELETE" or not values
                 else [("INSERT" if op == "INSERT" else "UPDATE", c) for c in values])
        needs += [("SELECT", k) for k in self.primary_key(table)] if filtered else []
        missing = [f"{p} on {c}" if c else p for p, c in needs if not self._conn.execute(
            "select case when %s::name is null then has_table_privilege('anon', %s::oid, %s)"
            " else has_column_privilege('anon', %s::oid, %s::name, %s) end",
            (c, rel, p, rel, c, p)).fetchone()[0]]
        if missing:
            return ("grant", table, f"anon has no grant for {', '.join(missing)} of {table}")
        if not self._rls_applies("anon", rel):
            return None
        try:
            with self._app.transaction(force_rollback=True):
                targets = [] if op == "INSERT" else self._target_rows(table, row)
                if op != "INSERT" and not targets:
                    return None  # no row there to reach: nothing to say about the policies
                if op != "DELETE":
                    self._catch([rel], op)
                self._become("anon", settings)
                if op != "INSERT":
                    using = self._policies("anon", rel, op, "using", filtered)
                    reached = [r for r in targets if self._passes(using, r)]
                    if not reached:
                        return ("using", table,
                                f"row-level security lets it reach no row ({using.describe()})")
                    if op == "DELETE":
                        return None  # a row anon's policies let it delete was not deleted
                self._app.execute(self._statement(op, table, values, row),
                                  self._params(table, values, row))
                caught = self._caught()  # none if the table's own trigger dropped them all
                check = self._policies("anon", rel, op, "check", filtered)
                refused = [new for _, _, new in caught if not self._passes(check, new)]
                if refused and len(refused) == len(caught):
                    return ("check", table,
                            f"row-level security refuses the new row ({check.describe()})")
                why = ("check", table, f"row-level security refuses {len(refused)} of the "
                       f"{len(caught)} new rows ({check.describe()})") if refused else None
            return self._in_full(op, table, values, row, settings, refused) or why
        except psycopg.Error:
            return None

    def _in_full(self, op, table, values, row, settings, refused: list[str]):
        """Run the write in full but for the `refused` new rows (dropped), with the inserts it
        makes into other RLS tables caught (and dropped): an error raises. Returns ("check", the
        table, why) if one of those inserts is refused by its table's policies, for the role
        that made it."""
        rel = self._oid(table)
        others = [r for (r,) in self._conn.execute(
            "select oid from pg_class where relkind in ('r', 'p') and relrowsecurity"
            " and oid <> %s and pg_has_role('postgres', relowner, 'USAGE')", (rel,))]
        with self._app.transaction(force_rollback=True):
            self._catch(others, "INSERT")
            if refused:
                self._catch([rel], op, only=refused)
            self._become("anon", settings)
            self._app.execute(self._statement(op, table, values, row), self._params(table, values, row))
            for other, role, new in self._caught():
                if other == rel:
                    continue
                if not self._rls_applies(role, other):
                    continue
                self._app.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))
                check = self._policies(role, other, "INSERT", "check", False)
                if not self._passes(check, new):
                    name = self._name(other)[1]
                    return ("check", name, f'row-level security on table "{name}" refuses the row '
                            f"{table} writes there ({check.describe()})")
        return None

    _CATCH = "rlsentry_seeded.rlsentry_catch"
    # Triggers fire in the byte order of their names. Only a name that begins with these 60
    # bytes (the highest code point, 15 times) sorts after this one; such a trigger fires after
    # ours, and the oracle reads the row before it does. That can only make the oracle disagree
    # with PostgreSQL (no answer) or agree with a refusal PostgreSQL made itself.
    _LAST = "\U0010ffff" * 15

    def _catch(self, rels: list[int], op: str, only: list[str] | None = None) -> None:
        """A BEFORE ROW trigger on each of `rels` that fires after all of the table's own, notes
        the row as PostgreSQL would check it, with the role writing it, and drops the row
        (with `only`, just the rows among those, by their text; it lets the others through)."""
        name = self._CATCH + ("_only" if only is not None else "")
        keep = sql.SQL("if not new::text = any({}) then return new; end if;").format(
            sql.Literal(only)).as_string(self._app) if only is not None else ""
        self._app.execute(f"""create function {name}() returns trigger language plpgsql as $f$
begin
  {keep}
  perform set_config('rlsentry.caught', (coalesce(nullif(current_setting('rlsentry.caught', true),
    ''), '[]')::jsonb || jsonb_build_array(jsonb_build_array(tg_relid::bigint, current_user, new::text)))::text,
    true);
  return null;
end $f$""")
        for rel in rels:
            self._app.execute(sql.SQL("create trigger {} before {} on {} for each row execute function {}()")
                              .format(sql.Identifier(self._LAST), sql.SQL(op), sql.Identifier(*self._name(rel)),
                                      sql.SQL(name)))

    def _caught(self) -> list[tuple[int, str, str]]:
        caught = self._app.execute("select current_setting('rlsentry.caught', true)").fetchone()[0]
        return [tuple(c) for c in json.loads(caught or "[]")]

    def _become(self, role: str, settings: dict[str, str]) -> None:
        """What PostgREST does at the start of each request's transaction."""
        self._app.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))
        self._app.execute("select set_config('search_path', %s, true)", [POSTGREST_SEARCH_PATH])
        for name, value in settings.items():
            self._app.execute("select set_config(%s, %s, true)", [name, value])

    def _rls_applies(self, role: str, rel: int) -> bool:
        return self._conn.execute(
            "select c.relrowsecurity and not r.rolbypassrls and not r.rolsuper"
            " and (c.relforcerowsecurity or not pg_has_role(r.oid, c.relowner, 'USAGE'))"
            " from pg_class c, pg_roles r where c.oid = %s and r.rolname = %s",
            (rel, role)).fetchone()[0]

    def _policies(self, role: str, rel: int, op: str, kind: str, select: bool) -> "_Policies":
        """The policies PostgreSQL applies to `role`'s `op` on `rel`: for "using" their USING,
        for "check" their WITH CHECK (USING where there is none). With `select` (the statement
        reads the table's columns, as a filter does) also the SELECT policies' USING, as a
        group of its own. A policy for PUBLIC applies to every role."""
        cmd = {"INSERT": "a", "UPDATE": "w", "DELETE": "d"}[op]
        groups = [(op, [cmd, "*"], "polqual" if kind == "using" else "coalesce(polwithcheck, polqual)")]
        if select:
            groups.append(("SELECT", ["r", "*"], "polqual"))
        out = []
        for name, cmds, expr in groups:
            rows = self._conn.execute(
                f"select polname, polpermissive, pg_get_expr({expr}, polrelid) from pg_policy"
                " where polrelid = %s and polcmd = any(%s::\"char\"[])"
                " and (0 = any(polroles) or exists (select from unnest(polroles) r"
                "      where r <> 0 and pg_has_role(%s, r, 'USAGE')))"
                " order by polname", (rel, cmds, role)).fetchall()
            out.append((name, [(n, p, e) for n, p, e in rows if e is not None]))
        return _Policies(role, self._name(rel), out)

    def _passes(self, policies: "_Policies", row_text: str) -> bool:
        """Do `policies` let the row through, as PostgreSQL combines them? In each group the
        permissive ones are OR'd (none at all is a no) and each restrictive one AND'd; a null
        is a no. Evaluated as the role in effect, on the row read into the table's row type."""
        exprs = [e for _, group in policies.groups for _, _, e in group]
        results = iter(self._app.execute(sql.SQL("select {} from (select {} from (select (%s::{}).*) as {}) as {}").format(
            sql.SQL(", ").join(sql.SQL("({}) is true").format(sql.SQL(e)) for e in exprs),
            self._row_columns(policies.rel), sql.Identifier(*policies.rel),
            sql.Identifier(policies.rel[1]), sql.Identifier(policies.rel[1])), [row_text]).fetchone()
            if exprs else [])
        for name, group in policies.groups:
            passed = [(n, p, next(results)) for n, p, _ in group]
            permitted = any(ok for _, p, ok in passed if p)
            restricted = [n for n, p, ok in passed if not p and not ok]
            if not permitted or restricted:
                policies.refusing = (name, restricted or [n for n, p, _ in passed if p])
                return False
        return True

    def _row_columns(self, rel: tuple[str, str]) -> sql.Composable:
        """The row's columns, stored generated ones computed again (a BEFORE trigger sees the
        row before PostgreSQL computes them)."""
        return sql.SQL(", ").join(
            sql.SQL("({}) as {}").format(sql.SQL(gen), sql.Identifier(name)) if gen else sql.Identifier(name)
            for name, gen in self._conn.execute(
                "select a.attname, case when a.attgenerated = 's' then pg_get_expr(d.adbin, d.adrelid) end"
                " from pg_attribute a left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum"
                " where a.attrelid = %s and a.attnum > 0 and not a.attisdropped order by a.attnum",
                (self._oid(rel[1], rel[0]),)))

    def _target_rows(self, table: str, row: dict | None) -> list[str]:
        """The rows a write by primary key (or without a filter) reaches, as their owner sees them."""
        where, params = self._where(table, row)
        return [r for (r,) in self._app.execute(
            sql.SQL("select t::text from {} as t").format(sql.Identifier("public", table)) + where, params)]

    def _statement(self, op: str, table: str, values: dict | None, row: dict | None) -> sql.Composable:
        """The write as PostgREST makes it: the JSON body read into the table's row type."""
        rel = sql.Identifier("public", table)
        record = sql.SQL("json_populate_record(null::{}, %s::json)").format(rel)
        cols = sql.SQL(", ").join(map(sql.Identifier, values or {}))
        if op == "INSERT":
            return (sql.SQL("insert into {} ({}) select {} from {}").format(rel, cols, cols, record)
                    if values else sql.SQL("insert into {} default values").format(rel))
        if op == "UPDATE":
            statement = sql.SQL("update {} set ({}) = (select {} from {})").format(
                rel, cols, cols, record) if len(values) > 1 else sql.SQL(
                "update {} set {} = (select {} from {})").format(rel, cols, cols, record)
        else:
            statement = sql.SQL("delete from {}").format(rel)
        return statement + self._where(table, row)[0]

    def _params(self, table: str, values: dict | None, row: dict | None) -> list:
        return ([json.dumps(values)] if values else []) + self._where(table, row)[1]

    def _where(self, table: str, row: dict | None) -> tuple[sql.Composable, list]:
        if row is None:
            return sql.SQL(""), []
        key = self.primary_key(table)
        return (sql.SQL(" where ") + sql.SQL(" and ").join(
            sql.SQL("{} = %s::{}").format(sql.Identifier(k), sql.SQL(self._type(table, k)))
            for k in key), [str(row[k]) for k in key])

    def _oid(self, table: str, schema: str = "public") -> int:
        return self._conn.execute("select format('%%I.%%I', %s::text, %s::text)::regclass::oid",
                                  (schema, table)).fetchone()[0]

    def _name(self, rel: int) -> tuple[str, str]:
        return self._conn.execute("select n.nspname, c.relname from pg_class c join pg_namespace n"
                                  " on n.oid = c.relnamespace where c.oid = %s", (rel,)).fetchone()

    def value_sources(self, table: str) -> list[tuple[str, str, object]]:
        """Value search's candidates (design §4) as (source, column, value), in this order:
        constants that anon's INSERT policies and the CHECK constraints compare a column with,
        enum labels, values in the seeded rows, and null. White-box on purpose (design D-3)."""
        columns = {name: (typ, enum, notnull) for name, typ, enum, notnull in self._conn.execute(
            "select a.attname, format_type(a.atttypid, a.atttypmod), t.typtype = 'e', a.attnotnull"
            " from pg_attribute a join pg_type t on t.oid = a.atttypid"
            " where a.attrelid = format('public.%%I', %s::text)::regclass and a.attnum > 0"
            " and not a.attisdropped and a.attgenerated = '' and a.attidentity = ''"
            " order by a.attnum", (table,))}
        out = []
        for (expr,) in self._conn.execute(
                "select coalesce(with_check, qual) from pg_policies where schemaname = 'public'"
                " and tablename = %s and cmd in ('INSERT', 'ALL')"
                " and roles && array['anon', 'public']::name[] and permissive = 'PERMISSIVE'",
                (table,)):
            out += [("policy", c, v) for c, v in _constants(expr or "", columns)
                    if self._fits(columns[c][0], v)]
        for (expr,) in self._conn.execute(
                "select pg_get_constraintdef(oid) from pg_constraint where contype = 'c'"
                " and conrelid = format('public.%%I', %s::text)::regclass", (table,)):
            out += [("check", c, v) for c, v in _constants(expr, columns)
                    if self._fits(columns[c][0], v)]
        for name, (typ, enum, _) in columns.items():
            if enum:
                out += [("enum", name, label) for (label,) in self._conn.execute(
                    "select enumlabel from pg_enum where enumtypid = %s::regtype"
                    " order by enumsortorder", (typ,))]
        rows = self.rows(table)
        for name in columns:
            seen = []
            for value in (json.loads(json.dumps(r[name], default=str)) for r in rows):
                if value is not None and value not in seen:
                    seen.append(value)
            out += [("seeded", name, v) for v in seen]
        out += [("null", name, None) for name, (_, _, notnull) in columns.items() if not notnull]
        return out

    def _fits(self, typ: str, value: str) -> bool:
        """Can a column of type `typ` hold `value`? ('1 day' is no date, 0.5 no integer, 32768
        no smallint.) An explicit cast truncates an over-long varchar: PostgREST then refuses the
        row (22001), which the attacker counts as a rejected candidate."""
        try:
            with self._app.transaction(force_rollback=True):
                self._app.execute(sql.SQL("select %s::{}").format(sql.SQL(typ)), [value])
        except psycopg.Error:
            return False
        return True

    def holds(self, table: str, row: dict) -> bool:
        """Can the table's columns hold the row's values? Read into the table's row type as
        PostgREST does (json_populate_record: typmods too, so an over-long varchar fails),
        with no trigger or policy involved, and rolled back."""
        try:
            with self._app.transaction(force_rollback=True):
                self._app.execute(sql.SQL("select json_populate_record(null::{}, %s::json)")
                                  .format(sql.Identifier("public", table)), [json.dumps(row)])
        except psycopg.Error:
            return False
        return True

    def make_room(self, table: str, constraint: str, row: dict) -> bool:
        """Remove the rows `row` collides with on unique `constraint`, so an insert anon's
        policy accepted can land (restore() puts them back). False if nothing was removed."""
        cols = [r[0] for r in self._conn.execute(
            "select a.attname from pg_index i join pg_class c on c.oid = i.indexrelid"
            " join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey)"
            " where i.indrelid = format('public.%%I', %s::text)::regclass and c.relname = %s",
            (table, constraint))]
        if not cols or any(row.get(c) is None for c in cols):
            return False
        where = sql.SQL(" and ").join(
            sql.SQL("{} = %s::{}").format(sql.Identifier(c), sql.SQL(self._type(table, c)))
            for c in cols)
        with self._app.transaction():
            self._app.execute("set local session_replication_role = replica")  # no cascades
            cur = self._app.execute(sql.SQL("delete from {} where {}").format(
                sql.Identifier("public", table), where), [_text(row[c]) for c in cols])
            return cur.rowcount > 0

    def detach_references(self, table: str) -> bool:
        """Remove the rows of other public tables that reference `table` (and clear its own
        references to itself), so a delete anon's policy allowed is not stopped by a foreign
        key (restore() puts them back). False if there was nothing to remove."""
        refs = self._conn.execute(
            "select k.conrelid = k.confrelid, n.nspname, c.relname,"
            " array(select attname from pg_attribute where attrelid = k.conrelid"
            "       and attnum = any(k.conkey))"
            " from pg_constraint k join pg_class c on c.oid = k.conrelid"
            " join pg_namespace n on n.oid = c.relnamespace"
            " where k.contype = 'f' and k.confrelid = format('public.%%I', %s::text)::regclass",
            (table,)).fetchall()
        changed = 0
        with self._app.transaction():
            self._app.execute("set local session_replication_role = replica")  # no cascades
            for itself, schema, child, cols in refs:
                rel = sql.Identifier(schema, child)
                if itself:
                    statement = sql.SQL("update {} set {}").format(rel, sql.SQL(", ").join(
                        sql.SQL("{} = null").format(sql.Identifier(c)) for c in cols))
                elif schema == "public":
                    statement = sql.SQL("delete from {}").format(rel)
                else:
                    continue  # restore() covers public tables only
                changed += self._app.execute(statement).rowcount
        return changed > 0

    def _type(self, table: str, column: str) -> str:
        return self._conn.execute(
            "select format_type(atttypid, atttypmod) from pg_attribute"
            " where attrelid = format('public.%%I', %s::text)::regclass and attname = %s",
            (table, column)).fetchone()[0]


class _Log:
    """The server's own log (jsonlog), which only the sandbox reads: PostgreSQL's account of
    each request PostgREST makes. authenticator's sessions log each statement they run, its
    plan with the rows it really reached, and each error with the C function that raised it.

    The file is in the cluster's data directory, wherever the backend runs the server (in a
    container, on the docker backend), so the server reads it out over the superuser's
    connection: the same route on every backend, and none that the role `postgres` can take."""

    _SYNC = "rlsentry: read the log up to here "

    def __init__(self, conn: psycopg.Connection):
        self._conn = conn
        self._offset, self._partial = 0, b""

    def request(self, request_id: str | None) -> list[dict]:
        """The entries of the one transaction whose request carried `request_id` (in the
        request.headers PostgREST set, logged with the statement that set them), among those
        logged since the last call; [] if there is not exactly one."""
        if not request_id:
            return []
        entries = self._since_last_call()
        named = {(e.get("session_id"), e.get("vxid")) for e in entries
                 if e.get("user") == "authenticator" and e.get("func_name") == "exec_execute_message"
                 and "set_config('request.headers'" in (e.get("message") or "")
                 and f'"{REQUEST_HEADER.lower()}":"{request_id}"' in (e.get("detail") or "")}
        if len(named) != 1:
            return []
        return [e for e in entries if e.get("user") == "authenticator"
                and (e.get("session_id"), e.get("vxid")) in named]

    def _since_last_call(self) -> list[dict]:
        """Everything logged since the last call; [] if the server keeps no jsonlog (then
        nothing it says can be read, and no refusal is RLS's). A line of ours, logged now,
        comes after every line of a request already answered: wait for it."""
        token = secrets.token_hex(8)
        self._conn.execute(f"do $$ begin raise log '{self._SYNC}{token}'; end $$")
        entries, deadline = [], time.monotonic() + 30
        while True:
            chunk = self._read()
            if chunk is None:
                return []
            self._offset += len(chunk)
            *lines, self._partial = (self._partial + chunk).split(b"\n")
            for line in lines:
                entry = json.loads(line)
                if entry.get("user") == SUPERUSER and entry.get("message") == self._SYNC + token:
                    return entries
                entries.append(entry)
            if time.monotonic() > deadline:
                raise BuildError("the server's log stopped growing")
            time.sleep(0.01)

    def _read(self) -> bytes | None:
        """What the jsonlog holds past the offset read so far; None if there is no jsonlog."""
        return self._conn.execute(
            "select pg_read_binary_file(f, %s, greatest((pg_stat_file(f)).size - %s, 0))"
            " from pg_current_logfile('jsonlog') as f", (self._offset, self._offset)).fetchone()[0]


def _nodes(plan: dict):
    """A plan node and every node below it."""
    yield plan
    for child in plan.get("Plans", []):
        yield from _nodes(child)


class _Policies:
    """The policies one check applies, as groups [(command, [(name, permissive, expression)])]:
    the operation's, then SELECT's when the statement reads the table. After a refusal,
    `refusing` is (command, the names of the policies that refused)."""

    def __init__(self, role: str, rel: tuple[str, str], groups):
        self.role, self.rel, self.groups, self.refusing = role, rel, groups, None

    def describe(self) -> str:
        command, names = self.refusing or (self.groups[0][0], [])
        if not names:
            return f"{self.role} has no {command} policy on {self.rel[1]}"
        return (f"refused by {self.role}'s {command} policies on {self.rel[1]}: "
                + ", ".join(json.dumps(n) for n in names))


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

def _text(value) -> str:
    return json.dumps(value) if isinstance(value, (dict, list)) else str(value)


_STRING = re.compile(r"'((?:[^']|'')*)'")
_NUMBER = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])")
_NUMERIC_TYPES = ("smallint", "integer", "bigint", "real", "double precision", "numeric")


def _constants(expr: str, columns: dict) -> list[tuple[str, object]]:
    """(column, constant) pairs from a deparsed expression: each constant goes with the
    columns named in the same AND/OR term (outside its string literals: `->> 'role'` names no
    column). Numbers n also give n+1 and n-1 (for < and >), and only to numeric columns.
    Whether the column can hold the constant is the caller's check."""
    out = []
    for term in re.split(r"\b(?:AND|OR)\b", expr):
        strings = [m.replace("''", "'") for m in _STRING.findall(term)]
        code = _STRING.sub("''", term)
        numbers = []
        for n in _NUMBER.findall(code):
            v = float(n) if "." in n else int(n)
            numbers += [str(v), str(v + 1), str(v - 1)]
        for name, (typ, _, _) in columns.items():
            if not re.search(r'(?<![\w"])' + re.escape(name) + r'(?![\w"])|"'
                             + re.escape(name.replace('"', '""')) + '"', code):
                continue
            out += [(name, v) for v in strings]
            if typ.split("(")[0] in _NUMERIC_TYPES:
                out += [(name, v) for v in numbers]
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
            return psycopg.connect(host="127.0.0.1", port=port, user=SUPERUSER, dbname="postgres",
                                   autocommit=True, connect_timeout=2,
                                   options="-c search_path=pg_catalog")
        except psycopg.OperationalError:
            if time.monotonic() > deadline:
                raise BuildError(f"postgres did not accept connections: {backend.log_tail('db')}")
            time.sleep(0.1)


def _wait_http(port: int, backend: Backend) -> None:
    deadline = time.monotonic() + 60
    while True:
        if not backend.alive():
            raise BuildError(f"postgrest exited: {backend.log_tail('rest')}")
        try:
            with OPENER.open(f"http://127.0.0.1:{port}/", timeout=2) as resp:
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
