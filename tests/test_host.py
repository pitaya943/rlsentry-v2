"""Nothing a migration file says may reach the host: migration-authored SQL runs as a role
shaped like hosted Supabase's `postgres` (not a superuser), never as the cluster superuser."""

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from conftest import FIXTURES, residue, run_rlsentry

TABLE = "create table t (id bigint generated always as identity primary key, note text);\n"


@pytest.fixture
def victim_dir():
    """A directory the server's OS user could write to, so only privileges stop a write."""
    path = Path(tempfile.mkdtemp(prefix="rlsentry-victim-"))
    path.chmod(0o777)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def _migrations(tmp_path, text):
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "001_host.sql").write_text(TABLE + text)
    return folder


# Each is a superuser-only way from SQL to the host; the line given is where it must stop.
HOST_ROUTES = {
    "copy to program": ("copy (select 1) to program 'touch {v}/x';\n", 2),
    "copy to file": ("copy (select 1) to '{v}/x';\n", 2),
    "copy from program": ("copy t (note) from program 'touch {v}/x';\n", 2),
    "copy from file": ("copy t (note) from '/etc/hostname';\n", 2),
    "lo_export": ("select lo_from_bytea(4242, 'x');\nselect lo_export(4242, '{v}/x');\n", 3),
    "pg_read_file": ("select pg_read_file('/etc/hostname');\n", 2),
    "grant itself program rights": ("grant pg_execute_server_program to postgres;\n"
                                    "copy (select 1) to program 'touch {v}/x';\n", 2),
    "become superuser": ("alter role postgres superuser;\n"
                         "copy (select 1) to program 'touch {v}/x';\n", 2),
    "untrusted extension": ("create extension adminpack;\n"
                            "select pg_file_write('{v}/x', 'x', false);\n", 2),
    "file_fdw program": ("create extension file_fdw;\n"
                         "create server f foreign data wrapper file_fdw;\n"
                         "create foreign table ft (x text) server f options (program 'touch {v}/x');\n"
                         "select * from ft;\n", 2),
}


@pytest.mark.parametrize("route", HOST_ROUTES)
def test_migration_cannot_reach_the_host(state_dir, tmp_path, victim_dir, route):
    text, line = HOST_ROUTES[route]
    before = residue()
    code, out, err = run_rlsentry("attack", "--migrations",
                                  str(_migrations(tmp_path, text.format(v=victim_dir))),
                                  state_dir=state_dir)
    assert list(victim_dir.iterdir()) == []
    assert code == 2, out
    assert out == ""
    assert f"migration 001_host.sql failed at line {line}: " in err
    assert "Traceback" not in err
    assert residue() == before


def test_trigger_fired_while_seeding_cannot_reach_the_host(state_dir, tmp_path, victim_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(_migrations(tmp_path, f"""
create function public.on_insert() returns trigger language plpgsql as $$
begin
  copy (select 1) to program 'touch {victim_dir}/x';
  return new;
end $$;
create trigger t_insert before insert on t for each row execute function public.on_insert();
""")), state_dir=state_dir)
    assert list(victim_dir.iterdir()) == []
    assert code == 2, out
    assert "could not seed public.t" in err and "external program" in err


def test_function_shadowing_a_builtin_is_never_called_by_rlsentry(state_dir, tmp_path, victim_dir):
    # A migration may define public functions named like the built-ins rlsentry's own catalogue
    # queries call; on the superuser's connection they would run as the superuser.
    shadows = "".join(f"""
create function public.{name}({args}) returns {ret} language plpgsql as $$
begin
  execute 'copy (select 1) to program ''touch {victim_dir}/{name}''';
  return pg_catalog.{name}({call});
end $$;""" for name, args, ret, call in [
        ("format", "a text, b text", "text", "a, b"),
        ("array_position", "a int2vector, b int2", "int", "a::int2[], b"),
    ])
    code, out, err = run_rlsentry("attack", "--migrations", str(_migrations(tmp_path, shadows)),
                                  state_dir=state_dir)
    assert list(victim_dir.iterdir()) == []
    assert code == 1, err  # t has RLS off: the run is otherwise an ordinary one


@pytest.mark.parametrize("fixture", ["supabase_app", "starter_trigger", "ext_qualified",
                                     "ext_unqualified"])
def test_what_built_as_superuser_still_builds(state_dir, fixture):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / fixture),
                                  state_dir=state_dir)
    assert code in (0, 1), err


def test_migrations_do_what_supabase_lets_its_postgres_role_do(state_dir, tmp_path):
    # pgcrypto/uuid-ossp/pg_stat_statements come installed (as on Supabase); citext is a
    # trusted extension the project's role may create, with or without a schema. The role
    # creates roles, and bypasses RLS (seeding a table that forces RLS on its owner).
    code, out, err = run_rlsentry("attack", "--migrations", str(_migrations(tmp_path, """
create extension if not exists pgcrypto with schema extensions;
create extension if not exists "uuid-ossp" with schema extensions;
create extension if not exists pg_stat_statements with schema extensions;
create extension citext;
create extension if not exists hstore with schema extensions;
create table c (id bigint generated always as identity primary key, e citext, h extensions.hstore);
create role reporting nologin;
grant select on c to reporting;
alter table c enable row level security;
alter table c force row level security;
""")), "--json", state_dir=state_dir)
    assert code == 1, err  # t has RLS off
    assert {f["table"]: f["notes"] for f in json.loads(out)["findings"]} == {
        "t": ["seeded 5 rows"], "c": ["seeded 5 rows"]}


def test_trigger_fired_while_restoring_cannot_reach_the_host(state_dir, tmp_path, victim_dir):
    # An ALWAYS trigger fires even with session_replication_role = replica, which restore() and
    # the clearing before a retried write use.
    code, out, err = run_rlsentry("attack", "--migrations", str(_migrations(tmp_path, f"""
create function public.on_delete() returns trigger language plpgsql as $$
begin
  if current_user <> 'anon' then
    copy (select 1) to program 'touch {victim_dir}/x';
  end if;
  return old;
end $$;
create trigger t_delete before delete on t for each row execute function public.on_delete();
alter table t enable always trigger t_delete;
""")), state_dir=state_dir)
    assert list(victim_dir.iterdir()) == []
    assert code == 2, out
    assert "external program" in err


def _domain_sandbox(tmp_path, monkeypatch, victim_dir):
    """A copy whose column type is a domain whose CHECK calls a migration's function: it logs
    each call and tries COPY TO PROGRAM (which only a superuser could run; the role postgres
    gets insufficient_privilege, swallowed). Any cast to the column's type runs it."""
    from rlsentry.sandbox import Sandbox
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    return Sandbox(_migrations(tmp_path, f"""
create table public.calls (who text);
create function public.ok(v text) returns boolean language plpgsql as $$
begin
  insert into public.calls values (current_user);
  begin
    reset role;  -- back to the session role, had rlsentry run this after SET ROLE anon
    execute 'copy (select 1) to program ''touch {victim_dir}/x''';
  exception when insufficient_privilege then null;
  end;
  if v = 'loop' then loop perform 1; end loop; end if;
  return true;
end $$;
create domain public.word as text check (public.ok(value));
create table public.d (id bigint generated always as identity primary key, w public.word,
                       code varchar(3), check (w is distinct from 'x'));
create unique index d_w_key on public.d (w);
alter table public.d enable row level security;
create policy p on public.d to anon using (public.ok(w)) with check (public.ok(w));
"""))


def _uses_of_the_column_type(db, settings):
    """Every Inspector call that casts a value to the domain (and so runs its CHECK), or
    evaluates d's policy, which calls the same function."""
    return {
        "holds": lambda: db.holds("d", {"w": "a", "code": "ab"}),
        "value_sources (_fits)": lambda: db.value_sources("d"),  # the CHECK's 'x' as a word
        "would_change": lambda: db.would_change("d", "w", "b", None),
        "fake_row": lambda: db.fake_row("d"),  # a trial insert: d has a CHECK
        "rls_refusal INSERT": lambda: db.rls_refusal("INSERT", "d", {"w": "c"}, None, settings, None),
        "rls_refusal UPDATE": lambda: db.rls_refusal("UPDATE", "d", {"w": "c"}, None, settings, None),
        "rls_refusal DELETE": lambda: db.rls_refusal("DELETE", "d", None, None, settings, None),
        "make_room": lambda: db.make_room("d", "d_w_key", {"w": "a"}),
    }


def test_inspector_runs_migration_code_only_as_postgres(tmp_path, monkeypatch, victim_dir):
    with _domain_sandbox(tmp_path, monkeypatch, victim_dir) as sb:
        db = sb.inspector()
        settings = sb.anon_channel().settings("POST", "d", {"w": "c"}, "0")
        for name, use in _uses_of_the_column_type(db, settings).items():
            calls = sb._conn.execute("select count(*) from public.calls").fetchone()[0]
            use()
            assert list(victim_dir.iterdir()) == [], name
            if name != "make_room":  # make_room changes rows on purpose (restore() undoes it)
                # it ran the CHECK, and kept none of what the CHECK did: rolled back
                assert sb._conn.execute("select count(*) from public.calls").fetchone()[0] \
                    == calls, name


@pytest.mark.parametrize("use, answer", [
    (lambda db: db.holds("d", {"w": "loop"}), False),
    # the oracle: the policy calls ok(), so evaluating it never returns either
    (lambda db: db.rls_refusal("INSERT", "d", {"w": "loop"}, None, {}, None), None),
], ids=["holds", "rls_refusal"])
def test_a_migration_function_that_never_returns_cannot_hang_the_run(tmp_path, monkeypatch,
                                                                     victim_dir, use, answer):
    import threading

    import rlsentry.sandbox
    monkeypatch.setattr(rlsentry.sandbox, "STATEMENT_TIMEOUT", "1s")
    with _domain_sandbox(tmp_path, monkeypatch, victim_dir) as sb:
        db, result = sb.inspector(), []
        worker = threading.Thread(target=lambda: result.append(use(db)), daemon=True)
        worker.start()
        worker.join(15)
        assert not worker.is_alive(), "still running: no statement timeout"
        assert result == [answer]
