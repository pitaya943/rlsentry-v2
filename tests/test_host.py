"""Nothing a migration file says may reach the host: migration-authored SQL runs as a role
shaped like hosted Supabase's `postgres` (not a superuser), never as the cluster superuser."""

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


def test_migrations_create_extensions_supabase_allows(state_dir, tmp_path):
    # pgcrypto/uuid-ossp/pg_stat_statements come installed (as on Supabase); citext is a
    # trusted extension a project's own role may create, with or without a schema.
    code, out, err = run_rlsentry("attack", "--migrations", str(_migrations(tmp_path, """
create extension if not exists pgcrypto with schema extensions;
create extension if not exists "uuid-ossp" with schema extensions;
create extension if not exists pg_stat_statements with schema extensions;
create extension citext;
create extension if not exists hstore with schema extensions;
create table c (id bigint generated always as identity primary key, e citext, h extensions.hstore);
""")), state_dir=state_dir)
    assert code == 1, err
