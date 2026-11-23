"""S-6: migrations written for a real Supabase project build, are seeded and attacked;
anything rlsentry cannot provide or seed stops the run with exit 2."""

import json

import pytest

from conftest import FIXTURES, residue, run_rlsentry


def _findings(out):
    return {f["table"]: f for f in json.loads(out)["findings"]}


@pytest.fixture(scope="module")
def app_run(tmp_path_factory):
    return run_rlsentry("attack", "--migrations", str(FIXTURES / "supabase_app"), "--json",
                        state_dir=tmp_path_factory.mktemp("state"))


def test_supabase_app_builds_and_every_table_is_seeded_in_full(app_run):
    code, out, err = app_run
    assert code == 1, err  # profiles is readable by everyone
    findings = _findings(out)
    assert set(findings) == {"profiles", "todos", "workspaces", "announcements", "staff_notes",
                             "share_links", "attachments"}
    assert {t: f["notes"] for t, f in findings.items()} == {t: ["seeded 5 rows"] for t in findings}


def test_policies_see_anon_through_auth_role_jwt_and_uid(app_run):
    verdicts = {t: f["results"]["READ"]["outcome"] for t, f in _findings(app_run[1]).items()}
    assert verdicts == {
        "profiles": "EXPOSED",       # using (true)
        "announcements": "EXPOSED",  # auth.role() = 'anon' and auth.jwt() ->> 'role' = 'anon'
        "staff_notes": "protected",  # auth.role() = 'authenticated'
        "todos": "protected",        # auth.uid() = user_id: anon has no uid
        "workspaces": "protected",   # RLS on, no policy
        "share_links": "EXPOSED",    # policy calls gen_random_bytes() unqualified
        "attachments": "protected",  # RLS on, no policy
    }


def test_seeded_row_honours_enum_check_and_auth_users_key(app_run):
    evidence = _findings(app_run[1])["profiles"]["results"]["READ"]["evidence"]
    assert evidence["rows_read"] == 5
    row = evidence["row"]
    assert row["role"] in {"member", "admin", "owner"}
    assert row["tier"] in {"free", "pro"}
    assert len(row["username"]) >= 3
    assert isinstance(row["tags"], list) and row["tags"]


def test_auth_functions_read_request_jwt_claims_like_supabase(state_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "auth_claims"), "--json",
                                  state_dir=state_dir)
    assert code == 0, err


def test_identifiers_quoted_and_partly_seedable_tables_noted(state_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "edge_cases"), "--json",
                                  state_dir=state_dir)
    assert code == 1, err  # RLS off everywhere
    findings = _findings(out)
    assert {t: f["notes"] for t, f in findings.items()} == {
        'q"uote': ["seeded 5 rows"],
        'child " table': ["seeded 5 rows"],
        "a grandchild": ["seeded 5 rows"],
        "pairs": ["seeded 2 of 5 rows; skipped: no value tried satisfies check pairs_side_check"],
        "settings": ["seeded 0 of 5 rows; skipped: no value tried satisfies check settings_id_check"],
    }
    row = findings['q"uote']["results"]["READ"]["evidence"]["row"]
    del row["id"]  # identity values used up by rows a CHECK rejected
    assert row == {"it's": "it's", "Mixed Case": "it's", 'lab"el\\s': ['lab"el\\s-1'],
                   "spot": None}
    assert findings["settings"]["results"]["READ"]["evidence"]["row"] == {"id": 1, "value": "x"}
    # The insert attack's row satisfies the CHECK too, so the open table is shown open.
    assert findings['q"uote']["results"]["INSERT"]["outcome"] == "EXPOSED"
    assert findings['q"uote']["results"]["INSERT"]["evidence"]["row"]["Mixed Case"] == "it's"



def test_writes_stopped_by_a_constraint_after_the_policy_are_tried_again(state_dir):
    # RLS is off on every edge_cases table, so every write must come out EXPOSED: a CHECK, a
    # unique key or a foreign key that refused the first try is no protection.
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "edge_cases"), "--json",
                                  state_dir=state_dir)
    assert code == 1, err
    findings = _findings(out)
    assert {t: {op: r["outcome"] for op, r in f["results"].items()}
            for t, f in findings.items()} == {t: dict.fromkeys(
                ["READ", "INSERT", "UPDATE", "DELETE"], "EXPOSED") for t in findings}
    # No fake row satisfies settings' CHECK (id = 1) and pairs' (two values, both seeded):
    # value search finds the CHECK's value, and the seeded row holding it makes room.
    for table, row in [("settings", {"id": 1}), ("pairs", {"side": "left"})]:
        insert = findings[table]["results"]["INSERT"]
        assert insert["evidence"]["source"] == "check"
        assert {k: insert["evidence"]["row"][k] for k in row} == row
        assert "collided with" in insert["basis"]
    # q"uote: fake row 6's "it's" (varchar(4)) equals every row's, so another column is set.
    assert findings['q"uote']["results"]["UPDATE"]["evidence"]["after"]["lab\"el\\s"] \
        == ['lab"el\\s-6']
    # Rows of child " table reference q"uote: the delete is tried again without them.
    assert "referencing it were removed first" in findings['q"uote']["results"]["DELETE"]["basis"]


@pytest.mark.parametrize("fixture, file, named", [
    ("broken", "002_broken.sql", ["line 2", "storage.buckets", 'relation "storage.buckets" does not exist']),
    ("no_extension", "001_postgis.sql", ["line 2", 'extension "postgis"']),
    # The line of the missing object, not of the statement's first line.
    ("broken_multiline", "001_files.sql", ["line 4", 'schema "storage" does not exist']),
    # One transaction per file, as Supabase applies them: a new enum value is not usable
    # in the file that adds it.
    ("enum_same_file", "002_use.sql", ["line 2", 'unsafe use of new value "closed"']),
])
def test_unsupported_migration_names_file_line_and_missing_object(state_dir, fixture, file, named):
    before = residue()
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / fixture),
                                  state_dir=state_dir)
    assert code == 2
    assert out == ""
    assert f"migration {file} failed" in err
    for word in named:
        assert word in err
    assert residue() == before
    assert list(state_dir.glob("*.json")) == []


@pytest.mark.parametrize("fixture, named", [
    ("unseedable_point", ["public.spots", "here (point)", "public.spot_visits",
                          "spot_id (bigint) references public.spots, which has no rows"]),
    ("unseedable_empty_enum", ["public.things", "kind (kind)"]),
    ("unseedable_check", ["public.impossible", "impossible_code_check"]),
])
def test_table_left_without_rows_stops_the_run(state_dir, fixture, named):
    before = residue()
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / fixture),
                                  state_dir=state_dir)
    assert code == 2, out
    assert out == ""  # never "READ: protected" for a table with nothing in it
    assert "could not seed" in err
    for word in named:
        assert word in err
    assert residue() == before
    assert list(state_dir.glob("*.json")) == []


def test_extensions_on_the_search_path_of_seeding_and_postgrest(state_dir):
    # The trigger calls gen_random_bytes() and uuid_generate_v4() without a schema: it runs
    # when the copy is seeded and when anon inserts through PostgREST.
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "ext_unqualified"),
                                  "--json", state_dir=state_dir)
    assert code == 1, err
    invites = _findings(out)["invites"]
    assert invites["notes"] == ["seeded 5 rows"]
    assert invites["results"]["INSERT"]["outcome"] == "EXPOSED", invites["results"]["INSERT"]


def test_extension_functions_called_with_their_schema(state_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "ext_qualified"),
                                  "--json", state_dir=state_dir)
    assert code == 0, err
    assert _findings(out)["api_keys"]["notes"] == ["seeded 5 rows"]


def test_starter_trigger_reads_the_auth_users_columns_supabase_has(state_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "starter_trigger"),
                                  "--json", state_dir=state_dir)
    assert code == 1, err  # profiles are readable by everyone
    read = _findings(out)["profiles"]["results"]["READ"]
    assert read["outcome"] == "EXPOSED"
    assert read["evidence"]["rows_read"] == 5  # one per seeded user, made by the trigger
    assert read["evidence"]["row"]["email"] is not None


def test_check_violated_in_another_table_stops_the_run_cleanly(state_dir):
    before = residue()
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "trigger_check"),
                                  state_dir=state_dir)
    assert code == 2, err
    assert "Traceback" not in err
    assert "could not seed auth.users" in err and "profiles_username_check" in err
    assert residue() == before
    assert list(state_dir.glob("*.json")) == []


@pytest.mark.parametrize("meta", ["\\! touch {victim}", "\\o {victim}"])
def test_migration_meta_commands_never_reach_the_host(state_dir, tmp_path, meta):
    victim = tmp_path / "victim"
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_meta.sql").write_text(
        "create table t (id bigint generated always as identity primary key);\n"
        + meta.format(victim=victim) + "\n"
        "select 1;\n")
    code, out, err = run_rlsentry("attack", "--migrations", str(migrations), state_dir=state_dir)
    assert not victim.exists()
    assert code == 2, out
    assert "migration 001_meta.sql failed at line 2" in err


def test_migration_split_where_postgres_splits_it(state_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "statements"), "--json",
                                  state_dir=state_dir)
    assert code == 1, err  # RLS off
    row = _findings(out)["semi;colon"]["results"]["READ"]["evidence"]["row"]
    assert (row["plain"], row["escaped"]) == ("a;b", "it's; fine")


def test_failing_statement_named_by_its_line_after_semicolons_that_split_nothing(state_dir,
                                                                                  tmp_path):
    text = (FIXTURES / "statements" / "001_statements.sql").read_text()
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_statements.sql").write_text(text + "create extension postgis;\n")
    code, out, err = run_rlsentry("attack", "--migrations", str(migrations), state_dir=state_dir)
    assert code == 2, out
    assert f"failed at line {text.count(chr(10)) + 1}: " in err and 'extension "postgis"' in err
