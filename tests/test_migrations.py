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


@pytest.mark.parametrize("fixture, file, named", [
    ("broken", "002_broken.sql", ["line 2", "storage.buckets", 'relation "storage.buckets" does not exist']),
    ("no_extension", "001_postgis.sql", ["line 2", 'extension "postgis"']),
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
