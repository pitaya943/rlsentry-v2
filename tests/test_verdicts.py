"""S-5 value search, and the rule behind every verdict: `protected` only when row-level
security answered. A refusal from anything else is cleared where it can be (a unique key or a
foreign key the policy got past) and otherwise stops the run with exit 2, as does a 5xx."""

import json

import pytest

from conftest import FIXTURES, residue, run_rlsentry


def _findings(out):
    return {f["table"]: f for f in json.loads(out)["findings"]}


def _run(tmp_path, state_dir, text):
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "001_t.sql").write_text(text)
    return run_rlsentry("attack", "--migrations", str(folder), "--json", state_dir=state_dir)


@pytest.fixture(scope="module")
def value_search(tmp_path_factory):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "value_search"),
                                  "--json", state_dir=tmp_path_factory.mktemp("state"))
    assert code == 1, err
    return _findings(out)


@pytest.mark.parametrize("table, source, accepted", [
    ("vs_two", "policy", {"status": "pending", "kind": "invite"}),
    ("vs_number", "policy", {"score": 11}),
    ("vs_enum", "enum", {"grade": "b"}),
    ("vs_seeded", "seeded", {"team": "team-1"}),
    ("vs_null", "null", {"note": None}),
])
def test_value_search_finds_the_row_a_policy_accepts_and_names_its_source(value_search, table,
                                                                          source, accepted):
    result = value_search[table]["results"]["INSERT"]
    assert result["outcome"] == "EXPOSED", result["basis"]
    assert result["evidence"]["source"] == source
    assert {k: result["evidence"]["row"][k] for k in accepted} == accepted
    assert "value search" in result["basis"]


def test_value_search_tries_only_the_insert_policies_constants(value_search):
    # vs_null: the fresh row, the 5 seeded notes, then null; not the select policy's 'visible'
    assert value_search["vs_null"]["results"]["INSERT"]["tries"] == 7


def test_value_search_is_bounded_and_says_how_many_rows_it_tried(value_search):
    result = value_search["vs_owner"]["results"]["INSERT"]
    assert result["outcome"] == "protected"
    assert result["tries"] == 50  # 1 fresh row + 60 enum labels and more: stops at the bound
    assert result["evidence"] is None


@pytest.mark.parametrize("op, policy, trigger", [
    ("READ", "for select to anon using (public.boom())", None),
    ("INSERT", None, "before insert"),
    ("UPDATE", None, "before update"),
    ("DELETE", None, "before delete"),
])
@pytest.mark.parametrize("errcode, says", [
    ("XX000", "the REST layer failed (HTTP 500 XX000"),  # PostgREST answers 500
    ("P0001", "got no answer from row-level security"),  # 400: refused, but not by RLS
])
def test_an_answer_that_is_not_rls_is_never_protected(state_dir, tmp_path, op, policy,
                                                       trigger, errcode, says):
    rls = f"alter table t enable row level security;\ncreate policy p on t {policy};\n" if policy else ""
    fire = (f"create trigger boom {trigger} on t for each row execute function public.boom();\n"
            if trigger else "")
    before = residue()
    code, out, err = _run(tmp_path, state_dir, f"""
create table t (id bigint generated always as identity primary key, note text);
create function public.boom() returns {'trigger' if trigger else 'boolean'} language plpgsql as $$
begin
  if current_user = 'anon' then raise exception 'boom' using errcode = '{errcode}'; end if;
  return {'new' if trigger else 'true'};
end $$;
{rls}{fire}""")
    assert code == 2, out
    assert out == ""
    assert says in err
    assert ("t: " + op if errcode == "P0001" else
            {"READ": "GET", "INSERT": "POST", "UPDATE": "PATCH", "DELETE": "DELETE"}[op] + " t:") in err
    assert residue() == before


@pytest.mark.parametrize("columns, says", [
    ("", "no column anon could set"),
    # every value an update could write is the one already there: no change could show
    (", kind public.only not null", "no value differs from the row's own"),
])
def test_update_not_attempted_stops_the_run(state_dir, tmp_path, columns, says):
    code, out, err = _run(tmp_path, state_dir, "create type public.only as enum ('one');\n"
                          f"create table t (id bigint generated always as identity primary key{columns});\n")
    assert code == 2, out
    assert out == ""
    assert "t: UPDATE not attempted: " + says in err


def test_update_avoids_a_unique_column_that_would_collide(state_dir, tmp_path):
    # PR #4 F4's reproduction: without a filter, setting every row's email to one value is 409.
    code, out, err = _run(tmp_path, state_dir, """
create table u (id bigint generated always as identity primary key, email text not null unique,
                note text);
alter table u enable row level security;
create policy p on u for update to anon using (true);
""")
    assert code == 1, err
    update = _findings(out)["u"]["results"]["UPDATE"]
    assert update["outcome"] == "EXPOSED", update["basis"]
    assert update["evidence"]["after"]["note"] == "note-6"


def test_update_sets_a_key_column_last(state_dir, tmp_path):
    # id has a default, so an update could set it; a changed key would hide which row changed.
    code, out, err = _run(tmp_path, state_dir, """
create table k (id uuid primary key default gen_random_uuid(), note text);
""")
    assert code == 1, err
    evidence = _findings(out)["k"]["results"]["UPDATE"]["evidence"]
    assert evidence["after"] == dict(evidence["before"], note="note-6")


def test_update_refused_only_by_a_unique_key_is_not_protected(state_dir, tmp_path):
    # The only settable column is unique: the unfiltered PATCH collides, with no other column
    # to try, and the policy let it through, so that is no protection.
    code, out, err = _run(tmp_path, state_dir, """
create table u (id bigint generated always as identity primary key, email text not null unique);
alter table u enable row level security;
create policy p on u for update to anon using (true);
""")
    assert code == 2, out
    assert "u: UPDATE got no answer from row-level security" in err and "23505" in err


def test_delete_a_foreign_key_stopped_is_tried_again_without_the_rows_referencing_it(
        state_dir, tmp_path):
    code, out, err = _run(tmp_path, state_dir, """
create table parent (id bigint generated always as identity primary key, note text);
alter table parent enable row level security;
create policy p on parent for delete to anon using (true);
create table child (id bigint generated always as identity primary key,
                    parent_id bigint not null references parent);
alter table child enable row level security;
""")
    assert code == 1, err
    delete = _findings(out)["parent"]["results"]["DELETE"]
    assert delete["outcome"] == "EXPOSED", delete["basis"]
    assert delete["evidence"]["rows_deleted"] == 5
    assert "referencing it were removed first" in delete["basis"]
