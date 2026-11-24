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


@pytest.fixture(scope="module")
def value_types(tmp_path_factory):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "value_types"),
                                  "--json", state_dir=tmp_path_factory.mktemp("state"))
    assert code == 0, err  # anon can satisfy none of these insert policies
    return _findings(out)


@pytest.mark.parametrize("table, tried", [
    ("posts", None),     # interval '1 day' is no timestamptz (seeded timestamps vary)
    ("bookings", 16),    # interval '30 days' is no date: fresh row + 3 columns x 5 seeded values
    ("t_int", 11),       # 0.5, 1.5, -0.5 are no integers: fresh row + 5 owners + 5 values of n
    ("t_small", 13),     # 32767 and 32766 are smallints, 32768 is not
    ("t_role", 11),      # 'role' and 'admin' are about the JWT, not the role column
    ("t_len", 7),        # 'abcd' is sent, refused as too long, and counts as a row tried
    ("t_auth", 11),      # the authenticated policy's 'staff' is no candidate for anon
])
def test_value_search_sends_only_values_the_column_can_hold(value_types, table, tried):
    result = value_types[table]["results"]["INSERT"]
    assert result["outcome"] == "protected", result["basis"]
    assert "42501" in result["basis"]
    if tried is not None:
        assert result["tries"] == tried


def test_insert_that_wrote_no_row_is_not_exposed(state_dir, tmp_path):
    # PR #6 verdict, Finding 1: the trigger drops anon's row and PostgREST still answers 201.
    code, out, err = _run(tmp_path, state_dir, """
create table inbox (id bigint generated always as identity primary key, note text);
create function public.drop_anon() returns trigger language plpgsql as $$
begin
  if current_user = 'anon' then return null; end if;
  return new;
end $$;
create trigger drop_anon before insert on inbox for each row execute function public.drop_anon();
alter table inbox enable row level security;
create policy p on inbox for insert to anon with check (true);
""")
    assert code == 2, out
    assert out == ""
    assert "inbox: INSERT got no answer from row-level security" in err
    assert "no row was written" in err


def test_seeding_that_kept_no_row_says_why(state_dir, tmp_path):
    # PR #6 verdict, Finding 2: every insert "succeeds" and the table stays empty.
    code, out, err = _run(tmp_path, state_dir, """
create table inbox (id bigint generated always as identity primary key, note text);
create function public.drop_all() returns trigger language plpgsql as $$
begin
  return null;
end $$;
create trigger drop_all before insert on inbox for each row execute function public.drop_all();
""")
    assert code == 2, out
    assert "could not seed public.inbox: " in err
    assert "no row was kept" in err


def test_delete_clears_a_tables_references_to_itself_before_trying_again(state_dir, tmp_path):
    # The rows reference each other (the migration's own two, and the fake rows point at
    # them); deleting row 1 by its key hits the self-reference, which is cleared, then retried.
    code, out, err = _run(tmp_path, state_dir, """
create table comments (id bigint generated always as identity primary key,
                       parent_id bigint references comments, note text);
insert into comments (parent_id, note) values (null, 'root');
insert into comments (parent_id, note) values (1, 'reply');
alter table comments enable row level security;
create policy r on comments for select to anon using (true);
create policy d on comments for delete to anon using (true);
""")
    assert code == 1, err
    delete = _findings(out)["comments"]["results"]["DELETE"]
    assert delete["outcome"] == "EXPOSED", delete["basis"]
    assert "by primary key" in delete["basis"]
    assert "referencing it were removed first" in delete["basis"]
    assert delete["evidence"] == {"rows_deleted": 1, "deleted": {"id": 1}}


@pytest.mark.parametrize("columns, refusal", [
    # PR #6 verdict D4: a trigger raising a class-22 error for anon
    (", note text", "create function public.no_anon() returns trigger language plpgsql as $$\n"
     "begin\n  if current_user = 'anon' then raise exception 'no' using errcode = '22023'; end if;\n"
     "  return new;\nend $$;\n"
     "create trigger no_anon before insert on t for each row execute function public.no_anon();\n"
     "create policy p on t for insert to anon with check (true);\n"),
    # ...and the policy itself dividing by zero (22012)
    (", note text", "create policy p on t for insert to anon with check "
     "(10 / (length(coalesce(note, '')) - length(coalesce(note, ''))) > 0);\n"),
    # the fresh fake row is the only row sent (no column gives a candidate), answered 22023
    ("", "create function public.no_anon() returns trigger language plpgsql as $$\n"
     "begin\n  if current_user = 'anon' then raise exception 'no' using errcode = '22023'; end if;\n"
     "  return new;\nend $$;\n"
     "create trigger no_anon before insert on t for each row execute function public.no_anon();\n"
     "create policy p on t for insert to anon with check (true);\n"),
], ids=["trigger-22023", "policy-22012", "fresh-row-only-22023"])
def test_a_class_22_refusal_from_a_trigger_or_policy_is_never_protected(state_dir, tmp_path,
                                                                        columns, refusal):
    # Only a value the column cannot hold (t_len's 22001) is a rejected candidate; the same
    # class from the table's own code is no answer from row-level security.
    code, out, err = _run(tmp_path, state_dir,
                          f"create table t (id bigint generated always as identity primary key{columns});\n"
                          "alter table t enable row level security;\n" + refusal)
    assert code == 2, out
    assert out == ""
    assert "t: INSERT got no answer from row-level security" in err


def test_protected_needs_at_least_one_answer_from_rls():
    # Every row sent is one the table cannot hold (each answered 22001). No row the database
    # built from them can make the table read protected: no table here can be built that way
    # (rlsentry's own fake rows always fit), so the attacker is driven with stand-ins.
    from rlsentry.attacker import Attacker, AttackError
    from rlsentry.channel import Response

    class Channel:
        def request(self, method, table, query=None, body=None):
            return Response(400, {"code": "22001", "message": "value too long"})

    class Db:
        fake_row = staticmethod(lambda table: {"code": "abcd"})
        value_sources = staticmethod(lambda table: [("check", "code", "wxyz")])
        rows = staticmethod(lambda table: [])
        holds = staticmethod(lambda table, row: False)

    with pytest.raises(AttackError, match="t: INSERT got no answer from row-level security"):
        Attacker(Channel(), Db()).insert("t")


@pytest.mark.parametrize("errcode", ["22023", "P0001"])
def test_one_row_refused_by_the_tables_code_among_rls_refusals_is_never_protected(
        state_dir, tmp_path, errcode):
    # RLS refuses every row but the null-note one, which the policy accepts and a trigger
    # refuses. The other rows' 42501s do not make the table protected.
    code, out, err = _run(tmp_path, state_dir, f"""
create table t (id bigint generated always as identity primary key, note text);
create function public.no_null() returns trigger language plpgsql as $$
begin
  if current_user = 'anon' and new.note is null then
    raise exception 'no' using errcode = '{errcode}';
  end if;
  return new;
end $$;
create trigger no_null before insert on t for each row execute function public.no_null();
alter table t enable row level security;
create policy p on t for insert to anon with check (note is null);
""")
    assert code == 2, out
    assert out == ""
    assert f"t: INSERT got no answer from row-level security, so it is neither exposed nor " \
           f"protected (HTTP 400 {errcode}: no)" in err


_GATE = """
create table inbox (id bigint generated always as identity primary key, note text);
create function public.gate() returns trigger language plpgsql as $$
begin
  if current_user = 'anon' {when} then
    {act}
  end if;
  return {ret};
end $$;
create trigger gate before {event} on inbox for each row execute function public.gate();
alter table inbox enable row level security;
{policies}
"""
_OPEN = ("create policy i on inbox for insert to anon with check (true);\n"
         "create policy u on inbox for update to anon using (true);\n"
         "create policy d on inbox for delete to anon using (true);\n")


@pytest.mark.parametrize("op, gate", [
    # PR #6 verdict D5, t42: the policy lets anon insert; a trigger refuses with RLS's code
    ("INSERT", dict(event="insert", when="and new.note is distinct from 'magic'",
                    act="raise exception 'note must be magic' using errcode = '42501';",
                    ret="new", policies=_OPEN)),
    # t42m: the common idiom, refusing anon outright
    ("INSERT", dict(event="insert", when="", ret="new", policies=_OPEN,
                    act="raise exception 'anon may not write' using errcode = '42501';")),
    # ...forging row-level security's exact message
    ("INSERT", dict(event="insert", when="", ret="new", policies=_OPEN,
                    act="raise exception 'new row violates row-level security policy for table "
                        "\"inbox\"' using errcode = '42501';")),
    # upd42: open update and delete policies, a trigger refusing both with 42501
    ("UPDATE", dict(event="update or delete", when="", ret="new", policies=_OPEN,
                    act="raise exception 'anon may not change rows' using errcode = '42501';")),
    ("DELETE", dict(event="delete", when="", ret="old", policies=_OPEN,
                    act="raise exception 'anon may not delete rows' using errcode = '42501';")),
    # a trigger that silently skips anon's update: 204 and nothing changed, but not RLS
    ("UPDATE", dict(event="update", when="", ret="new", policies=_OPEN, act="return null;")),
], ids=["t42", "t42m", "forged-message", "upd42", "del42", "update-skipped"])
def test_a_refusal_from_the_tables_own_code_is_never_read_as_rls(state_dir, tmp_path, op, gate):
    code, out, err = _run(tmp_path, state_dir, _GATE.format(**gate))
    assert code == 2, out
    assert out == ""
    assert f"inbox: {op} got no answer from row-level security" in err


# T-06: whether a refusal is row-level security's is decided from anon's policies, never from
# the error. The cases are PR #6's last verdict (D7, D8): https://github.com/pitaya943/rlsentry-v2/pull/6#issuecomment-7116794096

_OK_NOTE = """
create function public.ok_note(n text) returns boolean language plpgsql as $$
begin
  if current_user = 'anon' and n is distinct from 'magic' then
    raise exception 'note must be magic' using errcode = '42501';
  end if;
  return true;
end $$;
"""
_RLS = "alter table inbox enable row level security;\n"
_INSERT_OPEN = "create policy i on inbox for insert to anon with check (true);\n"
# Tautological, but it names 'magic', so value search sends it: the "proof" runs show anon can write
_PROOF = "alter table inbox add constraint magic check (note = 'magic' or note is null or note is not null);\n"
_T42 = dict(event="insert", when="and new.note is distinct from 'magic'",
            act="raise exception 'note must be magic' using errcode = '42501';", ret="new")
_C42 = _OK_NOTE + ("create table inbox (id bigint generated always as identity primary key,"
                   " note text check (public.ok_note(note)));\n") + _RLS
_D42 = _OK_NOTE + ("create domain public.note_t as text check (public.ok_note(value));\n"
                   "create table inbox (id bigint generated always as identity primary key,"
                   " note public.note_t);\n") + _RLS
_A42 = _GATE.format(**_T42, policies=_OPEN) + "alter table inbox enable always trigger gate;\n"
_R42 = _GATE.format(**_T42, policies=_OPEN.replace(
    "with check (true)", "with check (current_setting('session_replication_role') = 'origin')"))
_UC42 = _C42 + ("create policy s on inbox for select to anon using (true);\n"
                "create policy u on inbox for update to anon using (true);\n")

_CASES = {"c42": _C42 + _INSERT_OPEN, "d42": _D42 + _INSERT_OPEN, "a42": _A42, "r42": _R42,
          # no row-level security at all: the grant lets anon insert, so the 42501 is the CHECK's
          "c42-rls-off": _C42.replace(_RLS, ""),
          # the policy reads a stored generated column, which PostgreSQL computes after the
          # BEFORE triggers and before the policies
          "c42-generated": _C42.replace(" note text", " ok boolean generated always as (true) stored,"
                                        " note text") + "create policy i on inbox for insert to anon"
                                                        " with check (ok);\n"}


@pytest.mark.parametrize("op, migration", [("INSERT", text) for text in _CASES.values()]
                         + [("UPDATE", _UC42)], ids=list(_CASES) + ["uc42"])
def test_a_refusal_from_code_that_runs_after_the_policies_is_never_protected(
        state_dir, tmp_path, op, migration):
    # The policy lets anon write; a CHECK, a domain CHECK, an ALWAYS trigger, or a trigger
    # beside a policy that reads session_replication_role refuses with RLS's own code.
    code, out, err = _run(tmp_path, state_dir, migration)
    assert code == 2, out
    assert out == ""
    assert f"inbox: {op} got no answer from row-level security" in err


@pytest.mark.parametrize("migration", [_C42 + _INSERT_OPEN + _PROOF, _A42 + _PROOF, _R42 + _PROOF],
                         ids=["c42proof", "a42proof", "r42proof"])
def test_the_same_tables_are_exposed_once_value_search_sends_the_accepted_row(
        state_dir, tmp_path, migration):
    code, out, err = _run(tmp_path, state_dir, migration)
    assert code == 1, err
    insert = _findings(out)["inbox"]["results"]["INSERT"]
    assert insert["outcome"] == "EXPOSED", insert["basis"]
    assert insert["evidence"]["row"]["note"] == "magic"


_FP1 = """
create table posts (id bigint generated always as identity primary key,
                    status text not null default 'draft', note text);
create function public.publish() returns trigger language plpgsql as $$
begin
  new.status := 'published';
  return new;
end $$;
create trigger publish before insert on posts for each row execute function public.publish();
alter table posts enable row level security;
create policy "drafts only" on posts for insert to anon with check (status = 'draft');
"""
_FP2 = """
create table audit (id bigint generated always as identity primary key, what text);
alter table audit enable row level security;
create table posts (id bigint generated always as identity primary key, note text);
create function public.log_post() returns trigger language plpgsql as $$
begin
  insert into public.audit (what) values (new.note);
  return new;
end $$;
create trigger log_post after insert on posts for each row execute function public.log_post();
alter table posts enable row level security;
create policy "anyone can post" on posts for insert to anon with check (true);
"""


@pytest.mark.parametrize("migration, names", [
    (_FP1, '"drafts only"'),  # a trigger shapes the row the policy then refuses
    (_FP2, 'table "audit"'),  # a trigger writes to another table, whose RLS refuses it
], ids=["fp1", "fp2"])
def test_a_refusal_by_rls_is_protected_whatever_the_tables_triggers_do(
        state_dir, tmp_path, migration, names):
    code, out, err = _run(tmp_path, state_dir, migration)
    assert code == 0, err
    insert = _findings(out)["posts"]["results"]["INSERT"]
    assert insert["outcome"] == "protected"
    assert names in insert["basis"]


@pytest.mark.parametrize("policy", [
    "to anon with check (auth.role() = 'anon')",  # the JWT claims PostgREST sets
    "to anon with check ((auth.jwt() ->> 'exp')::bigint > extract(epoch from now()))",
    "to anon with check (auth.jwt() ->> 'iss' = 'rlsentry')",
    "to anon with check (current_user = 'anon')",
    "to anon with check (current_setting('request.method', true) = 'POST')",
    "to anon with check (current_setting('request.path', true) = '/inbox')",
    "to anon with check (current_setting('request.headers', true)::json ->> 'authorization'"
    " = 'Bearer ' || (current_setting('request.headers', true)::json ->> 'apikey'))",
    "to anon with check (current_setting('request.cookies', true) = '{}')",
    "to anon with check (current_setting('search_path') = '\"public\", \"public\", \"extensions\"')",
    "with check (true)",  # a policy for public is anon's too
], ids=["claims", "exp", "iss", "role", "method", "path", "headers", "cookies", "search_path",
        "public"])
def test_the_policies_are_evaluated_as_postgrest_runs_them(state_dir, tmp_path, policy):
    # c42 with a policy that is true only in the request PostgREST makes: had rlsentry read it
    # false, the CHECK's 42501 would be taken for row-level security's.
    code, out, err = _run(tmp_path, state_dir, _C42 + f"create policy i on inbox for insert {policy};\n")
    assert code == 2, out
    assert "inbox: INSERT got no answer from row-level security" in err


@pytest.mark.parametrize("restrictive", ["to anon", ""], ids=["anon", "public"])
def test_a_restrictive_policy_refusing_the_row_is_protected(state_dir, tmp_path, restrictive):
    # Permissive policies are OR'd, restrictive ones AND'd with them, whichever role they name.
    code, out, err = _run(tmp_path, state_dir, """
create table inbox (id bigint generated always as identity primary key, note text);
alter table inbox enable row level security;
create policy i on inbox for insert to anon with check (true);
""" + f"create policy r on inbox as restrictive for insert {restrictive} with check (note = 'never');\n")
    assert code == 0, err
    insert = _findings(out)["inbox"]["results"]["INSERT"]
    assert insert["outcome"] == "protected"
    assert '"r"' in insert["basis"]


def test_the_oracle_gets_exactly_the_settings_postgrest_makes(tmp_path, monkeypatch):
    # A policy records what PostgREST set for each request; the channel's settings for the same
    # request, which the oracle evaluates policies under, must be the same.
    from rlsentry.sandbox import Sandbox
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "001_t.sql").write_text("""
create schema seen;
create table seen.settings (s jsonb);
create function public.record() returns boolean language plpgsql security definer as $$
begin
  insert into seen.settings select jsonb_build_object(
    'request.jwt.claims', current_setting('request.jwt.claims', true),
    'request.method', current_setting('request.method', true),
    'request.path', current_setting('request.path', true),
    'request.headers', current_setting('request.headers', true)::jsonb,
    'request.cookies', current_setting('request.cookies', true),
    'search_path', current_setting('search_path'));
  return true;
end $$;
create table t (id bigint generated always as identity primary key, note text);
alter table t enable row level security;
create policy i on t for insert to anon with check (public.record());
create policy u on t for update to anon using (public.record());
create policy d on t for delete to anon using (public.record());
""")
    from rlsentry.sandbox import POSTGREST_SEARCH_PATH
    with Sandbox(folder) as sb:
        channel = sb.anon_channel()
        for method, body in [("POST", {"note": "x"}), ("PATCH", {"note": "y"}), ("DELETE", None)]:
            sb._conn.execute("truncate seen.settings")
            channel.request(method, "t", None, body)
            seen = sb._conn.execute("select s from seen.settings limit 1").fetchone()[0]
            want = dict(channel.settings(method, "t", body), search_path=POSTGREST_SEARCH_PATH)
            want["request.headers"] = json.loads(want["request.headers"])
            assert seen == want, method


_SOME = """
create function public.no_two(id bigint) returns boolean language plpgsql as $$
begin
  if current_user = 'anon' and id = 2 then
    raise exception 'not row 2' using errcode = '42501';
  end if;
  return true;
end $$;
create table m (id bigint generated always as identity primary key, note text {check});
alter table m enable row level security;
create policy u on m for update to anon using (true) with check (id <= 3);
"""


def test_an_update_whose_policy_refuses_some_of_the_new_rows_is_protected(state_dir, tmp_path):
    # Without a filter the PATCH reaches rows 1-5; the policy refuses rows 4 and 5, and
    # PostgreSQL refuses the whole statement at the first of them.
    code, out, err = _run(tmp_path, state_dir, _SOME.format(check=""))
    assert code == 0, err
    update = _findings(out)["m"]["results"]["UPDATE"]
    assert update["outcome"] == "protected"
    assert "refuses 2 of the 5 new rows" in update["basis"]


def test_an_update_refused_by_other_code_on_a_row_the_policy_accepts_is_not_protected(
        state_dir, tmp_path):
    # As above, but row 2, which the policy accepts, is refused by a CHECK with RLS's code: had
    # rows 4 and 5 not been there, the statement would still have been refused.
    code, out, err = _run(tmp_path, state_dir,
                          _SOME.format(check=", check (public.no_two(id))"))
    assert code == 2, out
    assert "m: UPDATE got no answer from row-level security" in err


_DEFINER = """
create table audit (id bigint generated always as identity primary key, what text);
alter table audit enable row level security;  -- no policy: only roles that bypass it write here
create function public.only_magic() returns trigger language plpgsql as $$
begin
  if current_setting('request.method', true) = 'POST' and new.what is distinct from 'magic' then
    raise exception 'note must be magic' using errcode = '42501';
  end if;
  return new;
end $$;
create trigger only_magic after insert on audit for each row execute function public.only_magic();
create table posts (id bigint generated always as identity primary key, note text);
create function public.log_post() returns trigger language plpgsql security definer as $$
begin
  insert into public.audit (what) values (new.note);
  return new;
end $$;
create trigger log_post after insert on posts for each row execute function public.log_post();
alter table posts enable row level security;
create policy "anyone can post" on posts for insert to anon with check (true);
"""


def test_a_write_elsewhere_by_a_role_that_bypasses_rls_is_no_answer_from_rls(state_dir, tmp_path):
    # fp2, but the trigger is SECURITY DEFINER: its insert into audit runs as postgres, which
    # row-level security does not apply to. audit's own trigger refuses with RLS's code.
    code, out, err = _run(tmp_path, state_dir, _DEFINER)
    assert code == 2, out
    assert "posts: INSERT got no answer from row-level security" in err
    (tmp_path / "proof").mkdir()
    code, out, err = _run(tmp_path / "proof", state_dir, _DEFINER + _PROOF.replace("inbox", "posts"))
    assert code == 1, err
    assert _findings(out)["posts"]["results"]["INSERT"]["evidence"]["row"]["note"] == "magic"



def test_a_write_elsewhere_is_checked_against_the_policies_of_the_role_that_made_it(
        state_dir, tmp_path):
    # As above, but the trigger runs as `writer`, a role row-level security applies to, whose
    # policy on audit lets it in: so audit's own trigger is what refused, not RLS.
    code, out, err = _run(tmp_path, state_dir, """
create role writer nologin;
grant writer to postgres;
create schema app;
grant usage, create on schema app to writer;
grant usage on schema app to anon;  -- so only the role decides what its policy says
create table app.audit (id bigint generated always as identity primary key, what text);
grant insert on app.audit to writer;
alter table app.audit enable row level security;
create policy "writer logs" on app.audit for insert to writer with check (current_user = 'writer');
create function app.only_magic() returns trigger language plpgsql as $$
begin
  if current_setting('request.method', true) = 'POST' and new.what is distinct from 'magic' then
    raise exception 'note must be magic' using errcode = '42501';
  end if;
  return new;
end $$;
create trigger only_magic after insert on app.audit for each row execute function app.only_magic();
create table posts (id bigint generated always as identity primary key, note text);
create function app.log_post() returns trigger language plpgsql security definer as $$
begin
  insert into app.audit (what) values (new.note);
  return new;
end $$;
alter function app.log_post() owner to writer;
create trigger log_post after insert on posts for each row execute function app.log_post();
alter table posts enable row level security;
create policy "anyone can post" on posts for insert to anon with check (true);
""")
    assert code == 2, out
    assert "posts: INSERT got no answer from row-level security" in err


def test_a_write_refused_for_want_of_a_grant_is_protected(state_dir, tmp_path):
    # No row-level security, but anon may only read: PostgreSQL refuses each write before any
    # policy or code of the table's runs.
    code, out, err = _run(tmp_path, state_dir, """
create table t (id bigint generated always as identity primary key, note text);
revoke insert, update, delete on t from anon;
""")
    assert code == 1, err  # the read is exposed
    results = _findings(out)["t"]["results"]
    for op in ("INSERT", "UPDATE", "DELETE"):
        assert results[op]["outcome"] == "protected", results[op]["basis"]
        assert "anon has no grant for" in results[op]["basis"]
