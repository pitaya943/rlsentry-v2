"""S-1..S-4, S-10: the lab run, its JSON report and exit codes."""

import json
from pathlib import Path

import jsonschema
import pytest

from conftest import FIXTURES, run_rlsentry

PACKAGE = Path(__file__).parent.parent / "rlsentry"


@pytest.fixture(scope="module")
def lab_run(tmp_path_factory):
    code, out, err = run_rlsentry("attack", "--lab", "--json",
                                  state_dir=tmp_path_factory.mktemp("state"))
    return code, out, err


def test_lab_verdicts_match_expected(lab_run):
    code, out, err = lab_run
    assert code == 1, err
    report = json.loads(out)
    got = {f"{f['schema']}.{f['table']}": {op: r["outcome"] for op, r in f["results"].items()}
           for f in report["findings"]}
    assert got == json.loads((PACKAGE / "lab" / "expected.json").read_text())


@pytest.mark.parametrize("table", ["lab_rls_off", "lab_using_true"])
def test_exposed_read_shows_count_and_a_seeded_row(lab_run, table):
    finding = next(f for f in json.loads(lab_run[1])["findings"] if f["table"] == table)
    evidence = finding["results"]["READ"]["evidence"]
    assert evidence["rows_read"] == 5
    assert evidence["row"]["email"] == "email-1"


def test_protected_read_has_no_evidence(lab_run):
    finding = next(f for f in json.loads(lab_run[1])["findings"] if f["table"] == "lab_no_policy")
    assert finding["results"]["READ"]["evidence"] is None


def test_json_report_matches_schema(lab_run):
    schema = json.loads((PACKAGE / "report.schema.json").read_text())
    jsonschema.validate(json.loads(lab_run[1]), schema)


LAB_TEXT_REPORT = """\
public.lab_delete_open
  READ: protected - anon read 0 rows
  INSERT: protected (12 rows tried) - HTTP 401 42501: new row violates row-level security policy for table "lab_delete_open"; row-level security refuses the new row (anon has no INSERT policy on lab_delete_open)
  UPDATE: protected - no row changed, confirmed as superuser (PATCH by primary key: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_delete_open); PATCH without a filter: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_delete_open))
  DELETE: EXPOSED - anon deleted 5 row(s) with DELETE without a filter (confirmed as superuser)
    evidence: {"rows_deleted": 5, "deleted": {"id": 1}}
  note: seeded 5 rows
public.lab_insert_only
  READ: protected - anon read 0 rows
  INSERT: EXPOSED - anon inserted a row (HTTP 201)
    evidence: {"row": {"id": 6, "email": "email-6", "note": "note-6"}}
  UPDATE: protected - no row changed, confirmed as superuser (PATCH by primary key: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_insert_only); PATCH without a filter: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_insert_only))
  DELETE: protected - no row changed, confirmed as superuser (DELETE by primary key: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_insert_only); DELETE without a filter: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_insert_only))
  note: seeded 5 rows
public.lab_no_policy
  READ: protected - anon read 0 rows
  INSERT: protected (12 rows tried) - HTTP 401 42501: new row violates row-level security policy for table "lab_no_policy"; row-level security refuses the new row (anon has no INSERT policy on lab_no_policy)
  UPDATE: protected - no row changed, confirmed as superuser (PATCH by primary key: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_no_policy); PATCH without a filter: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_no_policy))
  DELETE: protected - no row changed, confirmed as superuser (DELETE by primary key: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_no_policy); DELETE without a filter: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_no_policy))
  note: seeded 5 rows
public.lab_owner_only
  READ: protected - anon read 0 rows
  INSERT: protected (12 rows tried) - HTTP 401 42501: new row violates row-level security policy for table "lab_owner_only"; row-level security refuses the new row (refused by anon's INSERT policies on lab_owner_only: "owner adds")
  UPDATE: protected - no row changed, confirmed as superuser (PATCH by primary key: HTTP 204, row-level security lets it reach no row (refused by anon's UPDATE policies on lab_owner_only: "owner edits"); PATCH without a filter: HTTP 204, row-level security lets it reach no row (refused by anon's UPDATE policies on lab_owner_only: "owner edits"))
  DELETE: protected - no row changed, confirmed as superuser (DELETE by primary key: HTTP 204, row-level security lets it reach no row (refused by anon's DELETE policies on lab_owner_only: "owner deletes"); DELETE without a filter: HTTP 204, row-level security lets it reach no row (refused by anon's DELETE policies on lab_owner_only: "owner deletes"))
  note: seeded 5 rows
public.lab_rls_off
  READ: EXPOSED - anon read 5 row(s)
    evidence: {"rows_read": 5, "row": {"id": 1, "email": "email-1", "note": "note-1"}}
  INSERT: EXPOSED - anon inserted a row (HTTP 201)
    evidence: {"row": {"id": 6, "email": "email-6", "note": "note-6"}}
  UPDATE: EXPOSED - anon changed 1 row(s) with PATCH by primary key (confirmed as superuser)
    evidence: {"before": {"id": 1, "email": "email-1", "note": "note-1"}, "after": {"id": 1, "email": "email-6", "note": "note-1"}}
  DELETE: EXPOSED - anon deleted 1 row(s) with DELETE by primary key (confirmed as superuser)
    evidence: {"rows_deleted": 1, "deleted": {"id": 1}}
  note: seeded 5 rows
public.lab_update_open
  READ: protected - anon read 0 rows
  INSERT: protected (12 rows tried) - HTTP 401 42501: new row violates row-level security policy for table "lab_update_open"; row-level security refuses the new row (anon has no INSERT policy on lab_update_open)
  UPDATE: EXPOSED - anon changed 5 row(s) with PATCH without a filter (confirmed as superuser)
    evidence: {"before": {"id": 1, "email": "email-1", "note": "note-1"}, "after": {"id": 1, "email": "email-6", "note": "note-1"}}
  DELETE: protected - no row changed, confirmed as superuser (DELETE by primary key: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_update_open); DELETE without a filter: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_update_open))
  note: seeded 5 rows
public.lab_using_true
  READ: EXPOSED - anon read 5 row(s)
    evidence: {"rows_read": 5, "row": {"id": 1, "email": "email-1", "note": "note-1"}}
  INSERT: protected (12 rows tried) - HTTP 401 42501: new row violates row-level security policy for table "lab_using_true"; row-level security refuses the new row (anon has no INSERT policy on lab_using_true)
  UPDATE: protected - no row changed, confirmed as superuser (PATCH by primary key: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_using_true); PATCH without a filter: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_using_true))
  DELETE: protected - no row changed, confirmed as superuser (DELETE by primary key: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_using_true); DELETE without a filter: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_using_true))
  note: seeded 5 rows
public.lab_value_policy
  READ: protected - anon read 0 rows
  INSERT: EXPOSED - anon inserted a row (HTTP 201), row 2 of the value search, with status = "pending" from the insert policy's constants
    evidence: {"row": {"id": 8, "email": "email-6", "status": "pending"}, "source": "policy"}
  UPDATE: protected - no row changed, confirmed as superuser (PATCH by primary key: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_value_policy); PATCH without a filter: HTTP 204, row-level security lets it reach no row (anon has no UPDATE policy on lab_value_policy))
  DELETE: protected - no row changed, confirmed as superuser (DELETE by primary key: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_value_policy); DELETE without a filter: HTTP 204, row-level security lets it reach no row (anon has no DELETE policy on lab_value_policy))
  note: seeded 5 rows

9 exposed operation(s) in 8 table(s).
"""


def test_text_report_shows_verdicts_evidence_notes_and_summary(state_dir):
    code, out, _ = run_rlsentry("attack", "--lab", state_dir=state_dir)
    assert code == 1
    header, blank, *body = out.split("\n")
    assert header.startswith("rlsentry ") and " attack on lab (" in header
    assert blank == ""
    assert "\n".join(body) == LAB_TEXT_REPORT


def test_clean_migrations_exit_zero(state_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "clean"), "--json",
                                  state_dir=state_dir)
    assert code == 0, err
    [finding] = json.loads(out)["findings"]
    assert finding["results"]["READ"]["outcome"] == "protected"
