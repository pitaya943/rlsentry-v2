"""S-1, S-3, S-10: the lab run, its JSON report and exit codes."""

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


def test_text_report_names_the_verdict(state_dir):
    code, out, _ = run_rlsentry("attack", "--lab", state_dir=state_dir)
    assert code == 1
    assert "public.lab_rls_off\n  READ: EXPOSED - anon read 5 row(s)" in out


def test_clean_migrations_exit_zero(state_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "clean"), "--json",
                                  state_dir=state_dir)
    assert code == 0, err
    [finding] = json.loads(out)["findings"]
    assert finding["results"]["READ"]["outcome"] == "protected"
