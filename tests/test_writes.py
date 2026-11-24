"""S-2, S-4: insert, update and delete tried for real; judged by what the database holds."""

import json

import pytest

from conftest import FIXTURES, run_rlsentry
from rlsentry.attack import LAB, attack
from rlsentry.report import Op, Outcome
from rlsentry.sandbox import Sandbox

USER = "6f1c2a8e-3b4d-4e5f-8a9b-0c1d2e3f4a5b"


def _finding(report_json, table):
    return next(f for f in json.loads(report_json)["findings"] if f["table"] == table)


@pytest.fixture(scope="module")
def lab_json(tmp_path_factory):
    code, out, err = run_rlsentry("attack", "--lab", "--json",
                                  state_dir=tmp_path_factory.mktemp("state"))
    assert code == 1, err
    return out


def test_insert_evidence_is_the_row_created(lab_json):
    # S-4: the 6th row, after the 5 seeded ones, with the id the database gave it.
    result = _finding(lab_json, "lab_insert_only")["results"]["INSERT"]
    assert result["evidence"] == {"row": {"id": 6, "email": "email-6", "note": "note-6"}}


@pytest.mark.parametrize("table", ["lab_rls_off", "lab_update_open"])
def test_update_evidence_is_before_and_after(lab_json, table):
    result = _finding(lab_json, table)["results"]["UPDATE"]
    assert result["evidence"] == {"before": {"id": 1, "email": "email-1", "note": "note-1"},
                                  "after": {"id": 1, "email": "email-6", "note": "note-1"}}


@pytest.mark.parametrize("table, deleted", [("lab_rls_off", 1), ("lab_delete_open", 5)])
def test_delete_evidence_is_the_deleted_key(lab_json, table, deleted):
    result = _finding(lab_json, table)["results"]["DELETE"]
    assert result["evidence"] == {"rows_deleted": deleted, "deleted": {"id": 1}}


@pytest.mark.parametrize("table, op", [("update_hidden", "UPDATE"), ("delete_hidden", "DELETE")])
def test_2xx_that_changed_nothing_is_protected(state_dir, table, op):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "hidden_rows"),
                                  "--json", state_dir=state_dir)
    assert code == 1, err  # the reads are exposed; the writes must not be
    result = _finding(out, table)["results"][op]
    assert "HTTP 204" in result["basis"]  # PostgREST did answer success
    assert result["outcome"] == "protected"
    assert result["evidence"] is None


def _contents(db, table):
    return sorted(json.dumps(r, sort_keys=True, default=str) for r in db.rows(table))


def test_every_table_is_back_at_its_seeded_state_after_the_attack(tmp_path, monkeypatch):
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    with Sandbox(LAB) as sb:
        db = sb.inspector()
        seeded = {t: _contents(db, t) for t in sb.tables}
        assert all(len(rows) == 5 for rows in seeded.values())
        findings = attack(sb)
        assert sum(r.outcome.value == "EXPOSED" for f in findings for r in f.results.values()) == 9
        assert {t: _contents(db, t) for t in sb.tables} == seeded


def test_each_write_starts_from_the_seeded_state(tmp_path, monkeypatch):
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    with Sandbox(FIXTURES / "restore") as sb:
        db = sb.inspector()
        seeded = _contents(db, "uniq_email")
        [finding] = attack(sb)
        # a leftover inserted row (email-6) would make this update a unique violation
        assert finding.results[Op.UPDATE].outcome is Outcome.EXPOSED, finding.results[Op.UPDATE].basis
        # the run's last write was a delete that succeeded; it too was undone
        assert finding.results[Op.DELETE].outcome is Outcome.EXPOSED
        assert _contents(db, "uniq_email") == seeded


@pytest.mark.parametrize("claims, uid", [('{"role": "anon"}', None),
                                         ('{"role": "anon", "sub": "%s"}' % USER, USER)])
def test_auth_uid_is_the_jwt_subject_and_null_for_anon(tmp_path, monkeypatch, claims, uid):
    # lab_owner_only is protected because anon has no user id (sub); a stand-in that
    # returned some user would make owner policies pass for that user's rows.
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    with Sandbox(FIXTURES / "clean") as sb:
        with sb._conn.transaction():
            sb._conn.execute("set local role anon")
            sb._conn.execute("select set_config('request.jwt.claims', %s, true)", (claims,))
            got = sb._conn.execute("select auth.uid()::text").fetchone()[0]
    assert got == uid


def test_a_table_without_a_fake_row_is_not_called_protected(state_dir):
    code, out, err = run_rlsentry("attack", "--migrations", str(FIXTURES / "unfillable"),
                                  state_dir=state_dir)
    assert code == 2, out
    assert "tagged" in err
