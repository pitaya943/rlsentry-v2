"""Every attacking request, made as anon through an AnonChannel, and the verdicts."""

from __future__ import annotations

import json
from collections import Counter

from rlsentry.channel import AnonChannel
from rlsentry.report import Op, OpResult, Outcome


class AttackError(Exception):
    """The REST layer failed in a way that says nothing about the policies."""


class Attacker:
    """`inspector` is the sandbox's superuser view: rows, primary key and fresh fake rows."""

    def __init__(self, channel: AnonChannel, inspector):
        self._channel = channel
        self._db = inspector

    def read(self, table: str) -> OpResult:
        resp = self._channel.request("GET", table, {"select": "*"})
        if resp.status == 200 and isinstance(resp.body, list) and resp.body:
            n = len(resp.body)
            return OpResult(Op.READ, Outcome.EXPOSED, f"anon read {n} row(s)",
                            {"rows_read": n, "row": resp.body[0]})
        if resp.status >= 500:
            raise AttackError(f"GET {table}: HTTP {resp.status}{_pg_code(resp.body)}")
        if resp.status == 200:
            return OpResult(Op.READ, Outcome.PROTECTED, "anon read 0 rows", None)
        return OpResult(Op.READ, Outcome.PROTECTED, f"HTTP {resp.status}{_pg_code(resp.body)}", None)


    def insert(self, table: str) -> OpResult:
        row = self._fresh_row(table)
        before = self._db.rows(table)
        resp = self._send("POST", table, None, row)
        if 200 <= resp.status < 300:
            created = _missing(self._db.rows(table), before)
            return OpResult(Op.INSERT, Outcome.EXPOSED, f"anon inserted a row (HTTP {resp.status})",
                            {"row": created[0] if created else row})
        return OpResult(Op.INSERT, Outcome.PROTECTED, f"HTTP {resp.status}{_pg_code(resp.body)}", None)

    def update(self, table: str) -> OpResult:
        """EXPOSED only if the superuser sees a row changed: RLS can make a 2xx change nothing."""
        fresh, key = self._fresh_row(table), self._db.primary_key(table)
        column = next((c for c in fresh if c not in key), next(iter(fresh), None))
        if column is None:
            return OpResult(Op.UPDATE, Outcome.PROTECTED, "not attempted: no column anon could set",
                            None, tries=0)
        return self._destroy(Op.UPDATE, "PATCH", table, key, {column: fresh[column]})

    def delete(self, table: str) -> OpResult:
        """EXPOSED only if the superuser sees a row gone."""
        self._fresh_row(table)  # same precondition as update: the table must be one we could seed
        return self._destroy(Op.DELETE, "DELETE", table, self._db.primary_key(table), None)

    def _destroy(self, op: Op, method: str, table: str, key: list[str], body) -> OpResult:
        """Try by the first row's primary key, then without a filter: a filter on a column needs
        a SELECT policy too, so a write-only policy is only reachable unfiltered."""
        before = self._db.rows(table)
        attempts = []
        if key and before:
            attempts.append(("by primary key", {k: f"eq.{before[0][k]}" for k in key}))
        attempts.append(("without a filter", None))
        answers = []
        for how, query in attempts:
            resp = self._send(method, table, query, body)
            answers.append(f"{method} {how}: HTTP {resp.status}{_pg_code(resp.body)}")
            after = self._db.rows(table)
            gone, new = _missing(before, after), _missing(after, before)
            if not gone:
                continue
            confirmed = f"anon {'changed' if op is Op.UPDATE else 'deleted'} {len(gone)} row(s) " \
                        f"with {method} {how} (confirmed as superuser)"
            if op is Op.UPDATE:
                same = lambda r: all(r[k] == gone[0][k] for k in key)  # no key: rows in order
                evidence = {"before": gone[0], "after": next((r for r in new if same(r)), new[0])}
            else:
                evidence = {"rows_deleted": len(gone),
                            "deleted": {k: gone[0][k] for k in key} if key else gone[0]}
            return OpResult(op, Outcome.EXPOSED, confirmed, evidence, tries=len(answers))
        return OpResult(op, Outcome.PROTECTED, "no row changed, confirmed as superuser ("
                        + "; ".join(answers) + ")", None, tries=len(answers))

    def _fresh_row(self, table: str) -> dict:
        row = self._db.fake_row(table)
        if row is None:  # never call a table protected without attacking it
            raise AttackError(f"{table}: no fake row can be made, so it cannot be attacked")
        return row

    def _send(self, method: str, table: str, query, body):
        resp = self._channel.request(method, table, query, body)
        if resp.status >= 500:
            raise AttackError(f"{method} {table}: HTTP {resp.status}{_pg_code(resp.body)}")
        return resp


def _missing(rows: list[dict], other: list[dict]) -> list[dict]:
    """Rows of `rows` not in `other`, as multisets."""
    left = Counter(_key(r) for r in other)
    out = []
    for r in rows:
        if left[_key(r)]:
            left[_key(r)] -= 1
        else:
            out.append(r)
    return out


def _key(row: dict) -> str:
    return json.dumps(row, sort_keys=True, default=str)


def _pg_code(body) -> str:
    if isinstance(body, dict) and body.get("code"):
        return f" {body['code']}: {body.get('message', '')}".rstrip(": ")
    return ""
