"""Every attacking request, made as anon through an AnonChannel, and the verdicts.

`protected` is a verdict only when row-level security (or a missing grant) answered. A write's
refusal (42501, or a 2xx that changed nothing) is RLS's only if anon's policies themselves
refuse the rows it reached, which the sandbox evaluates (`Inspector.rls_refusal`); the error
alone never says so, as the table's own code can raise any error. Any other refusal (a CHECK,
a unique key, a foreign key) is no answer about the policies: the attacker clears the way and
tries again where it can, and otherwise stops the run (exit 2).
"""

from __future__ import annotations

import json
from collections import Counter

from rlsentry.channel import AnonChannel
from rlsentry.report import Op, OpResult, Outcome

MAX_INSERT_ROWS = 50  # value search bound (brief: 50 per table)

_SOURCES = {"policy": "the insert policy's constants", "check": "the CHECK constraints",
            "enum": "the enum labels", "seeded": "the seeded rows", "null": "null"}


class AttackError(Exception):
    """The attack got no answer about the policies: the run stops (exit 2)."""


class Attacker:
    """`inspector` is the sandbox's view as superuser: rows, keys, fresh fake values, the
    catalogue's candidate values, and clearing the way for a write the policies allowed."""

    def __init__(self, channel: AnonChannel, inspector):
        self._channel = channel
        self._db = inspector

    def read(self, table: str) -> OpResult:
        resp = self._send("GET", table, {"select": "*"}, None)
        if resp.status == 200 and isinstance(resp.body, list):
            if not resp.body:
                return OpResult(Op.READ, Outcome.PROTECTED, "anon read 0 rows", None)
            n = len(resp.body)
            return OpResult(Op.READ, Outcome.EXPOSED, f"anon read {n} row(s)",
                            {"rows_read": n, "row": resp.body[0]})
        if _refused(resp):
            return OpResult(Op.READ, Outcome.PROTECTED, _answer(resp), None)
        raise _unclean(table, Op.READ, [_answer(resp)])

    def insert(self, table: str) -> OpResult:
        """The fresh fake row first; if row-level security refused it, value search (design §4):
        rows changed by one candidate value at a time, at most MAX_INSERT_ROWS rows in all."""
        base = self._fresh_row(table)
        tried, unclean, last = 0, [], ""
        for source, change in [(None, {})] + self._candidates(table, base):
            if tried == MAX_INSERT_ROWS:
                break
            row = dict(base, **change)
            tried += 1
            resp, made_room, before = self._post(table, row)
            created = _missing(self._db.rows(table), before)
            if 200 <= resp.status < 300 and not created:  # e.g. a trigger returned null
                unclean.append(f"{_answer(resp)}, but no row was written (checked as superuser)")
                continue
            if 200 <= resp.status < 300:
                basis = f"anon inserted a row (HTTP {resp.status})"
                evidence = {"row": created[0]}
                if source:
                    basis += (f", row {tried} of the value search, with "
                              + ", ".join(f"{c} = {json.dumps(v)}" for c, v in change.items())
                              + f" from {_SOURCES[source]}")
                    evidence["source"] = source
                if made_room:
                    basis += f"; first the seeded row it collided with on {made_room} was removed"
                return OpResult(Op.INSERT, Outcome.EXPOSED, basis, evidence, tries=tried)
            if str(_code(resp)).startswith("22") and not self._db.holds(table, row):
                continue  # a value the column cannot hold (too long, say): no row, no answer
            reason = self._rls_answered(table, Op.INSERT, "POST", resp, row, None)
            if reason:
                last = f"{_answer(resp)}; {reason}"
            else:
                unclean.append(_answer(resp))
        if unclean or not last:  # protected rests on at least one answer from RLS itself
            raise _unclean(table, Op.INSERT, unclean or ["no row sent was one the table can hold"])
        return OpResult(Op.INSERT, Outcome.PROTECTED, last, None, tries=tried)

    def update(self, table: str) -> OpResult:
        """EXPOSED only if the superuser sees a row changed: RLS can make a 2xx change nothing.
        Each column is set to a value the target row does not hold, so a 2xx that changed
        nothing is RLS's answer; one column at a time, key columns last (a changed key would
        hide which row changed), the next one after a refusal such as a unique key's 409."""
        values, key = self._db.update_values(table), self._db.primary_key(table)
        bodies = [{c: values[c]} for c in sorted(values, key=lambda c: c in key)]
        if not bodies:
            raise AttackError(f"{table}: UPDATE not attempted: no column anon could set")
        return self._destroy(Op.UPDATE, "PATCH", table, key, bodies)

    def delete(self, table: str) -> OpResult:
        """EXPOSED only if the superuser sees a row gone."""
        self._fresh_row(table)  # same precondition as insert: the table must be one we could seed
        return self._destroy(Op.DELETE, "DELETE", table, self._db.primary_key(table), [None])

    def _destroy(self, op: Op, method: str, table: str, key: list[str], bodies) -> OpResult:
        """Try by the first row's primary key, then without a filter: a filter on a column needs
        a SELECT policy too, so a write-only policy is only reachable unfiltered. Each route
        ends at the first clean answer; other answers try the next body."""
        before = self._db.rows(table)
        routes = []
        if key and before:
            routes.append(("by primary key", {k: f"eq.{before[0][k]}" for k in key}, before[0]))
        routes.append(("without a filter", None, None))
        answers, unclean, detached = [], [], False
        for how, query, target in routes:
            for body in bodies:
                if body and not self._db.would_change(table, *next(iter(body.items())), target):
                    continue
                resp = self._send(method, table, query, body)
                if (op is Op.DELETE and _code(resp) == "23503" and not detached
                        and self._db.detach_references(table)):
                    detached = True  # the policy let the delete through; a foreign key stopped it
                    before = self._db.rows(table)  # references cleared: compare with that
                    resp = self._send(method, table, query, body)
                answers.append(f"{method} {how}: {_answer(resp)}")
                after = self._db.rows(table)
                gone, new = _missing(before, after), _missing(after, before)
                if gone:
                    return self._changed(op, method, how, key, gone, new, detached, len(answers))
                reason = self._rls_answered(table, op, method, resp, body, target)
                if reason:
                    answers[-1] += f", {reason}"
                    break
                unclean.append(answers[-1])
        if unclean:
            raise _unclean(table, op, unclean)
        if not answers:
            raise AttackError(f"{table}: {op.value} not attempted: no value differs from the "
                              "row's own")
        return OpResult(op, Outcome.PROTECTED, "no row changed, confirmed as superuser ("
                        + "; ".join(answers) + ")", None, tries=len(answers))

    @staticmethod
    def _changed(op, method, how, key, gone, new, detached, tries) -> OpResult:
        basis = (f"anon {'changed' if op is Op.UPDATE else 'deleted'} {len(gone)} row(s) "
                 f"with {method} {how} (confirmed as superuser)")
        if detached:
            basis += "; the rows referencing it were removed first, as a foreign key stopped it"
        if op is Op.UPDATE:
            same = lambda r: all(r[k] == gone[0][k] for k in key)  # no key: rows in order
            evidence = {"before": gone[0], "after": next((r for r in new if same(r)), new[0])}
        else:
            evidence = {"rows_deleted": len(gone),
                        "deleted": {k: gone[0][k] for k in key} if key else gone[0]}
        return OpResult(op, Outcome.EXPOSED, basis, evidence, tries=tries)

    def _rls_answered(self, table: str, op: Op, method: str, resp, values, target) -> str | None:
        """Why row-level security (or a missing grant) refused this write, or None if it did
        not: a 42501, or a 2xx that changed nothing, is RLS's only if anon's policies refuse
        the rows it reached, evaluated as PostgREST ran this request."""
        if _refused(resp) or (200 <= resp.status < 300 and op is not Op.INSERT):
            return self._db.rls_refusal(op.value, table, values, target,
                                        self._channel.settings(method, table, values))
        return None

    def _post(self, table: str, row: dict):
        """POST a row. On a unique violation (the policy let the row through; a seeded row holds
        its key) remove that seeded row and send it again."""
        before = self._db.rows(table)
        resp = self._send("POST", table, None, row)
        if _code(resp) == "23505":
            constraint = str(_body(resp).get("message", "")).rpartition(' constraint "')[2][:-1]
            if self._db.make_room(table, constraint, row):
                before = self._db.rows(table)
                return self._send("POST", table, None, row), constraint, before
        return resp, None, before

    def _candidates(self, table: str, base: dict) -> list[tuple[str, dict]]:
        """Changes to the base row, by source: for policy and CHECK constants first all of a
        source's columns at once (a policy may test two), then one column at a time."""
        sources = self._db.value_sources(table)
        out, seen = [], {_key(base)}
        for source in _SOURCES:
            pairs = [(c, v) for s, c, v in sources if s == source]
            changes = [{c: v} for c, v in pairs]
            if source in ("policy", "check") and len({c for c, _ in pairs}) > 1:
                changes.insert(0, {c: v for c, v in reversed(pairs)})  # each column's first value
            for change in changes:
                if _key(dict(base, **change)) not in seen:
                    seen.add(_key(dict(base, **change)))
                    out.append((source, change))
        return out

    def _fresh_row(self, table: str) -> dict:
        row = self._db.fake_row(table)
        if row is None:  # never call a table protected without attacking it
            raise AttackError(f"{table}: no fake row can be made, so it cannot be attacked")
        return row

    def _send(self, method: str, table: str, query, body):
        resp = self._channel.request(method, table, query, body)
        if resp.status >= 500:
            raise AttackError(f"{method} {table}: the REST layer failed ({_answer(resp)})")
        return resp


def _refused(resp) -> bool:
    """Row-level security's or a grant's refusal (PostgREST: 401/403 with 42501)."""
    return _code(resp) == "42501"


def _unclean(table: str, op: Op, answers: list[str]) -> AttackError:
    return AttackError(f"{table}: {op.value} got no answer from row-level security, so it is "
                       f"neither exposed nor protected ({answers[0]})")


def _body(resp) -> dict:
    return resp.body if isinstance(resp.body, dict) else {}


def _code(resp) -> str | None:
    return _body(resp).get("code")


def _answer(resp) -> str:
    return f"HTTP {resp.status}{_pg_code(resp.body)}"


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
