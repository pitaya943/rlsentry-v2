"""Every attacking request, made as anon through an AnonChannel, and the verdicts."""

from __future__ import annotations

from rlsentry.channel import AnonChannel
from rlsentry.report import Op, OpResult, Outcome


class AttackError(Exception):
    """The REST layer failed in a way that says nothing about the policies."""


class Attacker:
    def __init__(self, channel: AnonChannel):
        self._channel = channel

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


def _pg_code(body) -> str:
    if isinstance(body, dict) and body.get("code"):
        return f" {body['code']}: {body.get('message', '')}".rstrip(": ")
    return ""
