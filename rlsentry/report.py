"""Findings types and their rendering. Verdicts are decided by the attacker, not here."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum


class Op(Enum):
    READ = "READ"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class Outcome(Enum):
    EXPOSED = "EXPOSED"
    PROTECTED = "protected"


@dataclass(frozen=True)
class OpResult:
    op: Op
    outcome: Outcome
    basis: str
    evidence: dict | None
    tries: int = 1


@dataclass(frozen=True)
class TableFinding:
    schema: str
    table: str
    results: dict[Op, OpResult]
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RunReport:
    source: str
    findings: list[TableFinding]
    started_at: str
    rlsentry_version: str

    @property
    def exposed(self) -> bool:
        return any(
            r.outcome is Outcome.EXPOSED for f in self.findings for r in f.results.values()
        )


def to_dict(report: RunReport) -> dict:
    return {
        "source": report.source,
        "started_at": report.started_at,
        "rlsentry_version": report.rlsentry_version,
        "findings": [
            {
                "schema": f.schema,
                "table": f.table,
                "results": {
                    op.value: {
                        "op": r.op.value,
                        "outcome": r.outcome.value,
                        "basis": r.basis,
                        "evidence": r.evidence,
                        "tries": r.tries,
                    }
                    for op, r in f.results.items()
                },
                "notes": list(f.notes),
            }
            for f in report.findings
        ],
    }


def render_json(report: RunReport) -> str:
    return json.dumps(to_dict(report), indent=2, default=str)


def render_text(report: RunReport) -> str:
    lines = [f"rlsentry {report.rlsentry_version} attack on {report.source} ({report.started_at})", ""]
    for f in report.findings:
        lines.append(f"{f.schema}.{f.table}")
        for r in f.results.values():
            outcome = r.outcome.value
            if r.op is Op.INSERT and r.outcome is Outcome.PROTECTED:
                outcome += f" ({r.tries} row{'s' if r.tries != 1 else ''} tried)"
            lines.append(f"  {r.op.value}: {outcome} - {r.basis}")
            if r.evidence is not None:
                lines.append(f"    evidence: {json.dumps(r.evidence, default=str)}")
        for note in f.notes:
            lines.append(f"  note: {note}")
    exposed = sum(
        1 for f in report.findings for r in f.results.values() if r.outcome is Outcome.EXPOSED
    )
    lines += ["", f"{exposed} exposed operation(s) in {len(report.findings)} table(s)."]
    return "\n".join(lines)
