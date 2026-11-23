"""One attack run: build the copy, attack every table as anon, tear the copy down."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from rlsentry import __version__
from rlsentry.attacker import Attacker
from rlsentry.report import Op, RunReport, TableFinding
from rlsentry.sandbox import Sandbox

LAB = Path(__file__).parent / "lab"


def run(migrations: Path, source: str) -> RunReport:
    """Raises BuildError / AttackError (exit 2) or Interrupted."""
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with Sandbox(migrations) as sandbox:
        findings = attack(sandbox)
    return RunReport(source, findings, started_at, __version__)


def attack(sandbox: Sandbox) -> list[TableFinding]:
    """Every operation on every table, each write on the seeded state (restored after it)."""
    attacker = Attacker(sandbox.anon_channel(), sandbox.inspector())
    findings = []
    for table in sandbox.tables:
        results = {Op.READ: attacker.read(table)}
        for op, attempt in ((Op.INSERT, attacker.insert), (Op.UPDATE, attacker.update),
                            (Op.DELETE, attacker.delete)):
            try:
                results[op] = attempt(table)
            finally:
                sandbox.restore()
        findings.append(TableFinding("public", table, results, sandbox.notes.get(table, [])))
    return findings
