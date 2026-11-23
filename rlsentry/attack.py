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
    findings = []
    with Sandbox(migrations) as sandbox:
        attacker = Attacker(sandbox.anon_channel())
        for table in sandbox.tables:
            findings.append(TableFinding("public", table, {Op.READ: attacker.read(table)},
                                         sandbox.notes.get(table, [])))
    return RunReport(source, findings, started_at, __version__)
