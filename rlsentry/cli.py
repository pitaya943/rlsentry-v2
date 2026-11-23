"""Command line: arguments and exit codes only (0 nothing exposed, 1 exposed, 2 could not run)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rlsentry")
    sub = parser.add_subparsers(dest="command", required=True)
    attack = sub.add_parser("attack", help="attack a disposable copy as the anonymous visitor")
    source = attack.add_mutually_exclusive_group(required=True)
    source.add_argument("--lab", action="store_true", help="attack the bundled lab schemas")
    source.add_argument("--migrations", type=Path, metavar="DIR", help="folder of .sql migrations")
    source.add_argument("--target", metavar="URL", help="refused: rlsentry never attacks a live project")
    attack.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    if args.target is not None:
        print(f"rlsentry: refusing --target {args.target}: attack mode only attacks a copy it "
              "builds itself from migrations (use --migrations DIR or --lab). Nothing was sent.",
              file=sys.stderr)
        return 2

    # Imported here so the refusal above needs nothing but argparse.
    from rlsentry.attack import LAB, run
    from rlsentry.attacker import AttackError
    from rlsentry.report import render_json, render_text
    from rlsentry.sandbox import BuildError, Interrupted

    migrations, label = (LAB, "lab") if args.lab else (args.migrations, str(args.migrations))
    if not migrations.is_dir():
        print(f"rlsentry: {migrations} is not a directory", file=sys.stderr)
        return 2
    try:
        report = run(migrations, label)
    except (BuildError, AttackError) as err:
        print(f"rlsentry: could not build or attack the copy: {err}", file=sys.stderr)
        return 2
    except Interrupted as sig:
        print(f"rlsentry: interrupted ({sig}); the copy was torn down", file=sys.stderr)
        return 2
    except Exception as err:  # exit 1 means "exposed"; a run that broke says nothing of the kind
        print(f"rlsentry: the run failed unexpectedly ({type(err).__name__}: {err}); "
              "the copy was torn down", file=sys.stderr)
        return 2
    print(render_json(report) if args.json else render_text(report))
    return 1 if report.exposed else 0
