"""S-7: rlsentry never attacks a live project."""

import ast
import socket
from pathlib import Path

import pytest

from rlsentry.cli import main

PACKAGE = Path(__file__).parent.parent / "rlsentry"


def test_target_is_refused_before_any_connection(monkeypatch, capsys):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise OSError("network blocked by test")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)

    code = main(["attack", "--target", "https://x.supabase.co"])

    assert code == 2
    assert attempts == []
    assert "refusing --target https://x.supabase.co" in capsys.readouterr().err


def _modules():
    for path in sorted(PACKAGE.glob("*.py")):
        yield path, ast.parse(path.read_text(), filename=str(path))


def test_only_sandbox_constructs_anon_channel():
    constructors = [
        path.name
        for path, tree in _modules()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", getattr(node.func, "attr", None)) == "AnonChannel"
    ]
    assert constructors and set(constructors) == {"sandbox.py"}


@pytest.mark.parametrize("forbidden", ["urllib", "http", "socket", "requests", "httpx", "psycopg"])
def test_attacker_reaches_the_network_only_through_the_channel(forbidden):
    tree = ast.parse((PACKAGE / "attacker.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert forbidden not in imported
