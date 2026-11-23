"""S-7: rlsentry never attacks a live project."""

import ast
import json
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


# The properties below need a real sandbox: design §2's nonce check, the running state,
# the 127.0.0.1 address, no proxy, and both servers listening on loopback only.

import http.server
import os
import signal
import subprocess
import sys
import threading
import time

from conftest import FIXTURES, rlsentry, wait_for_marker
from rlsentry.channel import AnonChannel
from rlsentry.sandbox import BuildError, Sandbox


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    with Sandbox(FIXTURES / "clean") as sb:
        yield sb


def _marker_pids(sb_state_dir):
    [marker] = sb_state_dir.glob("*.json")
    return json.loads(marker.read_text())["pids"]


@pytest.mark.parametrize("tamper", [
    "update rlsentry_run.nonce set value = 'someone-else'",
    "delete from rlsentry_run.nonce",
])
def test_first_request_is_refused_when_the_nonce_is_not_ours(sandbox, tamper):
    # Stands in for "the port now answers for a database this run did not build".
    sandbox._conn.execute(tamper)
    channel = sandbox.anon_channel()
    with pytest.raises(BuildError, match="nonce"):
        channel.request("GET", "clean", {"select": "*"})


def test_first_request_is_refused_when_a_sandbox_server_has_died(sandbox, tmp_path):
    pids = _marker_pids(tmp_path / "state")
    os.kill(pids[-1], signal.SIGKILL)  # PostgREST: the port no longer belongs to our process
    os.waitpid(pids[-1], 0)
    with pytest.raises(BuildError, match="not running"):
        sandbox.anon_channel().request("GET", "clean", {"select": "*"})


def test_anon_channel_needs_a_running_sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    sb = Sandbox(FIXTURES / "clean")
    with pytest.raises(RuntimeError, match="running sandbox"):
        sb.anon_channel()  # never built
    with sb:
        sb.anon_channel()
    with pytest.raises(RuntimeError, match="running sandbox"):
        sb.anon_channel()  # torn down


class _Recorder(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.paths.append(self.path)
        body = b"[]"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def listener():
    """Start an HTTP server on 127.0.0.1 that records the paths it is asked for."""
    servers = []

    def start():
        server = http.server.HTTPServer(("127.0.0.1", 0), _Recorder)
        server.paths = []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


class _EveryVariableIs(dict):
    """An os.environ where every variable, whatever its name, holds one value."""

    def __init__(self, value):
        super().__init__()
        self._value = value

    def __getitem__(self, key):
        return self._value

    def get(self, key, default=None):
        return self._value

    def __contains__(self, key):
        return True


def test_channel_address_is_127_0_0_1_and_its_port_whatever_the_environment(listener, monkeypatch):
    sandbox_port, decoy = listener(), listener()
    decoy_url = f"http://127.0.0.1:{decoy.server_address[1]}"
    monkeypatch.setattr(os, "environ", _EveryVariableIs(decoy_url))
    channel = AnonChannel(sandbox_port.server_address[1], "token", lambda: None)
    resp = channel.request("GET", "t", {"select": "*"})
    monkeypatch.undo()
    assert resp.status == 200
    assert sandbox_port.paths == ["/t?select=%2A"]
    assert decoy.paths == []


def test_attack_requests_ignore_proxy_environment_variables(listener, tmp_path):
    proxy = listener()
    proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
    env = {k: v for k, v in os.environ.items() if k.lower() != "no_proxy"}
    env.update(RLSENTRY_STATE_DIR=str(tmp_path / "state"), http_proxy=proxy_url,
               HTTP_PROXY=proxy_url, all_proxy=proxy_url, ALL_PROXY=proxy_url)
    run = subprocess.run([sys.executable, "-m", "rlsentry", "attack", "--lab"], env=env,
                         capture_output=True, text=True, timeout=120)
    assert proxy.paths == []
    assert run.returncode == 1, run.stderr
    assert "8 exposed operation(s) in 7 table(s)." in run.stdout


def _listening_addresses(pid):
    """Local (address, port) of every TCP socket in LISTEN state that `pid` holds."""
    inodes = set()
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[8:-1])
    found = []
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        if not os.path.exists(table):  # no IPv6 on this machine
            continue
        for line in open(table).read().splitlines()[1:]:
            cols = line.split()
            if cols[3] == "0A" and cols[9] in inodes:  # 0A = LISTEN
                addr, port = cols[1].split(":")
                found.append((_ip(addr), int(port, 16)))
    return found


def _ip(hex_addr):
    raw = bytes.fromhex(hex_addr)
    if len(raw) == 4:
        return ".".join(str(b) for b in reversed(raw))
    words = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
    return "[" + b"".join(words).hex() + "]"


def test_both_sandbox_servers_listen_on_loopback_only(state_dir):
    proc = rlsentry("attack", "--migrations", str(FIXTURES / "slow"), state_dir=state_dir)
    try:
        _, info = wait_for_marker(state_dir)
        deadline = time.monotonic() + 30
        while not all(_listening_addresses(pid) for pid in info["pids"]):
            assert time.monotonic() < deadline, "a sandbox server never started listening"
            time.sleep(0.1)
        addresses = {pid: _listening_addresses(pid) for pid in info["pids"]}
    finally:
        proc.send_signal(signal.SIGINT)
        proc.communicate(timeout=60)
    assert len(addresses) == 2
    for pid, found in addresses.items():
        assert found and {addr for addr, _ in found} == {"127.0.0.1"}, (pid, found)
