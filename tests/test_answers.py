"""Only an answer the copy confirms decides a verdict (T-07, PR #10 verdict D1 and D2).

The channel never follows a redirect: migration code can make PostgREST answer any 3xx (the
response.status and response.headers settings), and following it would send the anon request,
token included, wherever it points. A READ is EXPOSED only with rows the copy's superuser holds
in the table, and protected only on PostgreSQL's own account of that very request.
https://github.com/pitaya943/rlsentry-v2/pull/10#issuecomment-7143781168
"""

import http.server
import json
import threading
import urllib.error
import urllib.request

import pytest

import conftest
from conftest import run_rlsentry


class _Listener(http.server.BaseHTTPRequestHandler):
    """Records every request; answers with `server.answer(handler)` -> (status, body bytes),
    or None when the answer wrote its own."""

    def _any(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.sent = self.rfile.read(length) if length else None
        self.server.seen.append(f"{self.command} {self.path}")
        answer = self.server.answer(self)
        if answer is None:
            return
        status, body = answer
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PATCH = do_DELETE = _any

    def log_message(self, *args):
        pass


@pytest.fixture
def listener():
    """Start an HTTP server on 127.0.0.1 with the given answer; it records what reached it."""
    servers = []

    def start(answer):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Listener)
        server.seen, server.answer = [], answer
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _run(tmp_path, state_dir, text):
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "001_t.sql").write_text(text)
    return run_rlsentry("attack", "--migrations", str(folder), "--json", state_dir=state_dir)


def _bounce(port, returns):
    """A function a policy can call: it makes PostgREST answer 302 to the listener."""
    return f"""
create function public.bounce() returns boolean language plpgsql as $$
begin
  perform set_config('response.status', '302', true);
  perform set_config('response.headers',
                     '[{{"Location": "http://127.0.0.1:{port}/rest/v1/elsewhere"}}]', true);
  return {returns};
end $$;
"""


_NOTES = """
create table notes (id bigint generated always as identity primary key, body text not null);
alter table notes enable row level security;
"""


@pytest.mark.parametrize("returns, answer", [
    # the verdict's two reproductions: a row the copy never held read EXPOSED (exit 1), and a
    # table whose every row anon reads read protected (exit 0)
    ("false", [{"id": 1, "secret": "FABRICATED-NOT-IN-COPY"}]),
    ("true", []),
], ids=["fabricated-exposed", "false-protected"])
def test_a_read_answered_with_a_redirect_gives_no_verdict_and_goes_nowhere(
        listener, state_dir, tmp_path, returns, answer):
    elsewhere = listener(lambda h: (200, json.dumps(answer).encode()))
    code, out, err = _run(tmp_path, state_dir,
                          _NOTES + _bounce(elsewhere.server_address[1], returns)
                          + "create policy r on notes for select to anon using (public.bounce());\n")
    assert elsewhere.seen == []  # nothing, the anon token least of all, left the copy
    assert code == 2, out
    assert out == ""
    assert "notes: READ was answered with a redirect (HTTP 302)" in err


@pytest.mark.parametrize("op, policy", [
    ("INSERT", "for insert to anon with check (public.bounce())"),
    ("UPDATE", "for update to anon using (public.bounce())"),
    ("DELETE", "for delete to anon using (public.bounce())"),
])
def test_a_write_answered_with_a_redirect_gives_no_verdict_and_goes_nowhere(
        listener, state_dir, tmp_path, op, policy):
    # The write itself went through (bounce() lets it), but its answer points off the copy.
    elsewhere = listener(lambda h: (200, b"[]"))
    code, out, err = _run(tmp_path, state_dir, _NOTES + _bounce(elsewhere.server_address[1], "true")
                          + "create policy r on notes for select to anon using (true);\n"
                          + f"create policy w on notes {policy};\n")
    assert elsewhere.seen == []
    assert code == 2, out
    assert f"notes: {op} was answered with a redirect (HTTP 302)" in err


def test_the_wait_for_the_rest_layer_follows_no_redirect(listener):
    # Before the attack, rlsentry polls the REST layer until it answers 200; a 3xx is not that.
    from rlsentry.sandbox import _wait_http

    elsewhere = listener(lambda h: (200, b"{}"))
    answers = iter([(302, b"")])

    def rest(handler):
        status, body = next(answers, (200, b"{}"))
        if status == 302:
            handler.send_response(302)
            handler.send_header("Location", f"http://127.0.0.1:{elsewhere.server_address[1]}/")
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return None
        return status, body

    class Alive:
        alive = staticmethod(lambda: True)

    copy = listener(rest)
    _wait_http(copy.server_address[1], Alive())
    assert copy.seen == ["GET /", "GET /"]
    assert elsewhere.seen == []


# An answer that did not come from the copy as the copy gave it. Here something stands between
# rlsentry and the copy's REST layer (in place of PostgREST's port); it forwards the request or
# not, and changes the answer or not.

def _forward(handler, port):
    """Send the request on to the copy's REST layer as it came; its (status, body)."""
    headers = {k: v for k, v in handler.headers.items()
               if k.lower() not in ("host", "content-length")}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{handler.path}", data=handler.sent,
                                 method=handler.command, headers=headers)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def _twice(port):
    def answer(handler):
        status, body = _forward(handler, port)
        return status, json.dumps(json.loads(body)[:1] * 2).encode()
    return answer


def _instead(status, body, ask_the_copy=True):
    """Answer (status, body) whatever the copy said; ask it first (so PostgreSQL logs the
    request) or not."""
    def answer_for(port):
        def answer(handler):
            if ask_the_copy:
                _forward(handler, port)
            return status, body
        return answer
    return answer_for


_ANSWERS = {
    "as-it-came": lambda port: lambda h: _forward(h, port),
    "fabricated": _instead(200, b'[{"id": 1, "body": "FABRICATED-NOT-IN-COPY"}]', False),
    "one-real-row-twice": _twice,
    "empty-after-the-copy-answered": _instead(200, b"[]"),
    "empty-without-asking-the-copy": _instead(200, b"[]", False),
    "not-rows-after-the-copy-answered": _instead(200, b'{"rows": 0}'),
    "42501-after-the-copy-answered": _instead(401, b'{"code": "42501", "message": "permission '
                                              b'denied for table notes", "details": null, '
                                              b'"hint": null}'),
}
_READABLE = _NOTES + "create policy r on notes for select to anon using (true);\n"


@pytest.mark.parametrize("migration, answer, verdict", [
    (_READABLE, "as-it-came", "EXPOSED"),
    (_NOTES, "as-it-came", "protected"),
    (_READABLE, "fabricated", "the table does not hold"),
    (_READABLE, "one-real-row-twice", "the table does not hold"),
    (_READABLE, "empty-after-the-copy-answered", "HTTP 200)"),
    (_NOTES, "empty-without-asking-the-copy", "HTTP 200)"),
    (_NOTES, "not-rows-after-the-copy-answered", "HTTP 200)"),
    (_READABLE, "42501-after-the-copy-answered", "HTTP 401 42501"),
], ids=["exposed", "protected", "fabricated", "twice", "empty-after", "empty-alone", "not-rows",
        "42501"])
def test_a_read_verdict_rests_on_the_copy_not_on_the_answer(listener, tmp_path, monkeypatch,
                                                           migration, answer, verdict):
    from rlsentry.attacker import Attacker, AttackError
    from rlsentry.sandbox import Sandbox

    monkeypatch.setenv("RLSENTRY_STATE_DIR", str(tmp_path / "state"))
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "001_t.sql").write_text(migration)
    with Sandbox(folder, conftest.BACKEND) as sb:
        between = listener(_ANSWERS[answer](sb._rest_port))
        sb._rest_port = between.server_address[1]
        attacker = Attacker(sb.anon_channel(), sb.inspector())
        try:
            got = attacker.read("notes").outcome.value
        except AttackError as err:
            got = str(err)
    assert between.seen == ["GET /notes?select=%2A"]
    if verdict in ("EXPOSED", "protected"):
        assert got == verdict
    else:
        assert got.startswith("notes: READ got no answer from row-level security"), got
        assert verdict in got, got


def test_a_read_refused_by_the_tables_code_with_the_grants_own_words_is_never_protected(
        state_dir, tmp_path):
    # PostgREST answers 401 42501 "permission denied for table notes" either way; only the
    # server's log says it was a RAISE in the policy's function, not the privilege check.
    deny = _NOTES + """
create function public.deny() returns boolean language plpgsql as $$
begin raise exception 'permission denied for table notes' using errcode = '42501'; end $$;
create policy r on notes for select to anon using (public.deny());
"""
    code, out, err = _run(tmp_path, state_dir, deny)
    assert code == 2, out
    assert ("notes: READ got no answer from row-level security, so it is neither exposed nor "
            "protected (HTTP 401 42501: permission denied for table notes)") in err
    (tmp_path / "revoked").mkdir()  # the grant's own refusal, in the same words, is protected
    code, out, err = _run(tmp_path / "revoked", state_dir,
                          _NOTES + "revoke select on notes from anon;\n")
    assert code == 0, err
    read = json.loads(out)["findings"][0]["results"]["READ"]
    assert read["outcome"] == "protected"
    assert read["basis"] == "HTTP 401 42501: permission denied for table notes"


def test_a_readable_table_is_exposed_whatever_its_columns_write_out_by_the_search_path(
        state_dir, tmp_path):
    # A regclass names its table as PostgREST's search path sees it ("notes", not
    # "public.notes"): the rows anon received are still the rows the table holds.
    code, out, err = _run(tmp_path, state_dir, _READABLE.replace(
        "body text not null", "body text not null, kind regclass not null default 'public.notes'"))
    assert code == 1, err
    read = json.loads(out)["findings"][0]["results"]["READ"]
    assert read["outcome"] == "EXPOSED", read["basis"]
    assert read["evidence"]["row"]["kind"] == "notes"
