"""The only way the attacker reaches a database: HTTP to a sandbox's REST layer, as anon.

Only `Sandbox.anon_channel()` constructs an `AnonChannel` (checked by a source-tree test).
It takes a port, not a URL, so its address is always 127.0.0.1; before its first request it
asks the sandbox to confirm the run nonce (design §2).

It is also the one source of what PostgREST sets in the database for a request (the token's
claims, the method, path and headers): the sandbox's RLS oracle evaluates policies under it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


# No proxy, whatever the environment says: the request must reach the sandbox directly.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def anon_jwt(secret: str, lifetime_s: int = 3600) -> str:
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(
        json.dumps({"role": "anon", "iss": "rlsentry", "exp": int(time.time()) + lifetime_s}).encode()
    )
    signing_input = f"{header}.{payload}".encode()
    signature = b64(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


@dataclass(frozen=True)
class Response:
    status: int
    body: Any


class AnonChannel:
    def __init__(self, port: int, token: str, verify: Callable[[], None]):
        self._base = f"http://127.0.0.1:{int(port)}"
        self._token = token
        self._verify = verify
        self._verified = False

    def request(self, method: str, table: str, query: dict[str, str] | None = None,
                body: Any = None) -> Response:
        if not self._verified:
            self._verify()
            self._verified = True
        url = f"{self._base}/{urllib.parse.quote(table)}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = _data(body)
        req = urllib.request.Request(url, data=data, method=method, headers=self._headers(data))
        try:
            with _opener.open(req, timeout=60) as resp:
                return Response(resp.status, _json(resp.read()))
        except urllib.error.HTTPError as err:
            return Response(err.code, _json(err.read()))

    def settings(self, method: str, table: str, body: Any = None) -> dict[str, str]:
        """The settings PostgREST 12 makes for this request, as `request()` would send it."""
        payload = self._token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return {
            "request.jwt.claims": json.dumps(claims, separators=(",", ":"), sort_keys=True),
            "request.method": method,
            "request.path": "/" + urllib.parse.quote(table),
            "request.headers": json.dumps({k.lower(): v for k, v in self._headers(_data(body)).items()}),
            "request.cookies": "{}",
        }

    def _headers(self, data: bytes | None) -> dict[str, str]:
        """Every header the request carries (urllib adds none of its own beside these)."""
        headers = {
            "Host": self._base.removeprefix("http://"),
            "User-Agent": "rlsentry",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Authorization": f"Bearer {self._token}",
            "apikey": self._token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if data is not None:
            headers["Content-Length"] = str(len(data))
        return headers


def _data(body: Any) -> bytes | None:
    return None if body is None else json.dumps(body).encode()


def _json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")
