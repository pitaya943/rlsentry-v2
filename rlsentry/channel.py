"""The only way the attacker reaches a database: HTTP to a sandbox's REST layer, as anon.

Only `Sandbox.anon_channel()` constructs an `AnonChannel` (checked by a source-tree test).
It takes a port, not a URL, so its address is always 127.0.0.1; before its first request it
asks the sandbox to confirm the run nonce (design §2).
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
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self._token}",
            "apikey": self._token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        try:
            with _opener.open(req, timeout=60) as resp:
                return Response(resp.status, _json(resp.read()))
        except urllib.error.HTTPError as err:
            return Response(err.code, _json(err.read()))


def _json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")
