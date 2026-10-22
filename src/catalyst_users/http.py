"""A small HTTP layer over urllib: HTTPS only (loopback excepted), no redirects,
a timeout on every call (id-AUTH-000005). The transport is injectable so unit
tests never touch the network (env-QUALITY-000002)."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from catalyst_users.errors import InsecureURLError, ProviderUnavailableError

LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK):
        return
    raise InsecureURLError(f"refusing {parts.scheme or 'no'}:// to {parts.hostname or url}: HTTPS is required")


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


Transport = Callable[[Request, float], Response]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a 3xx comes back as a response, never followed


_OPENER = urllib.request.build_opener(_NoRedirect)


def urllib_transport(request: Request, timeout: float) -> Response:
    req = urllib.request.Request(  # noqa: S310 - the scheme is checked by check_url
        request.url, data=request.body, headers=dict(request.headers), method=request.method
    )
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return Response(resp.status, dict(resp.headers.items()), resp.read())
    except urllib.error.HTTPError as err:
        return Response(err.code, dict(err.headers.items()) if err.headers else {}, err.read() or b"")
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        reason = getattr(err, "reason", err)
        raise ProviderUnavailableError(f"identity provider unreachable: {reason}") from None


class Http:
    def __init__(self, transport: Transport | None = None, timeout: float = 10.0) -> None:
        self._transport = transport or urllib_transport
        self.timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        form: Mapping[str, str] | None = None,
        json_body: Any = None,
        bearer: str | None = None,
        basic: tuple[str, str] | None = None,
    ) -> Response:
        check_url(url)
        if params:
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
            url = f"{url}?{query}" if query else url
        headers = {"Accept": "application/json"}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        elif basic:
            user, password = (urllib.parse.quote(part, safe="") for part in basic)
            headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        return self._transport(Request(method, url, headers, body), self.timeout)
