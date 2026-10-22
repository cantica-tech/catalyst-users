"""Test doubles: a fake transport and a discovery document (env-QUALITY-000002: no network)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from catalyst_users.config import Settings
from catalyst_users.http import Http, Request, Response
from catalyst_users.oidc import OIDCClient

ISSUER = "https://id.example.com/realms/catalyst"
OIDC = f"{ISSUER}/protocol/openid-connect"
ADMIN = "https://id.example.com/admin/realms/catalyst"

DISCOVERY = {
    "issuer": ISSUER,
    "token_endpoint": f"{OIDC}/token",
    "device_authorization_endpoint": f"{OIDC}/auth/device",
    "introspection_endpoint": f"{OIDC}/token/introspect",
    "userinfo_endpoint": f"{OIDC}/userinfo",
    "revocation_endpoint": f"{OIDC}/revoke",
}


def reply(status: int = 200, body: Any = None, headers: dict[str, str] | None = None) -> Response:
    return Response(status, headers or {}, json.dumps(body).encode() if body is not None else b"")


Handler = Response | list[Response] | Callable[[Request], Response]


class FakeTransport:
    """Answers by (method, URL without query); a list answers in turn."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Handler] = {
            ("GET", f"{ISSUER}/.well-known/openid-configuration"): reply(body=DISCOVERY)
        }
        self.requests: list[Request] = []

    def on(self, method: str, url: str, handler: Handler) -> None:
        self.routes[(method, url)] = handler

    def __call__(self, request: Request, timeout: float) -> Response:
        assert timeout > 0
        self.requests.append(request)
        key = (request.method, request.url.split("?", 1)[0])
        handler = self.routes.get(key)
        if handler is None:
            return reply(404, {"error": "not_found", "path": key[1]})
        if isinstance(handler, list):
            return handler.pop(0)
        if callable(handler):
            return handler(request)
        return handler

    def form(self, index: int = -1) -> dict[str, str]:
        from urllib.parse import parse_qsl

        return dict(parse_qsl((self.requests[index].body or b"").decode()))

    def calls(self, method: str | None = None) -> list[tuple[str, str]]:
        return [(r.method, r.url) for r in self.requests if method is None or r.method == method]


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture
def settings() -> Settings:
    return Settings(server_url="https://id.example.com", api_client_secret="api-secret")


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def oidc(settings: Settings, transport: FakeTransport, clock: Clock) -> OIDCClient:
    return OIDCClient(settings, Http(transport), clock=clock, sleep=clock.sleep)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CATALYST_USERS_HOME", str(tmp_path / "home"))
    for name in ("SERVER", "REALM", "CLIENT_ID", "API_CLIENT_ID", "API_CLIENT_SECRET", "TIMEOUT"):
        monkeypatch.delenv(f"CATALYST_USERS_{name}", raising=False)
    return tmp_path / "home"
