"""Integration tests run against the compose Keycloak only when CATALYST_USERS_IT=1
(env-QUALITY-000002); start it with `docker compose up -d`."""

from __future__ import annotations

import html
import http.cookiejar
import json
import os
import re
import urllib.parse
import urllib.request

import pytest

from catalyst_users.config import Settings
from catalyst_users.oidc import DeviceCode

SERVER = os.environ.get("CATALYST_USERS_IT_SERVER", "http://127.0.0.1:8080")
DEV_PASSWORD = "dev-only-{}-password"  # the realm's dev-only users (keycloak/realm-catalyst.json)


def pytest_collection_modifyitems(config, items):
    if os.environ.get("CATALYST_USERS_IT") == "1":
        return
    skip = pytest.mark.skip(reason="integration tests: set CATALYST_USERS_IT=1 with `docker compose up -d`")
    for item in items:
        if "integration" in item.nodeid:
            item.add_marker(skip)


@pytest.fixture
def settings() -> Settings:
    return Settings(server_url=SERVER, api_client_secret="dev-only-api-secret")


def password_token(username: str, client_id: str = "catalyst-tests") -> str:
    """A real access token through the dev-only password-grant client."""
    form = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": DEV_PASSWORD.format(username),
        "scope": "openid",
    }
    url = f"{SERVER}/realms/catalyst/protocol/openid-connect/token"
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode())  # noqa: S310 - loopback test server
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        return json.load(resp)["access_token"]


def bootstrap_token() -> str:
    """The dev bootstrap admin of realm `master` (compose.yaml), who administers every realm (env-LOCAL-000002)."""
    form = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": "admin",
        "password": "dev-only-admin-password",
    }
    url = f"{SERVER}/realms/master/protocol/openid-connect/token"
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode())  # noqa: S310 - loopback test server
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        return json.load(resp)["access_token"]


def approve_device(code: DeviceCode, username: str) -> None:
    """What a person does in the browser: open the link, sign in, grant access."""
    policy = http.cookiejar.DefaultCookiePolicy()
    policy.secure_protocols = ("https", "wss", "http")  # browsers treat loopback http as secure; urllib does not
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy)))

    def form_action(page: str, form_id: str | None = None) -> str:
        pattern = rf'<form[^>]*id="{form_id}"[^>]*action="([^"]+)"' if form_id else r'<form[^>]*action="([^"]+)"'
        action = html.unescape(re.search(pattern, page).group(1))
        return urllib.parse.urljoin(SERVER, action)

    page = opener.open(code.verification_uri_complete, timeout=10).read().decode()
    credentials = {"username": username, "password": DEV_PASSWORD.format(username)}
    page = opener.open(form_action(page, "kc-form-login"), urllib.parse.urlencode(credentials).encode()).read().decode()
    hidden = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
    opener.open(form_action(page), urllib.parse.urlencode({**hidden, "accept": "Yes"}).encode()).read()
