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
DEV_PASSWORD = "dev-only-{}-password"  # the test people's (PEOPLE, below)


def pytest_collection_modifyitems(config, items):
    if os.environ.get("CATALYST_USERS_IT") == "1":
        return
    skip = pytest.mark.skip(reason="integration tests: set CATALYST_USERS_IT=1 with `docker compose up -d`")
    for item in items:
        if "integration" in item.nodeid:
            item.add_marker(skip)


# The integration tests' people: development-only, created through the bootstrap admin, never in the realm file
# (id-PROVIDER-000007, env-LOCAL-000001).
PEOPLE = {
    "alice": ("Alice", "Developer", "/cantica-tech/catalyst/developers"),
    "bob": ("Bob", "Maintainer", "/cantica-tech/catalyst/maintainers"),
    "ada": ("Ada", "Stakeholder", "/cantica-tech"),
}


def _admin_call(method: str, path: str, body: object = None) -> object:
    req = urllib.request.Request(  # noqa: S310 - loopback test server
        f"{SERVER}/admin/realms/catalyst{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {bootstrap_token()}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        raw = resp.read()
    return json.loads(raw) if raw else None


@pytest.fixture(scope="session")
def dev_people() -> None:
    """Each test person, with their password and group, created when the realm lacks them (the compose realm's tests
    ask for it; the onboarding tests bring a Keycloak of their own)."""
    if os.environ.get("CATALYST_USERS_IT") != "1":
        return
    for username, (first, last, group) in PEOPLE.items():
        found = _admin_call("GET", f"/users?username={username}&exact=true")
        if not found:
            rep = {"username": username, "enabled": True, "emailVerified": True, "firstName": first, "lastName": last}
            _admin_call("POST", "/users", {**rep, "email": f"{username}@example.com"})
            found = _admin_call("GET", f"/users?username={username}&exact=true")
        user = found[0]["id"]
        reset = {"type": "password", "value": DEV_PASSWORD.format(username), "temporary": False}
        _admin_call("PUT", f"/users/{user}/reset-password", reset)
        target = _admin_call("GET", "/group-by-path/" + group.strip("/"))
        _admin_call("PUT", f"/users/{user}/groups/{target['id']}")


def api_secret() -> str:
    """catalyst-api's secret, which Keycloak generated: the realm file holds none."""
    client = _admin_call("GET", "/clients?clientId=catalyst-api")[0]["id"]
    return _admin_call("GET", f"/clients/{client}/client-secret")["value"]


@pytest.fixture
def settings() -> Settings:
    return Settings(server_url=SERVER, api_client_secret=api_secret())


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


def master_admin() -> tuple[str, str]:
    """An admin of realm `master`, who administers every realm (env-LOCAL-000002): compose.yaml's bootstrap admin, or
    the one a persistent dev Keycloak keeps instead, named by CATALYST_USERS_IT_ADMIN with a command printing their
    password in CATALYST_USERS_IT_ADMIN_PASSWORD_COMMAND (run without a shell; the password is never shown)."""
    from catalyst_users.provider import secret_from_command

    command = os.environ.get("CATALYST_USERS_IT_ADMIN_PASSWORD_COMMAND")
    password = secret_from_command(command, "the master admin's password command") if command else None
    return os.environ.get("CATALYST_USERS_IT_ADMIN", "admin"), password or "dev-only-admin-password"


def bootstrap_token() -> str:
    """The master admin's access token (`master_admin`)."""
    username, password = master_admin()
    form = {"grant_type": "password", "client_id": "admin-cli", "username": username, "password": password}
    url = f"{SERVER}/realms/master/protocol/openid-connect/token"
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode())  # noqa: S310 - loopback test server
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        return json.load(resp)["access_token"]


def approve_device(code: DeviceCode, username: str, password: str | None = None) -> None:
    """What a person does in the browser: open the link, sign in (with a test person's password unless given), grant
    access."""
    policy = http.cookiejar.DefaultCookiePolicy()
    policy.secure_protocols = ("https", "wss", "http")  # browsers treat loopback http as secure; urllib does not
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy)))

    def form_action(page: str, form_id: str | None = None) -> str:
        pattern = rf'<form[^>]*id="{form_id}"[^>]*action="([^"]+)"' if form_id else r'<form[^>]*action="([^"]+)"'
        action = html.unescape(re.search(pattern, page).group(1))
        return urllib.parse.urljoin(code.verification_uri_complete, action)

    page = opener.open(code.verification_uri_complete, timeout=10).read().decode()
    credentials = {"username": username, "password": password or DEV_PASSWORD.format(username)}
    page = opener.open(form_action(page, "kc-form-login"), urllib.parse.urlencode(credentials).encode()).read().decode()
    hidden = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
    opener.open(form_action(page), urllib.parse.urlencode({**hidden, "accept": "Yes"}).encode()).read()
