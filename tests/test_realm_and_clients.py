"""The dev realm file holds no person or secret (id-PROVIDER-000007), and sync_clients adds what a running realm
lacks (env-LOCAL-000003)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from catalyst_users.http import Response
from catalyst_users.providers.keycloak import definition_problems

KEYCLOAK = Path(__file__).resolve().parent.parent / "keycloak"
sys.path.insert(0, str(KEYCLOAK))  # the scripts import each other as siblings

import sync_clients  # noqa: E402

REALM = json.loads((KEYCLOAK / "realm-catalyst.json").read_text())


class FakeAdmin:
    def __init__(self, clients: list[dict[str, Any]] | None = None) -> None:
        self.clients = clients or []
        self.calls: list[tuple[str, str, Any]] = []

    def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None) -> Response:
        self.calls.append((method, path, body))
        payload: Any = None
        if (method, path) == ("GET", "/clients"):
            payload = [c for c in self.clients if c["clientId"] == (params or {}).get("clientId")]
        elif method == "GET" and path.endswith("/protocol-mappers/models"):
            payload = [{"name": "groups"}]
        return Response(200, {}, json.dumps(payload).encode() if payload is not None else b"")


def test_the_dev_realm_holds_no_person_and_no_secret():
    assert definition_problems(REALM) == []
    assert "users" not in REALM
    assert all("secret" not in c for c in REALM["clients"])


def test_the_dev_realm_declares_the_admin_password_client_with_the_mappers():
    client = next(c for c in REALM["clients"] if c["clientId"] == "catalyst-admin-cli")
    assert client["publicClient"] and client["directAccessGrantsEnabled"]
    assert not (client["standardFlowEnabled"] or client["serviceAccountsEnabled"])
    mappers = {m["name"] for m in client["protocolMappers"]}
    assert {"groups", "audience catalyst-api", "realm roles in userinfo", "catalyst grants"} <= mappers


@pytest.mark.parametrize(
    ("definition", "named"),
    [
        ({"realm": "r", "users": [{"username": "a"}]}, "`users`"),
        ({"realm": "r", "clients": [{"clientId": "c", "secret": "s"}]}, "`clients[0].secret`"),
        ({"realm": "r", "smtpServer": {"password": "p"}}, "`smtpServer.password`"),
        ({"realm": "r", "identityProviders": [{"config": {"clientSecret": "s"}}]}, "clientSecret"),
    ],
)
def test_a_definition_with_a_person_or_a_secret_is_refused(definition, named):
    problems = definition_problems(definition)
    assert problems and named in problems[0]


def test_an_empty_secret_field_or_a_password_policy_is_not_a_secret():
    assert definition_problems({"realm": "r", "passwordPolicy": "length(12)", "clients": [{"secret": ""}]}) == []
    assert definition_problems([]) == ["the realm definition is not a JSON object"]


def test_sync_creates_a_missing_client_and_adds_missing_mappers_only():
    admin = FakeAdmin()
    assert sync_clients.sync_client(admin, {"clientId": "c1"}) == ["c1"]
    assert ("POST", "/clients", {"clientId": "c1"}) in admin.calls
    held = FakeAdmin(clients=[{"id": "u-9", "clientId": "c2"}])
    mappers = [{"name": "groups"}, {"name": "catalyst grants"}]
    assert sync_clients.sync_client(held, {"clientId": "c2", "protocolMappers": mappers}) == ["c2: catalyst grants"]
    posted = [(path, body) for method, path, body in held.calls if method == "POST"]
    assert posted == [("/clients/u-9/protocol-mappers/models", {"name": "catalyst grants"})]


def test_sync_refuses_a_realm_file_with_a_secret():
    with pytest.raises(SystemExit, match="person or a secret"):
        sync_clients.declared_clients({"clients": [{"clientId": "c", "secret": "s"}]})
