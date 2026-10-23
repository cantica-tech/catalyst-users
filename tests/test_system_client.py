"""catalyst's system client (env-LOCAL-000003): its declaration, and what set_system_client does in a realm."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from catalyst_users.http import Response

KEYCLOAK = Path(__file__).resolve().parent.parent / "keycloak"
sys.path.insert(0, str(KEYCLOAK))  # the scripts import each other as siblings

import set_system_client as ssc  # noqa: E402


class FakeAdmin:
    """The admin API of a realm, recorded."""

    def __init__(self, clients: list[dict[str, Any]] | None = None, held: list[str] | None = None) -> None:
        self.clients = clients or []
        self.held = held or []
        self.calls: list[tuple[str, str, Any]] = []
        self.secret = ""

    def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None) -> Response:
        self.calls.append((method, path, body))
        payload: Any = None
        if (method, path) == ("GET", "/clients"):
            payload = self.clients
        elif (method, path) == ("POST", "/clients"):
            self.clients = [{"id": "uuid-1", **body}]
        elif path.endswith("/protocol-mappers/models") and method == "GET":
            payload = [{"name": "catalyst grants"}]
        elif path.endswith("/service-account-user"):
            payload = {"id": "sa-1"}
        elif (method, path) == ("GET", "/users/sa-1/role-mappings/realm"):
            payload = [{"name": n} for n in self.held]
        elif method == "GET" and path.startswith("/roles/"):
            payload = {"id": f"r-{path[7:]}", "name": path[7:]}
        elif path.endswith("/client-secret"):
            if method == "POST":
                self.secret = "generated"
            payload = {"type": "secret", "value": self.secret} if self.secret else {"type": "secret"}
        return Response(200, {}, json.dumps(payload).encode() if payload is not None else b"")


def test_the_realm_declares_a_confidential_service_account_client_without_a_secret():
    client = ssc.declared_client(json.loads(ssc.REALM_FILE.read_text()))
    assert client["publicClient"] is False and client["serviceAccountsEnabled"] is True
    assert not (client["standardFlowEnabled"] or client["implicitFlowEnabled"] or client["directAccessGrantsEnabled"])
    assert "oauth2.device.authorization.grant.enabled" not in client.get("attributes", {})
    mappers = {m["name"] for m in client["protocolMappers"]}
    assert {"audience catalyst-api", "catalyst grants"} <= mappers


def test_a_declaration_holding_a_secret_is_refused():
    with pytest.raises(SystemExit, match="must not hold"):
        ssc.declared_client({"clients": [{"clientId": "catalyst-system", "secret": "x"}]})
    with pytest.raises(SystemExit, match="declares no"):
        ssc.declared_client({"clients": []})


def test_creates_the_client_only_when_missing():
    admin = FakeAdmin()
    assert ssc.ensure_client(admin, {"clientId": "catalyst-system"}) == ("uuid-1", True)
    assert ("POST", "/clients", {"clientId": "catalyst-system"}) in admin.calls
    again = FakeAdmin(clients=[{"id": "uuid-9", "clientId": "catalyst-system"}])
    mappers = [{"name": "catalyst grants"}, {"name": "realm roles in userinfo"}]
    assert ssc.ensure_client(again, {"clientId": "catalyst-system", "protocolMappers": mappers}) == ("uuid-9", False)
    posted = [(path, body) for method, path, body in again.calls if method == "POST"]
    assert posted == [("/clients/uuid-9/protocol-mappers/models", {"name": "realm roles in userinfo"})]


def test_grants_only_the_roles_the_service_account_lacks():
    admin = FakeAdmin(held=["stakeholder"])
    assert ssc.grant_roles(admin, "uuid-1", ["stakeholder", "catalyst-admin"]) == ["catalyst-admin"]
    assert ("POST", "/users/sa-1/role-mappings/realm", [{"id": "r-catalyst-admin", "name": "catalyst-admin"}]) in (
        admin.calls
    )
    none = FakeAdmin()
    assert ssc.grant_roles(none, "uuid-1", []) == [] and none.calls == []


def test_reads_the_secret_and_generates_one_when_there_is_none():
    admin = FakeAdmin()
    admin.secret = "kept"
    assert ssc.client_secret(admin, "uuid-1") == "kept"
    fresh = FakeAdmin()
    assert ssc.client_secret(fresh, "uuid-1") == "generated"


def test_the_keychain_line_quotes_the_secret_for_security():
    line = ssc.keychain_command('a"b\\c')
    assert line == 'add-generic-password -U -s "catalyst-system@catalyst-users" -a "catalyst-system" -w "a\\"b\\\\c"\n'
