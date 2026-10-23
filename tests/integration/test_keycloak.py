"""End to end against the local Keycloak (env-LOCAL-000001)."""

from __future__ import annotations

import base64
import json
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from catalyst_users.admin import KeycloakAdmin
from catalyst_users.credentials import CredentialStore
from catalyst_users.errors import AdminError, OIDCError
from catalyst_users.fastapi_auth import KeycloakAuth
from catalyst_users.identity import Identity
from catalyst_users.oidc import OIDCClient
from catalyst_users.providers.keycloak import KeycloakProvider
from catalyst_users.session import Session
from tests.integration.conftest import approve_device, bootstrap_token, password_token


@pytest.fixture
def oidc(settings):
    return OIDCClient(settings)


def test_device_login_whoami_refresh_logout(oidc, settings):
    session = Session(oidc, CredentialStore())
    shown = []

    def show(code):
        shown.append(code)
        threading.Thread(target=approve_device, args=(code, "alice"), daemon=True).start()

    who = session.login(show)
    assert shown and shown[0].user_code
    assert who.username == "alice" and who.issuer == settings.issuer
    assert who.in_group("/cantica-tech") and who.has_role("stakeholder")  # inherited from the parent group

    stored = session.store.load(settings.issuer, settings.client_id)
    refreshed = oidc.refresh(stored)
    assert refreshed.access_token != stored.access_token

    assert session.logout() is None
    assert not session.store.path.exists()
    with pytest.raises(OIDCError):  # the revoked refresh token no longer works
        oidc.refresh(stored)


def test_introspection_accepts_a_real_token_for_the_api(oidc):
    claims = oidc.introspect(password_token("bob"))
    assert oidc.accepts(claims)
    who = Identity.from_claims(claims)
    assert who.in_group("/cantica-tech/catalyst") and who.has_role("release-manager")


def test_introspection_rejects_garbage(oidc):
    assert not oidc.accepts(oidc.introspect("not-a-token"))


def test_directory_changes_with_an_admins_own_token(settings):
    admin = KeycloakAdmin(settings, bootstrap_token)
    suffix = secrets.token_hex(3)
    username, path = f"it-user-{suffix}", f"/it-{suffix}/team"

    group = admin.create_group(path)
    assert group.path == path and admin.group(f"/it-{suffix}").path == f"/it-{suffix}"
    admin.create_user(username, email=f"{username}@example.invalid", first_name="It", last_name="User")
    admin.add_member(path, username)
    assert admin.members(path) == [username]
    admin.grant_role_to_group(f"/it-{suffix}", "qa")
    assert "qa" in admin.group(f"/it-{suffix}").roles
    assert [g.path for g in admin.groups() if g.path.startswith(f"/it-{suffix}")] == [f"/it-{suffix}", path]
    assert admin.user_groups(username) == [path]

    assert admin.set_enabled(username, False).enabled is False
    assert admin.set_enabled(username, True).enabled is True
    admin.remove_member(path, username)
    assert admin.members(path) == []


def test_a_non_admin_cannot_change_the_directory(settings):
    admin = KeycloakAdmin(settings, lambda: password_token("alice"))
    with pytest.raises(AdminError, match="not allowed"):
        admin.create_role(f"it-role-{secrets.token_hex(3)}")


def test_fastapi_with_real_tokens(settings):
    auth = KeycloakAuth(settings)
    app = FastAPI()

    @app.get("/release", dependencies=[Depends(auth.require_roles("release-manager"))])
    def release():
        return {"ok": True}

    in_catalyst = auth.require_groups("/cantica-tech/catalyst")

    @app.get("/catalyst")
    def catalyst(who: Identity = Depends(in_catalyst)):
        return who.signer()

    client = TestClient(app)
    bob, alice = password_token("bob"), password_token("alice")
    assert client.get("/release", headers={"Authorization": f"Bearer {bob}"}).status_code == 200
    assert client.get("/release", headers={"Authorization": f"Bearer {alice}"}).status_code == 403
    assert client.get("/catalyst", headers={"Authorization": f"Bearer {alice}"}).json()["username"] == "alice"
    assert client.get("/catalyst", headers={"Authorization": "Bearer forged"}).status_code == 401


def test_provisioned_grants_reach_the_token(settings):
    from catalyst_users import provision
    from catalyst_users.provider import whoami_from_claims

    roles = [
        {
            "name": "Tech Lead / Architect",
            "id": "tech-lead",
            "actions": ["/create", "/freeze"],
            "reconciliation": "full",
        },
        {"name": "Release Manager", "id": "release-manager", "actions": ["/share"], "reconciliation": "full"},
        {"name": "Developer", "id": "developer", "actions": ["/create", "/status"], "reconciliation": "propose"},
    ]
    admin = KeycloakAdmin(settings, bootstrap_token)
    provision.provision(admin, roles, login_clients=("catalyst-cli", "catalyst-tests"))
    again = provision.provision(admin, roles, login_clients=("catalyst-cli", "catalyst-tests"))
    assert again.created == []  # idempotent
    bob = OIDCClient(settings).userinfo(password_token("bob"))  # maintainers: tech-lead, release-manager
    who = whoami_from_claims(bob, settings.issuer, "catalyst")
    assert {"create", "freeze", "share"} <= set(who.commands) and who.reconciliation == "full"
    alice = whoami_from_claims(OIDCClient(settings).userinfo(password_token("alice")), settings.issuer, "catalyst")
    assert set(alice.commands) == {"create", "status"} and alice.reconciliation == "propose"


def test_the_system_client_signs_in_with_client_credentials(settings):
    """catalyst-system (env-LOCAL-000003): its generated secret gets a token for the service account, nothing else."""
    admin = KeycloakAdmin(settings, bootstrap_token)
    client = admin._call("GET", "/clients", params={"clientId": "catalyst-system"}).json()[0]["id"]
    secret = admin._call("GET", f"/clients/{client}/client-secret").json()["value"]
    url = f"{settings.issuer}/protocol/openid-connect/token"
    form = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "client_id": "catalyst-system", "client_secret": secret}
    ).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=form), timeout=10) as resp:  # noqa: S310 - loopback
        token = json.load(resp)["access_token"]
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert claims["azp"] == "catalyst-system" and claims["iss"] == settings.issuer
    assert "catalyst-api" in ([claims["aud"]] if isinstance(claims["aud"], str) else claims["aud"])
    wrong = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "client_id": "catalyst-system", "client_secret": "wrong"}
    ).encode()
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(urllib.request.Request(url, data=wrong), timeout=10)  # noqa: S310 - loopback
    assert refused.value.code == 401


def test_the_keycloak_provider_signs_the_system_account_in(settings, monkeypatch):
    """The facade's system sign-in (id-AUTH-000006): the secret comes from secret_command, here reading the env."""
    admin = KeycloakAdmin(settings, bootstrap_token)
    client = admin._call("GET", "/clients", params={"clientId": "catalyst-system"}).json()[0]["id"]
    monkeypatch.setenv("IT_SYSTEM_SECRET", admin._call("GET", f"/clients/{client}/client-secret").json()["value"])
    command = [sys.executable, "-c", "import os; print(os.environ['IT_SYSTEM_SECRET'])"]
    provider = KeycloakProvider(issuer=settings.issuer, secret_command=command)
    who = provider.system_whoami()
    assert who.username == "service-account-catalyst-system" and who.issuer == settings.issuer
    assert provider.system_token()["access_token"]
