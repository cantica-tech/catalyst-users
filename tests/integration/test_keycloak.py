"""End to end against the local Keycloak (env-LOCAL-000001)."""

from __future__ import annotations

import json
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from catalyst_users.admin import KeycloakAdmin
from catalyst_users.credentials import CredentialStore
from catalyst_users.errors import AdminError, OIDCError
from catalyst_users.fastapi_auth import KeycloakAuth
from catalyst_users.identity import Identity
from catalyst_users.oidc import OIDCClient
from catalyst_users.provider import ProviderError
from catalyst_users.providers.keycloak import KeycloakProvider
from catalyst_users.session import Session
from tests.integration.conftest import SERVER, approve_device, bootstrap_token, master_admin, password_token

pytestmark = pytest.mark.usefixtures("dev_people")


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
    assert stored is not None
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
    # provisioning only adds (id-PROVIDER-000003): a realm holding catalyst's own roles gives a developer more, but
    # never what only a tech lead or a release manager holds
    assert {"create", "status"} <= set(alice.commands) and not {"freeze", "share"} & set(alice.commands)
    assert alice.reconciliation == "propose"


def test_setup_creates_a_realm_and_its_admin_then_only_signs_in(monkeypatch):
    """Setup end to end (id-PROVIDER-000006): a throwaway realm from the dev realm's definition, its admin created
    and signed in, a second setup only signing in, a wrong password refused; then the admin as the system account."""
    definition = json.loads((Path(__file__).resolve().parents[2] / "keycloak" / "realm-catalyst.json").read_text())
    realm = f"it-setup-{secrets.token_hex(4)}"
    settings = {"url": SERVER, "realm": realm, "definition": {**definition, "realm": realm}}
    password = f"it-{secrets.token_hex(8)}"
    try:
        profile = {"email": "it-owner@example.com", "first_name": "It", "last_name": "Owner"}
        created = KeycloakProvider.setup(settings, "it-owner", password, master_admin, ask_profile=lambda: profile)
        assert created.outcome == "created" and created.provider["realm"] == realm

        def never() -> tuple[str, str]:
            raise AssertionError("the realm exists: no server admin needed")

        again = KeycloakProvider.setup(settings, "it-owner", password, never)
        assert again.outcome == "authenticated"
        with pytest.raises(ProviderError, match="refused it-owner's sign-in"):
            KeycloakProvider.setup(settings, "it-owner", "wrong", never)

        monkeypatch.setenv("IT_OWNER_PASSWORD", password)
        command = [sys.executable, "-c", "import os; print(os.environ['IT_OWNER_PASSWORD'])"]
        system = KeycloakProvider.from_pointer(
            {**created.provider, "username": "it-owner", "password_command": command}
        )
        who = system.system_whoami()
        assert who.username == "it-owner" and who.issuer == f"{SERVER}/realms/{realm}"
        assert "/catalyst-admins" in who.groups and "catalyst-admin" in who.roles
        assert system.system_token()["access_token"]
    finally:
        url = f"{SERVER}/admin/realms/{realm}"
        headers = {"Authorization": f"Bearer {bootstrap_token()}"}
        deleting = urllib.request.Request(url, method="DELETE", headers=headers)  # noqa: S310 - loopback test server
        urllib.request.urlopen(deleting, timeout=10).close()  # noqa: S310
