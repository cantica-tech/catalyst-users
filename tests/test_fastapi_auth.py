"""FastAPI integration: 200/401/403/503 (id-API-000001), dependencies (id-API-000002), cache bounds (id-AUTH-000004)."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from catalyst_users.config import Settings
from catalyst_users.fastapi_auth import KeycloakAuth
from catalyst_users.identity import Identity
from tests.conftest import ISSUER, OIDC, reply


def active(clock, **over):
    return {
        "active": True,
        "iss": ISSUER,
        "aud": "catalyst-api",
        "exp": clock.now + 300,
        "sub": "s-alice",
        "preferred_username": "alice",
        "groups": ["/cantica-tech/catalyst/developers"],
        "realm_access": {"roles": ["developer", "stakeholder"]},
        **over,
    }


@pytest.fixture
def auth(oidc, clock):
    return KeycloakAuth(oidc=oidc, clock=clock)


@pytest.fixture
def client(auth):
    app = FastAPI()

    @app.get("/me")
    def me(who: Identity = Depends(auth)):
        return who.signer()

    @app.get("/dev", dependencies=[Depends(auth.require_roles("developer", "stakeholder"))])
    def dev():
        return {"ok": True}

    @app.get("/release", dependencies=[Depends(auth.require_roles("release-manager"))])
    def release():
        return {"ok": True}

    @app.get("/catalyst", dependencies=[Depends(auth.require_groups("/cantica-tech/catalyst"))])
    def catalyst():
        return {"ok": True}

    @app.get("/admins", dependencies=[Depends(auth.require_groups("/catalyst-admins"))])
    def admins():
        return {"ok": True}

    return TestClient(app)


def bearer(token="tok-1"):
    return {"Authorization": f"Bearer {token}"}


def test_a_valid_token_reaches_the_endpoint_as_an_identity(client, transport, clock):
    transport.on("POST", f"{OIDC}/token/introspect", reply(body=active(clock)))
    resp = client.get("/me", headers=bearer())
    assert resp.status_code == 200
    assert (resp.json()["iss"], resp.json()["sub"], resp.json()["username"]) == (ISSUER, "s-alice", "alice")


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Basic dXNlcjpwYXNz"}, {"Authorization": "Bearer "}])
def test_a_missing_or_malformed_token_is_401(client, transport, headers):
    resp = client.get("/me", headers=headers)
    assert resp.status_code == 401 and resp.headers["www-authenticate"] == "Bearer"
    assert transport.calls("POST") == []  # nothing to introspect


@pytest.mark.parametrize("over", [{"active": False}, {"aud": "account"}, {"iss": "https://other/realms/catalyst"}])
def test_a_rejected_token_is_401_and_says_no_more(client, transport, clock, over):
    transport.on("POST", f"{OIDC}/token/introspect", reply(body=active(clock, **over)))
    resp = client.get("/me", headers=bearer())
    assert resp.status_code == 401 and resp.json() == {"detail": "not authenticated"}


def test_roles_and_groups(client, transport, clock):
    transport.on("POST", f"{OIDC}/token/introspect", reply(body=active(clock)))
    assert client.get("/dev", headers=bearer()).status_code == 200
    assert client.get("/catalyst", headers=bearer()).status_code == 200  # member of a subgroup
    assert client.get("/release", headers=bearer()).status_code == 403
    assert client.get("/admins", headers=bearer()).json() == {"detail": "forbidden"}


def test_an_unreachable_provider_is_503(client, transport):
    transport.on("POST", f"{OIDC}/token/introspect", reply(500))
    assert client.get("/me", headers=bearer()).status_code == 503


def test_the_cache_lasts_at_most_30_seconds(client, auth, transport, clock):
    transport.on("POST", f"{OIDC}/token/introspect", reply(body=active(clock)))
    client.get("/me", headers=bearer())
    clock.now += 29
    client.get("/me", headers=bearer())
    assert len(transport.calls("POST")) == 1
    clock.now += 2
    client.get("/me", headers=bearer())
    assert len(transport.calls("POST")) == 2


def test_the_cache_never_outlives_the_token(client, transport, clock):
    transport.on(
        "POST",
        f"{OIDC}/token/introspect",
        [reply(body=active(clock, exp=clock.now + 5)), reply(body={"active": False})],
    )
    assert client.get("/me", headers=bearer()).status_code == 200
    clock.now += 6
    assert client.get("/me", headers=bearer()).status_code == 401


def test_the_cache_holds_hashes_not_tokens(auth, transport, clock):
    transport.on("POST", f"{OIDC}/token/introspect", reply(body=active(clock)))
    auth.identify("secret-token-value")
    assert all("secret-token-value" not in key for key in auth._cache)


def test_the_cache_is_bounded(oidc, transport, clock):
    small = KeycloakAuth(oidc=oidc, clock=clock, cache_size=3)
    transport.on("POST", f"{OIDC}/token/introspect", lambda r: reply(body=active(clock)))
    for i in range(10):
        small.identify(f"t{i}")
    assert len(small._cache) == 3


def test_a_longer_ttl_is_capped_at_30_seconds(oidc, clock):
    assert KeycloakAuth(oidc=oidc, clock=clock, cache_ttl=3600).cache_ttl == 30.0


def test_the_api_secret_is_required():
    with pytest.raises(ValueError, match="secret"):
        KeycloakAuth(Settings(api_client_secret=None))
