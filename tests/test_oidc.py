"""Device login (id-AUTH-000001), refresh and revocation (id-AUTH-000003), introspection checks (id-AUTH-000004)."""

import pytest

from catalyst_users.errors import LoginDeniedError, LoginExpiredError, OIDCError, ProviderUnavailableError
from catalyst_users.oidc import Tokens
from tests.conftest import ISSUER, OIDC, reply

DEVICE = {
    "device_code": "dev-code",
    "user_code": "ABCD-EFGH",
    "verification_uri": f"{ISSUER}/device",
    "expires_in": 600,
    "interval": 5,
}
GRANT = {
    "access_token": "at-1",
    "refresh_token": "rt-1",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "token_type": "Bearer",
}


def pending(error):
    return reply(400, {"error": error})


def test_device_login_polls_until_approved(oidc, transport, clock):
    transport.on("POST", f"{OIDC}/auth/device", reply(body=DEVICE))
    transport.on("POST", f"{OIDC}/token", [pending("authorization_pending"), pending("slow_down"), reply(body=GRANT)])
    code = oidc.start_device_login()
    assert (code.user_code, code.interval) == ("ABCD-EFGH", 5.0)
    assert transport.form() == {"client_id": "catalyst-cli", "scope": "openid"}
    tokens = oidc.poll_device_login(code)
    assert tokens.access_token == "at-1" and tokens.refresh_token == "rt-1"
    assert clock.slept == [5.0, 5.0, 10.0]  # slow_down adds five seconds
    assert transport.form()["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"


@pytest.mark.parametrize(
    ("error", "raised"), [("access_denied", LoginDeniedError), ("expired_token", LoginExpiredError)]
)
def test_device_login_stops_on_denial_or_expiry(oidc, transport, error, raised):
    transport.on("POST", f"{OIDC}/auth/device", reply(body=DEVICE))
    transport.on("POST", f"{OIDC}/token", pending(error))
    with pytest.raises(raised):
        oidc.poll_device_login(oidc.start_device_login())


def test_device_login_gives_up_at_the_code_expiry(oidc, transport):
    transport.on("POST", f"{OIDC}/auth/device", reply(body={**DEVICE, "expires_in": 12}))
    transport.on("POST", f"{OIDC}/token", lambda r: pending("authorization_pending"))
    with pytest.raises(LoginExpiredError):
        oidc.poll_device_login(oidc.start_device_login())


def test_refresh_keeps_the_refresh_token_when_none_is_returned(oidc, transport, clock):
    transport.on("POST", f"{OIDC}/token", reply(body={"access_token": "at-2", "expires_in": 300}))
    old = Tokens("at-1", "rt-1", clock.now)
    new = oidc.refresh(old)
    assert (new.access_token, new.refresh_token, new.expires_at) == ("at-2", "rt-1", clock.now + 300)
    assert transport.form() == {"grant_type": "refresh_token", "refresh_token": "rt-1", "client_id": "catalyst-cli"}


def test_refresh_failure_is_an_oidc_error(oidc, transport, clock):
    transport.on(
        "POST", f"{OIDC}/token", reply(400, {"error": "invalid_grant", "error_description": "Session not active"})
    )
    with pytest.raises(OIDCError, match="invalid_grant"):
        oidc.refresh(Tokens("at-1", "rt-1", clock.now))


def test_revoke_sends_the_refresh_token(oidc, transport, clock):
    transport.on("POST", f"{OIDC}/revoke", reply(200))
    oidc.revoke(Tokens("at-1", "rt-1", clock.now))
    assert transport.form() == {"token": "rt-1", "token_type_hint": "refresh_token", "client_id": "catalyst-cli"}


def test_introspection_authenticates_as_the_api_client(oidc, transport):
    transport.on("POST", f"{OIDC}/token/introspect", reply(body={"active": False}))
    assert oidc.introspect("some-token") == {"active": False}
    req = transport.requests[-1]
    assert req.headers["Authorization"].startswith("Basic ")
    assert transport.form() == {"token": "some-token", "token_type_hint": "access_token"}


def test_introspection_failure_is_provider_unavailable(oidc, transport):
    transport.on("POST", f"{OIDC}/token/introspect", reply(401, {"error": "invalid_client"}))
    with pytest.raises(ProviderUnavailableError):
        oidc.introspect("t")


def claims(clock, **over):
    return {
        "active": True,
        "iss": ISSUER,
        "aud": ["catalyst-api", "account"],
        "exp": clock.now + 60,
        "sub": "u1",
        **over,
    }


def test_accepts_an_active_token_for_this_issuer_and_audience(oidc, clock):
    assert oidc.accepts(claims(clock))
    assert oidc.accepts(claims(clock, aud="catalyst-api"))


@pytest.mark.parametrize(
    "over",
    [
        {"active": False},
        {"active": "true"},
        {"iss": "https://other.example.com/realms/catalyst"},
        {"aud": "account"},
        {"aud": None},
        {"exp": 0},
        {"exp": None},
    ],
)
def test_rejects_anything_else(oidc, clock, over):
    assert not oidc.accepts(claims(clock, **over))


def test_tokens_repr_hides_the_tokens():
    assert "secret-at" not in repr(Tokens("secret-at", "secret-rt", 1.0))
