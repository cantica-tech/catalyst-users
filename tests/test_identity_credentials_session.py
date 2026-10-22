"""Identity (id-DIR-000003, id-SIGN-000001), credentials (id-AUTH-000002), session (id-AUTH-000003)."""

import stat
from datetime import UTC, datetime

import pytest

from catalyst_users.credentials import CredentialStore
from catalyst_users.errors import NotLoggedInError
from catalyst_users.identity import Identity
from catalyst_users.oidc import Tokens
from catalyst_users.session import Session
from tests.conftest import ISSUER, OIDC, reply

ALICE = {
    "sub": "3c15-alice",
    "preferred_username": "alice",
    "name": "Alice Developer",
    "email": "alice@example.invalid",
    "groups": ["/cantica-tech/catalyst/developers"],
    "realm_access": {"roles": ["developer", "stakeholder"]},
}


def test_identity_from_userinfo_claims():
    who = Identity.from_claims(ALICE, issuer=ISSUER)
    assert (who.issuer, who.subject, who.username, who.name) == (ISSUER, "3c15-alice", "alice", "Alice Developer")
    assert who.roles == ("developer", "stakeholder")


def test_group_membership_is_hierarchical():
    who = Identity.from_claims(ALICE, issuer=ISSUER)
    assert (
        who.in_group("/cantica-tech")
        and who.in_group("cantica-tech/catalyst")
        and who.in_group("/cantica-tech/catalyst/developers/")
    )
    assert not who.in_group("/cantica-tech/cat")  # a prefix of a name is not a parent
    assert not who.in_group("/catalyst-admins")


def test_roles_are_the_effective_realm_roles():
    who = Identity.from_claims(ALICE, issuer=ISSUER)
    assert who.has_role("stakeholder")  # inherited from /cantica-tech
    assert not who.has_role("release-manager")


def test_signer_is_issuer_and_subject_with_a_snapshot():
    who = Identity.from_claims(ALICE, issuer=ISSUER)
    assert who.signer(datetime(2026, 10, 22, 21, 0, tzinfo=UTC)) == {
        "iss": ISSUER,
        "sub": "3c15-alice",
        "username": "alice",
        "name": "Alice Developer",
        "at": "2026-10-22T21:00:00Z",
    }


def test_name_falls_back_to_given_and_family_then_username():
    assert (
        Identity.from_claims({"sub": "s", "preferred_username": "u", "given_name": "G", "family_name": "F"}).name
        == "G F"
    )
    assert Identity.from_claims({"sub": "s", "preferred_username": "u"}).name == "u"


def test_credentials_are_owner_only_and_round_trip(isolated_home):
    store = CredentialStore()
    store.save(ISSUER, "catalyst-cli", Tokens("at", "rt", 10.0))
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    assert store.load(ISSUER, "catalyst-cli") == Tokens("at", "rt", 10.0)
    assert store.load("https://other.example.com/realms/x", "catalyst-cli") is None
    assert list(store.path.parent.iterdir()) == [store.path]  # no temp file left
    assert store.delete() and not store.delete()


def test_a_corrupt_credentials_file_reads_as_logged_out(isolated_home):
    store = CredentialStore()
    store.path.parent.mkdir(parents=True)
    store.path.write_text("{not json")
    assert store.load(ISSUER, "catalyst-cli") is None


@pytest.fixture
def session(oidc):
    return Session(oidc, CredentialStore())


def test_access_token_is_refreshed_close_to_expiry(session, transport, clock):
    session.store.save(ISSUER, "catalyst-cli", Tokens("at-old", "rt-1", clock.now + 20))
    transport.on(
        "POST", f"{OIDC}/token", reply(body={"access_token": "at-new", "refresh_token": "rt-2", "expires_in": 300})
    )
    assert session.access_token() == "at-new"
    assert session.store.load(ISSUER, "catalyst-cli").refresh_token == "rt-2"


def test_a_fresh_access_token_is_used_as_is(session, transport, clock):
    session.store.save(ISSUER, "catalyst-cli", Tokens("at-ok", "rt-1", clock.now + 120))
    assert session.access_token() == "at-ok"
    assert transport.calls("POST") == []


def test_a_failed_refresh_means_logged_out(session, transport, clock):
    session.store.save(ISSUER, "catalyst-cli", Tokens("at-old", "rt-1", clock.now))
    transport.on("POST", f"{OIDC}/token", reply(400, {"error": "invalid_grant"}))
    with pytest.raises(NotLoggedInError):
        session.access_token()


def test_no_credentials_means_logged_out(session):
    with pytest.raises(NotLoggedInError):
        session.identity()


def test_login_stores_tokens_and_returns_the_identity(session, transport):
    transport.on(
        "POST",
        f"{OIDC}/auth/device",
        reply(body={"device_code": "d", "user_code": "U", "verification_uri": "v", "interval": 1}),
    )
    transport.on("POST", f"{OIDC}/token", reply(body={"access_token": "at", "refresh_token": "rt", "expires_in": 300}))
    transport.on("GET", f"{OIDC}/userinfo", reply(body=ALICE))
    shown = []
    who = session.login(shown.append)
    assert who.username == "alice" and shown[0].user_code == "U"
    assert transport.requests[-1].headers["Authorization"] == "Bearer at"


def test_logout_revokes_and_deletes(session, transport, clock):
    session.store.save(ISSUER, "catalyst-cli", Tokens("at", "rt", clock.now + 300))
    transport.on("POST", f"{OIDC}/revoke", reply(200))
    assert session.logout() is None
    assert not session.store.path.exists()


def test_logout_deletes_even_when_revocation_fails(session, transport, clock):
    session.store.save(ISSUER, "catalyst-cli", Tokens("at", "rt", clock.now + 300))
    transport.on("POST", f"{OIDC}/revoke", reply(503))
    warning = session.logout()
    assert warning and "deleted anyway" in warning and "rt" not in warning.split()
    assert not session.store.path.exists()
