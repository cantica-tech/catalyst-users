"""Directory administration (id-DIR-000001/2/4) and the CLI."""

import json
import time

import pytest

from catalyst_users import cli
from catalyst_users.admin import KeycloakAdmin
from catalyst_users.credentials import CredentialStore
from catalyst_users.errors import AdminError, NotFoundError
from catalyst_users.http import Http
from catalyst_users.oidc import Tokens
from tests.conftest import ADMIN, ISSUER, OIDC, reply

ALICE = {"id": "u-alice", "username": "alice", "email": "a@x", "firstName": "Alice", "lastName": "D", "enabled": True}
GROUP = {"id": "g-dev", "path": "/cantica-tech/catalyst/developers", "realmRoles": ["developer"]}


@pytest.fixture
def admin(settings, transport):
    return KeycloakAdmin(settings, lambda: "caller-token", Http(transport))


def test_every_call_uses_the_callers_token(admin, transport):
    transport.on("GET", f"{ADMIN}/users", reply(body=[ALICE]))
    admin.list_users()
    assert transport.requests[-1].headers["Authorization"] == "Bearer caller-token"


def test_there_is_no_way_to_delete_a_user():
    assert not [name for name in dir(KeycloakAdmin) if "delete" in name.lower()]


def test_disable_puts_enabled_false_and_never_deletes(admin, transport):
    transport.on("GET", f"{ADMIN}/users", reply(body=[ALICE]))
    transport.on("PUT", f"{ADMIN}/users/u-alice", reply(204))
    admin.set_enabled("alice", False)
    assert json.loads(transport.requests[1].body) == {"enabled": False}
    assert transport.calls("DELETE") == []


def test_create_user_with_a_temporary_password(admin, transport):
    transport.on("POST", f"{ADMIN}/users", reply(201, headers={"Location": f"{ADMIN}/users/u-new"}))
    transport.on("PUT", f"{ADMIN}/users/u-new/reset-password", reply(204))
    transport.on("GET", f"{ADMIN}/users", reply(body=[{**ALICE, "id": "u-new", "username": "carol"}]))
    user = admin.create_user("carol", email="c@x", temporary_password="Temp-Password-1")
    assert user.username == "carol"
    assert json.loads(transport.requests[0].body) == {"username": "carol", "enabled": True, "email": "c@x"}
    assert json.loads(transport.requests[1].body) == {"type": "password", "value": "Temp-Password-1", "temporary": True}


def test_create_group_creates_missing_parents_only(admin, transport):
    existing = {"/a": {"id": "g-a", "path": "/a"}}

    def by_path(request):
        path = "/" + request.url.split("/group-by-path/", 1)[1]
        return reply(body=existing[path]) if path in existing else reply(404)

    def child(request):
        name = json.loads(request.body)["name"]
        existing[f"/a/{name}"] = {"id": f"g-{name}", "path": f"/a/{name}"}
        return reply(201)

    for path in ("a", "a/b"):
        transport.on("GET", f"{ADMIN}/group-by-path/{path}", by_path)
    transport.on("POST", f"{ADMIN}/groups/g-a/children", child)
    group = admin.create_group("/a/b")
    assert group.path == "/a/b"
    assert transport.calls("POST") == [("POST", f"{ADMIN}/groups/g-a/children")]


def test_groups_are_listed_as_a_tree(admin, transport):
    top = [
        {"id": "g2", "name": "zeta", "path": "/zeta", "subGroups": []},
        {"id": "g1", "name": "alpha", "path": "/alpha", "subGroupCount": 1, "subGroups": []},
    ]
    transport.on("GET", f"{ADMIN}/groups", reply(body=top))
    transport.on(
        "GET", f"{ADMIN}/groups/g1/children", reply(body=[{"id": "g3", "name": "beta", "path": "/alpha/beta"}])
    )
    assert [(g.path, g.depth) for g in admin.groups()] == [("/alpha", 0), ("/alpha/beta", 1), ("/zeta", 0)]


def test_membership_and_role_grants(admin, transport):
    transport.on("GET", f"{ADMIN}/users", reply(body=[ALICE]))
    transport.on("GET", f"{ADMIN}/group-by-path/cantica-tech/catalyst/developers", reply(body=GROUP))
    transport.on("PUT", f"{ADMIN}/users/u-alice/groups/g-dev", reply(204))
    transport.on("DELETE", f"{ADMIN}/users/u-alice/groups/g-dev", reply(204))
    transport.on("GET", f"{ADMIN}/roles/developer", reply(body={"id": "r1", "name": "developer"}))
    transport.on("POST", f"{ADMIN}/groups/g-dev/role-mappings/realm", reply(204))
    admin.add_member("/cantica-tech/catalyst/developers", "alice")
    admin.remove_member("cantica-tech/catalyst/developers", "alice")
    admin.grant_role_to_group("/cantica-tech/catalyst/developers", "developer")
    assert json.loads(transport.requests[-1].body) == [{"id": "r1", "name": "developer"}]
    assert ("DELETE", f"{ADMIN}/users/u-alice/groups/g-dev") in transport.calls()  # a membership, not a user


@pytest.mark.parametrize(
    ("status", "raised", "text"),
    [(403, AdminError, "not allowed"), (404, NotFoundError, "not found"), (409, AdminError, "already exists")],
)
def test_admin_errors_are_explained(admin, transport, status, raised, text):
    transport.on("POST", f"{ADMIN}/roles", reply(status))
    with pytest.raises(raised, match=text):
        admin.create_role("x")


def test_unknown_user_is_not_found(admin, transport):
    transport.on("GET", f"{ADMIN}/users", reply(body=[]))
    with pytest.raises(NotFoundError):
        admin.user("nobody")


# --- CLI ---------------------------------------------------------------------


@pytest.fixture
def wired(monkeypatch, transport):
    """Route the CLI's HTTP through the fake transport, logged in as alice."""
    monkeypatch.setenv("CATALYST_USERS_SERVER", "https://id.example.com")
    original = Http.__init__

    def init(self, transport_=None, timeout=10.0):
        original(self, transport, timeout)

    monkeypatch.setattr(Http, "__init__", init)
    CredentialStore().save(ISSUER, "catalyst-cli", Tokens("at-alice", "rt-alice", time.time() + 300))
    return transport


def test_whoami(wired, capsys):
    wired.on(
        "GET",
        f"{OIDC}/userinfo",
        reply(
            body={
                "sub": "s1",
                "preferred_username": "alice",
                "name": "Alice D",
                "groups": ["/g"],
                "realm_access": {"roles": ["developer"]},
            }
        ),
    )
    assert cli.main(["whoami"]) == 0
    out = capsys.readouterr().out
    assert "alice (Alice D)" in out and "/g" in out and "developer" in out
    assert "at-alice" not in out


def test_whoami_json_carries_the_signer(wired, capsys):
    wired.on("GET", f"{OIDC}/userinfo", reply(body={"sub": "s1", "preferred_username": "alice"}))
    assert cli.main(["--json", "whoami"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert (data["iss"], data["sub"], data["username"]) == (ISSUER, "s1", "alice")


def test_token_prints_the_access_token_only_when_asked(wired, capsys):
    assert cli.main(["token"]) == 0
    assert capsys.readouterr().out.strip() == "at-alice"


def test_users_disable(wired, capsys):
    wired.on("GET", f"{ADMIN}/users", reply(body=[{**ALICE, "enabled": False}]))
    wired.on("PUT", f"{ADMIN}/users/u-alice", reply(204))
    assert cli.main(["users", "disable", "alice"]) == 0
    assert "alice is disabled." in capsys.readouterr().out


def test_logged_out_is_a_clear_error(monkeypatch, capsys):
    monkeypatch.setenv("CATALYST_USERS_SERVER", "https://id.example.com")
    assert cli.main(["users", "list"]) == 1
    assert "not logged in: run `catalyst-users login`" in capsys.readouterr().err


def test_an_admin_refusal_exits_1_without_leaking_the_token(wired, capsys):
    wired.on("GET", f"{ADMIN}/roles", reply(403))
    assert cli.main(["roles", "list"]) == 1
    captured = capsys.readouterr()
    assert "not allowed" in captured.err and "at-alice" not in captured.err + captured.out


def test_usage_errors_exit_2():
    with pytest.raises(SystemExit) as exc:
        cli.main(["users"])
    assert exc.value.code == 2
