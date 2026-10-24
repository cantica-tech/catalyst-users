"""Setup (id-PROVIDER-000006): IAM/settings.json from the provider's check, creation or sign-in."""

from __future__ import annotations

import json
import stat
import sys

import pytest

from catalyst_users import cli, config, keychain
from catalyst_users.errors import ProviderUnavailableError
from catalyst_users.http import Http
from catalyst_users.provider import ProviderError
from catalyst_users.providers.keycloak import KeycloakProvider
from tests.conftest import ADMIN, DISCOVERY, OIDC, reply

URL = "https://id.example.com"
MASTER_TOKEN = f"{URL}/realms/master/protocol/openid-connect/token"
DISCOVERY_URL = f"{URL}/realms/catalyst/.well-known/openid-configuration"
PASSWORD_COMMAND = [sys.executable, "-c", "print('owner-pw')"]
DEFINITION = {"realm": "catalyst", "groups": [{"name": "catalyst-admins"}], "clients": [{"clientId": "c"}]}
SIGNED_IN = reply(body={"access_token": "at-owner", "expires_in": 300})


@pytest.fixture(autouse=True)
def ready_realm(transport):
    """A realm already ready for criteria (id-PROVIDER-000008): setup reads it and changes nothing."""
    transport.on("GET", ADMIN, reply(body={"realm": "catalyst", "adminPermissionsEnabled": True}))
    transport.on("GET", f"{ADMIN}/roles", reply(body=[{"name": "criterion-admin"}]))
    transport.on("GET", f"{ADMIN}/group-by-path/criteria", reply(body={"id": "g-c", "path": "/criteria"}))
    return transport


def _sign_in(transport) -> dict[str, str]:
    """The form of the last sign-in (readying the realm for criteria follows it)."""
    return transport.form(max(i for i, r in enumerate(transport.requests) if r.url == f"{OIDC}/token"))


def _never_asked() -> tuple[str, str]:
    raise AssertionError("the server admin is asked for only to create a realm")


def test_a_realm_that_exists_is_only_signed_in_to(transport):
    transport.on("POST", f"{OIDC}/token", SIGNED_IN)
    outcome = KeycloakProvider.setup({"url": URL + "/"}, "owner", "owner-pw", _never_asked, transport)
    assert outcome.outcome == "authenticated"
    assert outcome.provider == {
        "url": URL,
        "realm": "catalyst",
        "client": "catalyst-cli",
        "password_client": "catalyst-admin-cli",
        "catalyst_client": "catalyst",
    }
    assert _sign_in(transport)["grant_type"] == "password" and _sign_in(transport)["username"] == "owner"
    assert not [url for method, url in transport.calls("POST") if "/admin/" in url]


def test_setup_readies_a_realm_for_criteria_and_adds_the_ones_named(transport, monkeypatch):
    from catalyst_users.admin import KeycloakAdmin

    transport.on("POST", f"{OIDC}/token", SIGNED_IN)
    realm = {"realm": "catalyst", "displayName": "kept"}
    transport.on("GET", ADMIN, reply(body=realm))
    transport.on("PUT", ADMIN, reply(204))
    transport.on("GET", f"{ADMIN}/roles", reply(body=[{"name": "tech-lead"}]))
    transport.on("POST", f"{ADMIN}/roles", reply(201))
    transport.on("GET", f"{ADMIN}/group-by-path/criteria", [reply(404), reply(body={"id": "g-c", "path": "/criteria"})])
    transport.on("POST", f"{ADMIN}/groups", reply(201))
    added = []
    monkeypatch.setattr(KeycloakAdmin, "add_criterion", lambda self, name: added.append(name) or [f"criterion {name}"])
    monkeypatch.setattr(KeycloakAdmin, "appoint", lambda self, name, user: added.append((name, user)))
    outcome = KeycloakProvider.setup(
        {"url": URL}, "owner", "owner-pw", _never_asked, transport, criteria=("catalyst", "catalyst-ui")
    )
    put = json.loads(next(r.body for r in transport.requests if r.method == "PUT" and r.url == ADMIN))
    assert put == {**realm, "adminPermissionsEnabled": True}
    role = json.loads(next(r.body for r in transport.requests if r.method == "POST" and r.url == f"{ADMIN}/roles"))
    assert role["name"] == "criterion-admin"
    assert added == ["catalyst", ("catalyst", "owner"), "catalyst-ui", ("catalyst-ui", "owner")]
    assert "criteria: fine-grained admin permissions, role criterion-admin, group /criteria" in outcome.note
    assert "owner administers catalyst-ui" in outcome.note


def test_a_refused_sign_in_fails_setup(transport):
    transport.on("POST", f"{OIDC}/token", reply(401, {"error": "invalid_grant", "error_description": "bad"}))
    with pytest.raises(ProviderError, match="refused owner's sign-in"):
        KeycloakProvider.setup({"url": URL}, "owner", "wrong", _never_asked, transport)


def test_an_unreachable_provider_keeps_the_json_unchecked():
    def down(request, timeout):
        raise ProviderUnavailableError("identity provider unreachable: connection refused")

    outcome = KeycloakProvider.setup({"url": URL, "realm": "r1"}, "owner", "pw", _never_asked, down)
    assert outcome.outcome == "unreachable" and outcome.provider["realm"] == "r1"
    assert "not up" in outcome.note


def test_a_missing_realm_is_created_with_its_admin_then_signed_in(transport, tmp_path):
    path = tmp_path / "realm.json"
    path.write_text(json.dumps(DEFINITION))
    transport.on("GET", DISCOVERY_URL, [reply(404), reply(body=DISCOVERY)])
    transport.on("POST", MASTER_TOKEN, reply(body={"access_token": "at-server"}))
    transport.on("POST", f"{URL}/admin/realms", reply(201))
    transport.on("POST", f"{ADMIN}/users", reply(201, headers={"Location": f"{ADMIN}/users/u-1"}))
    transport.on("GET", f"{ADMIN}/users", reply(body=[{"id": "u-1", "username": "owner"}]))
    transport.on("PUT", f"{ADMIN}/users/u-1/reset-password", reply(204))
    transport.on("GET", f"{ADMIN}/group-by-path/catalyst-admins", reply(body={"id": "g-1", "path": "/catalyst-admins"}))
    transport.on("PUT", f"{ADMIN}/users/u-1/groups/g-1", reply(204))
    transport.on("POST", f"{OIDC}/token", SIGNED_IN)
    asked = []

    def server_admin() -> tuple[str, str]:
        asked.append(True)
        return "admin", "server-pw"

    transport.on("PUT", f"{ADMIN}/users/u-1", reply(204))
    profile = {"email": "o@example.com", "first_name": "O", "last_name": "Wner"}
    outcome = KeycloakProvider.setup(
        {"url": URL, "definition": str(path)}, "owner", "owner-pw", server_admin, transport, ask_profile=lambda: profile
    )
    assert outcome.outcome == "created" and asked == [True]
    assert "definition" not in outcome.provider
    created = json.loads(next(r.body for r in transport.requests if r.url == f"{URL}/admin/realms"))
    assert created == DEFINITION
    reset = json.loads(next(r.body for r in transport.requests if r.url.endswith("/reset-password")))
    assert reset == {"type": "password", "value": "owner-pw", "temporary": False}
    assert ("PUT", f"{ADMIN}/users/u-1/groups/g-1") in transport.calls()
    user = json.loads(next(r.body for r in transport.requests if r.method == "POST" and r.url == f"{ADMIN}/users"))
    assert (user["email"], user["firstName"], user["lastName"]) == ("o@example.com", "O", "Wner")
    assert _sign_in(transport)["client_id"] == "catalyst-admin-cli"


def test_a_missing_realm_needs_a_definition_without_people_or_secrets(transport):
    transport.on("GET", DISCOVERY_URL, reply(404))
    with pytest.raises(ProviderError, match='no "definition"'):
        KeycloakProvider.setup({"url": URL}, "owner", "pw", _never_asked, transport)
    with pytest.raises(ProviderError, match="person or a secret: `users`"):
        KeycloakProvider.setup(
            {"url": URL, "definition": {"realm": "catalyst", "users": [{"username": "x"}]}}, "o", "p", _never_asked
        )
    with pytest.raises(ProviderError, match="is for 'other'"):
        KeycloakProvider.setup(
            {"url": URL, "definition": {"realm": "other"}, "realm": "catalyst"}, "o", "p", _never_asked, transport
        )


def test_a_refused_server_admin_creates_nothing(transport):
    transport.on("GET", DISCOVERY_URL, reply(404))
    transport.on("POST", MASTER_TOKEN, reply(401, {"error": "invalid_grant"}))
    with pytest.raises(ProviderError, match="server admin admin was refused"):
        KeycloakProvider.setup({"url": URL, "definition": DEFINITION}, "owner", "pw", lambda: ("admin", "x"), transport)
    assert ("POST", f"{URL}/admin/realms") not in transport.calls()


# --- the CLI -------------------------------------------------------------------------------


@pytest.fixture
def wired(monkeypatch, transport):
    original = Http.__init__

    def init(self, transport_=None, timeout=10.0):
        original(self, transport, timeout)

    monkeypatch.setattr(Http, "__init__", init)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    transport.on("POST", f"{OIDC}/token", SIGNED_IN)
    return transport


def _setup_args(*extra: str) -> list[str]:
    return [
        "setup",
        "--type",
        "keycloak",
        "--provider",
        json.dumps({"url": URL}),
        "--username",
        "owner",
        "--password-command",
        " ".join(PASSWORD_COMMAND[:1]) + " -c \"print('owner-pw')\"",
        *extra,
    ]


def test_setup_writes_owner_only_settings_with_no_secret(wired, capsys):
    assert cli.main(_setup_args()) == 0
    path = config.settings_file()
    stored = json.loads(path.read_text())
    assert stored["type"] == "keycloak" and stored["username"] == "owner"
    assert stored["provider"]["url"] == URL and "definition" not in stored["provider"]
    assert stored["password_command"].endswith("-c \"print('owner-pw')\"")
    assert "owner-pw" not in path.read_text().replace("print('owner-pw')", "")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert "signed owner in" in capsys.readouterr().out


def test_setup_refuses_to_replace_settings_without_force(wired, capsys):
    assert cli.main(_setup_args()) == 0
    assert cli.main(_setup_args()) == 1
    assert "pass --force" in capsys.readouterr().err
    assert cli.main(_setup_args("--force")) == 0


def test_the_settings_choose_the_provider_and_its_system_account(wired, transport, capsys):
    assert cli.main(_setup_args()) == 0
    capsys.readouterr()
    transport.on("GET", f"{OIDC}/userinfo", reply(body={"sub": "u-1", "preferred_username": "owner"}))
    assert cli.main(["--json", "whoami", "--system"]) == 0
    assert json.loads(capsys.readouterr().out)["username"] == "owner"
    sign_in = transport.form(max(i for i, r in enumerate(transport.requests) if r.method == "POST"))
    assert sign_in["username"] == "owner" and sign_in["password"] == "owner-pw"


def test_without_settings_and_no_terminal_a_command_asks_for_setup(wired, capsys):
    assert cli.main(["whoami", "--system"]) == 1
    assert "run `catalyst-users setup`" in capsys.readouterr().err


def test_setup_without_a_terminal_needs_every_answer(wired, capsys):
    assert cli.main(["setup", "--type", "keycloak"]) == 1
    assert "no terminal to ask" in capsys.readouterr().err


def test_a_typed_password_goes_to_the_keychain_and_its_command_to_the_settings(wired, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    answers = iter([""])  # the password command: none, type it
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "typed-pw")
    kept = {}

    def store(account: str, secret: str) -> str:
        kept[account] = secret
        return f"read-it {account}"

    monkeypatch.setattr(keychain, "store", store)
    args = ["setup", "--type", "keycloak", "--provider", json.dumps({"url": URL}), "--username", "owner"]
    assert cli.main(args) == 0
    assert kept == {f"owner@{URL}/catalyst": "typed-pw"}
    stored = json.loads(config.settings_file().read_text())
    assert stored["password_command"] == f"read-it owner@{URL}/catalyst"
    assert "typed-pw" not in config.settings_file().read_text() + capsys.readouterr().out
