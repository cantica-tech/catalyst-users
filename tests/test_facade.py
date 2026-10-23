"""The facade: providers registered by name, the pointer that chooses one, and the local system account
(id-PROVIDER-000005, id-AUTH-000006)."""

from __future__ import annotations

import importlib.metadata
import json
import sys
from dataclasses import dataclass, field
from typing import Any

import pytest

from catalyst_users import cli, config, provider as facade
from catalyst_users.http import Http
from catalyst_users.provider import (
    ProviderError,
    Whoami,
    from_pointer,
    pointer_problems,
    provider_class,
    registered,
)
from catalyst_users.providers.keycloak import KeycloakProvider
from tests.conftest import ISSUER, OIDC, reply

SECRET_COMMAND = [sys.executable, "-c", "print('s3cret'); print('ignored')"]


@dataclass
class AcmeProvider:
    """A provider an installed package would register."""

    tenant: str
    kind: str = field(default="acme", init=False)
    issuer: str = "acme:"

    @classmethod
    def from_pointer(cls, doc: dict[str, Any], store: Any = None, transport: Any = None) -> AcmeProvider:
        return cls(tenant=doc["tenant"])

    @staticmethod
    def problems(doc: dict[str, Any]) -> list[str]:
        return [] if doc.get("tenant") else ['an "acme" pointer needs a "tenant"']

    def whoami(self, username: str | None = None) -> Whoami:
        return Whoami(issuer=self.issuer, subject="s-1", username=f"robot@{self.tenant}", name="Robot")

    def system_whoami(self) -> Whoami:
        return Whoami(issuer=self.issuer, subject="sys", username=f"system@{self.tenant}", name="System")


@pytest.fixture
def entry_points(monkeypatch):
    """Installed packages registering providers through the entry-point group."""
    eps = [
        importlib.metadata.EntryPoint("acme", f"{__name__}:AcmeProvider", facade.ENTRY_POINT_GROUP),
        importlib.metadata.EntryPoint("keycloak", f"{__name__}:AcmeProvider", facade.ENTRY_POINT_GROUP),
        importlib.metadata.EntryPoint("broken", "no_such_module:Provider", facade.ENTRY_POINT_GROUP),
    ]
    monkeypatch.setattr(
        facade.importlib.metadata, "entry_points", lambda group: [ep for ep in eps if ep.group == group]
    )


# --- the registry -----------------------------------------------------------------------


def test_the_built_in_providers_are_registered():
    found = registered()
    assert {"keycloak", "static"} <= set(found)
    assert found["keycloak"].source == "built-in"
    assert provider_class("keycloak") is KeycloakProvider


def test_an_installed_package_registers_a_provider_but_never_replaces_a_built_in(entry_points):
    found = registered()
    assert found["acme"].target.endswith(":AcmeProvider")
    assert found["keycloak"].source == "built-in"
    assert provider_class("keycloak") is KeycloakProvider
    provider = from_pointer({"provider": "acme", "tenant": "t1"})
    assert isinstance(provider, AcmeProvider) and provider.whoami().username == "robot@t1"
    assert pointer_problems({"provider": "acme"}) == ['an "acme" pointer needs a "tenant"']


def test_an_unknown_or_broken_provider_is_explained(entry_points):
    with pytest.raises(ProviderError, match=r"unknown provider 'ldap' \(keycloak, static, acme, broken\)"):
        from_pointer({"provider": "ldap"})
    with pytest.raises(ProviderError, match=r"'broken' .* cannot be loaded"):
        from_pointer({"provider": "broken"})
    assert pointer_problems({"provider": "ldap"})[0].startswith("unknown provider 'ldap'")


def test_the_built_ins_stay_importable_from_the_facade():
    assert facade.KeycloakProvider is KeycloakProvider
    assert facade.StaticProvider.__name__ == "StaticProvider"


# --- the pointer ------------------------------------------------------------------------


def test_with_no_configuration_setup_is_needed():
    with pytest.raises(config.NoSettingsError, match="run `catalyst-users setup`"):
        config.pointer()


def test_explicit_keycloak_settings_need_no_configuration(monkeypatch):
    monkeypatch.setenv("CATALYST_USERS_SERVER", "http://localhost:8080")
    assert config.pointer() == {
        "provider": "keycloak",
        "issuer": "http://localhost:8080/realms/catalyst",
        "client": "catalyst-cli",
        "catalyst_client": "catalyst",
        "timeout": 10.0,
    }


def test_config_toml_names_the_provider_and_its_settings(isolated_home):
    isolated_home.mkdir(parents=True)
    (isolated_home / "config.toml").write_text('provider = "acme"\n\n[acme]\ntenant = "t1"\n')
    assert config.pointer() == {"provider": "acme", "tenant": "t1"}
    (isolated_home / "config.toml").write_text(
        'provider = "keycloak"\n\n[keycloak]\nissuer = "https://id.example.com/realms/x"\n'
        'system_client = "catalyst-system"\nsecret_command = "security find-generic-password -w"\n'
    )
    doc = config.pointer()
    assert doc["issuer"] == "https://id.example.com/realms/x" and doc["client"] == "catalyst-cli"
    assert doc["secret_command"] == "security find-generic-password -w"


def test_explicit_keycloak_settings_win_over_the_table(isolated_home, monkeypatch):
    isolated_home.mkdir(parents=True)
    (isolated_home / "config.toml").write_text('[keycloak]\nissuer = "https://id.example.com/realms/x"\n')
    assert config.pointer({"server_url": "https://other.example.com"})["issuer"] == (
        "https://other.example.com/realms/catalyst"
    )
    monkeypatch.setenv("CATALYST_USERS_REALM", "r2")
    assert config.pointer()["issuer"] == "http://localhost:8080/realms/r2"


def test_a_pointer_file_wins_and_must_be_a_json_object(tmp_path, monkeypatch):
    path = tmp_path / "pointer.json"
    path.write_text(json.dumps({"provider": "acme", "tenant": "t2"}))
    assert config.pointer(pointer_file=str(path)) == {"provider": "acme", "tenant": "t2"}
    monkeypatch.setenv("CATALYST_USERS_POINTER", str(path))
    assert config.pointer()["tenant"] == "t2"
    path.write_text("[]")
    with pytest.raises(config.CatalystUsersError, match="not a JSON object"):
        config.pointer(pointer_file=str(path))


# --- the local system account: setup's admin -------------------------------------------


def _system(transport, password_command: Any = SECRET_COMMAND, username: str | None = "owner") -> KeycloakProvider:
    transport.on("POST", f"{OIDC}/token", reply(body={"access_token": "at-admin", "expires_in": 300}))
    transport.on("GET", f"{OIDC}/userinfo", reply(body={"sub": "u-1", "preferred_username": "owner", "groups": ["/a"]}))
    return KeycloakProvider(issuer=ISSUER, transport=transport, username=username, password_command=password_command)


def test_the_system_account_signs_in_with_the_password_grant(transport):
    token = _system(transport).system_token()
    assert token["access_token"] == "at-admin" and token["token_type"] == "Bearer"
    assert transport.form() == {
        "grant_type": "password",
        "client_id": "catalyst-admin-cli",
        "username": "owner",
        "password": "s3cret",
        "scope": "openid",
    }


def test_the_system_account_is_read_from_userinfo(transport):
    who = _system(transport).system_whoami()
    assert (who.username, who.subject, who.issuer, who.groups) == ("owner", "u-1", ISSUER, ("/a",))


def test_a_missing_or_failing_password_command_is_explained_without_a_secret(transport):
    with pytest.raises(ProviderError, match="no password_command"):
        _system(transport, password_command=None).system_token()
    with pytest.raises(ProviderError, match="no username"):
        _system(transport, username=None).system_token()
    with pytest.raises(ProviderError, match="gave no secret: exit 3"):
        _system(transport, [sys.executable, "-c", "import sys; sys.exit(3)"]).system_token()
    with pytest.raises(ProviderError, match="printed nothing"):
        _system(transport, [sys.executable, "-c", "pass"]).system_token()
    with pytest.raises(ProviderError, match="failed"):
        _system(transport, "/no/such/command").system_token()
    assert not transport.calls("POST")


def test_a_refused_sign_in_names_the_account_never_the_password(transport):
    provider = _system(transport)
    transport.on("POST", f"{OIDC}/token", reply(401, {"error": "invalid_grant", "error_description": "bad"}))
    with pytest.raises(ProviderError, match="refused owner's sign-in") as refused:
        provider.system_token()
    assert "s3cret" not in str(refused.value)
    transport.on("POST", f"{OIDC}/token", reply(401, {"error": "unauthorized_client"}))
    with pytest.raises(ProviderError, match="no client catalyst-admin-cli allowing a password sign-in"):
        provider.system_token()


def test_the_static_provider_has_no_system_account(monkeypatch):
    monkeypatch.setenv(facade.STATIC_FLAG, "1")
    with pytest.raises(ProviderError, match="static provider does not support a system account"):
        from_pointer({"provider": "static"}).system_token()


# --- the CLI ------------------------------------------------------------------------------


@pytest.fixture
def cli_transport(monkeypatch, transport, tmp_path):
    original = Http.__init__

    def init(self, transport_=None, timeout=10.0):
        original(self, transport, timeout)

    monkeypatch.setattr(Http, "__init__", init)
    pointer = tmp_path / "pointer.json"
    pointer.write_text(
        json.dumps({"provider": "keycloak", "issuer": ISSUER, "username": "owner", "password_command": SECRET_COMMAND})
    )
    return pointer


def test_providers_lists_the_registry(capsys, entry_points):
    assert cli.main(["--json", "providers"]) == 0
    names = [p["name"] for p in json.loads(capsys.readouterr().out)]
    assert names == ["keycloak", "static", "acme", "broken"]


def test_token_and_whoami_for_the_system_account(cli_transport, transport, capsys):
    _system(transport)
    assert cli.main(["--pointer", str(cli_transport), "token", "--system"]) == 0
    assert capsys.readouterr().out.strip() == "at-admin"
    assert cli.main(["--pointer", str(cli_transport), "--json", "whoami", "--system"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["username"] == "owner"
    assert "s3cret" not in out and "at-admin" not in out


def test_the_cli_reaches_a_registered_provider(entry_points, tmp_path, capsys):
    pointer = tmp_path / "acme.json"
    pointer.write_text(json.dumps({"provider": "acme", "tenant": "t9"}))
    assert cli.main(["--pointer", str(pointer), "whoami", "--system"]) == 0
    assert "system@t9 (System)" in capsys.readouterr().out
