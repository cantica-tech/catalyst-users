"""Loopback issuers are one provider (BUG-000047, id-AUTH-000006), explicit settings naming settings.json's provider
keep its system account (BUG-000049), setup fails when the provider cannot be checked (BUG-000048,
id-PROVIDER-000006), and global options go before or after the command (BUG-000050, id-PROVIDER-000001)."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from catalyst_users import cli, config
from catalyst_users.config import Settings, canonical_issuer, same_issuer
from catalyst_users.errors import ProviderUnavailableError
from catalyst_users.http import Http
from catalyst_users.oidc import OIDCClient
from catalyst_users.provider import from_pointer
from tests.conftest import FakeTransport, reply

LOCAL = "http://localhost:8080/realms/catalyst"
NUMERIC = "http://127.0.0.1:8080/realms/catalyst"
PASSWORD_COMMAND = f"{sys.executable} -c \"print('owner-pw')\""


# --- one loopback provider, whatever its spelling (BUG-000047) ---------------------------------------
@pytest.mark.parametrize(
    "spelling",
    [
        NUMERIC,
        f"{NUMERIC}/",
        "http://[::1]:8080/realms/catalyst",
        "HTTP://LocalHost:8080/realms/catalyst",
    ],
)
def test_the_loopback_spellings_name_one_issuer(spelling):
    assert canonical_issuer(spelling) == LOCAL
    assert same_issuer(spelling, LOCAL)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (NUMERIC, "http://127.0.0.1:8081/realms/catalyst"),  # another port: another provider
        (NUMERIC, "http://127.0.0.1:8080/realms/other"),
        ("https://id.example.com/realms/catalyst", "https://id2.example.com/realms/catalyst"),
        ("http://10.0.0.1:8080/realms/catalyst", NUMERIC),  # not loopback
        (None, LOCAL),
        ("", ""),
    ],
)
def test_other_issuers_stay_apart(a, b):
    assert not same_issuer(a, b)


def _discovery(issuer: str) -> dict[str, str]:
    oidc = f"{issuer}/protocol/openid-connect"
    return {
        "issuer": issuer,
        "token_endpoint": f"{oidc}/token",
        "device_authorization_endpoint": f"{oidc}/auth/device",
        "introspection_endpoint": f"{oidc}/token/introspect",
        "userinfo_endpoint": f"{oidc}/userinfo",
        "revocation_endpoint": f"{oidc}/revoke",
    }


def test_discovery_and_introspection_take_a_loopback_issuer_as_the_same():
    transport = FakeTransport()
    transport.on("GET", f"{NUMERIC}/.well-known/openid-configuration", reply(body=_discovery(LOCAL)))
    oidc = OIDCClient(Settings(server_url="http://127.0.0.1:8080"), Http(transport), clock=lambda: 1000.0)
    assert oidc.endpoints.issuer == LOCAL
    assert oidc.accepts({"active": True, "iss": LOCAL, "aud": "catalyst-api", "exp": 2000})
    assert not oidc.accepts(
        {"active": True, "iss": "http://localhost:9090/realms/catalyst", "aud": "catalyst-api", "exp": 2000}
    )


# --- settings.json's system account, kept for its own provider (BUG-000049) --------------------------
def _settings(url: str = "http://127.0.0.1:8080", **extra: Any) -> None:
    provider = {"url": url, "realm": "catalyst", "client": "catalyst-cli", "password_client": "catalyst-admin-cli"}
    config.write_settings(
        {"type": "keycloak", "username": "owner", "provider": provider, "password_command": PASSWORD_COMMAND, **extra}
    )


def test_the_system_pointer_is_found_for_its_provider_under_any_loopback_spelling():
    _settings()
    doc = config.system_pointer(LOCAL)
    assert doc is not None and doc["username"] == "owner" and doc["password_command"] == PASSWORD_COMMAND
    assert from_pointer(doc).issuer == LOCAL  # reached as the caller spells it: its tokens carry that `iss`
    assert from_pointer(config.system_pointer(f"{NUMERIC}/") or {}).issuer == NUMERIC
    assert config.system_pointer("http://localhost:8081/realms/catalyst") is None
    assert config.system_pointer(LOCAL, client="other-cli")["client"] == "other-cli"  # type: ignore[index]


def test_no_system_pointer_without_a_system_account():
    assert config.system_pointer(LOCAL) is None  # no settings.json
    _settings(password_command="")
    assert config.system_pointer(LOCAL) is None


def test_explicit_settings_naming_settings_json_provider_keep_its_system_account(monkeypatch):
    _settings()
    monkeypatch.setenv("CATALYST_USERS_SERVER", "http://localhost:8080")
    doc = config.pointer()
    assert doc["username"] == "owner" and doc["password_command"] == PASSWORD_COMMAND
    assert doc["issuer"] == LOCAL and doc["password_client"] == "catalyst-admin-cli"
    flags = config.pointer({"server_url": "http://127.0.0.1:8080/", "client_id": "other-cli"})
    assert flags["username"] == "owner" and flags["client"] == "other-cli"


def test_explicit_settings_naming_another_provider_still_drop_the_system_account(monkeypatch):
    _settings()
    monkeypatch.setenv("CATALYST_USERS_SERVER", "https://id.example.com")
    doc = config.pointer()
    assert doc["issuer"] == "https://id.example.com/realms/catalyst" and "username" not in doc
    monkeypatch.setenv("CATALYST_USERS_SERVER", "http://localhost:8080")
    monkeypatch.setenv("CATALYST_USERS_REALM", "other")
    assert "username" not in config.pointer()


# --- setup fails when the provider cannot be checked (BUG-000048) ------------------------------------
def test_setup_with_the_provider_down_writes_the_settings_unchecked_and_fails(monkeypatch, capsys):
    def down(self, method, url, **kwargs):
        raise ProviderUnavailableError("identity provider unreachable: connection refused")

    monkeypatch.setattr(Http, "request", down)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    args = ["--json", "setup", "--type", "keycloak", "--provider", json.dumps({"url": "http://localhost:8080"})]
    assert cli.main([*args, "--username", "owner", "--password-command", PASSWORD_COMMAND]) == 1
    out = capsys.readouterr()
    assert json.loads(out.out)["outcome"] == "unreachable"
    assert "could not be checked" in out.err and "setup --force" in out.err
    assert json.loads(config.settings_file().read_text())["username"] == "owner"


# --- global options before or after the command (BUG-000050) -----------------------------------------
@pytest.mark.parametrize(
    "argv",
    [
        ["whoami", "--json"],
        ["--json", "whoami"],
        ["whoami", "--server", "http://localhost:8080", "--json"],
        ["users", "list", "--json", "--realm", "r"],
        ["criteria", "members", "c1", "--pointer", "p.json"],
    ],
)
def test_global_options_go_before_or_after_the_command(argv):
    args = cli._parser().parse_args(argv)
    given = dict(zip(argv, [*argv[1:], None], strict=True))
    assert args.json == ("--json" in argv)
    assert args.server_url == given.get("--server")
    assert args.realm == given.get("--realm")
    assert args.pointer == given.get("--pointer")


def test_an_option_before_the_command_is_kept_when_not_repeated_after_it():
    args = cli._parser().parse_args(["--json", "--server", "http://a", "users", "list", "--search", "x"])
    assert args.json and args.server_url == "http://a" and args.search == "x"
    later = cli._parser().parse_args(["--server", "http://a", "whoami", "--server", "http://b"])
    assert later.server_url == "http://b"


def test_token_system_help_names_the_password_grant(capsys):
    with pytest.raises(SystemExit):
        cli._parser().parse_args(["token", "--help"])
    shown = capsys.readouterr().out
    assert "password grant" in shown and "client credentials" not in shown
