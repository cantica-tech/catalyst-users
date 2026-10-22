"""Transport safety (id-AUTH-000005) and settings precedence."""

import pytest

from catalyst_users import config
from catalyst_users.errors import InsecureURLError, ProviderUnavailableError
from catalyst_users.http import Http, Request, check_url, urllib_transport
from catalyst_users.oidc import OIDCClient
from tests.conftest import DISCOVERY, ISSUER, reply


@pytest.mark.parametrize(
    "url", ["https://id.example.com/x", "http://localhost:8080/x", "http://127.0.0.1/x", "http://[::1]:8080/x"]
)
def test_https_or_loopback_is_allowed(url):
    check_url(url)


@pytest.mark.parametrize(
    "url", ["http://id.example.com/x", "ftp://id.example.com/x", "file:///etc/passwd", "id.example.com"]
)
def test_anything_else_is_refused(url):
    with pytest.raises(InsecureURLError):
        check_url(url)


def test_a_refused_url_is_never_sent(transport):
    with pytest.raises(InsecureURLError):
        Http(transport).request("GET", "http://id.example.com/realms/catalyst")
    assert transport.requests == []


def test_redirects_are_not_followed():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.handle_request, daemon=True).start()
    resp = urllib_transport(Request("GET", f"http://127.0.0.1:{server.server_port}/"), 5)
    server.server_close()
    assert resp.status == 302


def test_an_unreachable_provider_is_reported_as_such():
    with pytest.raises(ProviderUnavailableError):
        urllib_transport(Request("GET", "http://127.0.0.1:9/"), 1)


def test_discovery_must_name_the_expected_issuer(settings, transport, clock):
    transport.on(
        "GET",
        f"{ISSUER}/.well-known/openid-configuration",
        reply(body={**DISCOVERY, "issuer": "https://evil.example.com/realms/catalyst"}),
    )
    with pytest.raises(ProviderUnavailableError, match="issuer"):
        _ = OIDCClient(settings, Http(transport), clock=clock).endpoints


def test_discovery_endpoints_must_be_https(settings, transport, clock):
    transport.on(
        "GET",
        f"{ISSUER}/.well-known/openid-configuration",
        reply(body={**DISCOVERY, "token_endpoint": "http://id.example.com/token"}),
    )
    with pytest.raises(InsecureURLError):
        _ = OIDCClient(settings, Http(transport), clock=clock).endpoints


def test_settings_precedence(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('server_url = "https://from-file.example.com"\nrealm = "file-realm"\ntimeout = 3\n')
    monkeypatch.setenv("CATALYST_USERS_REALM", "env-realm")
    s = config.load({"client_id": "flag-client", "realm": None}, config_file=cfg)
    assert (s.server_url, s.realm, s.client_id, s.timeout) == (
        "https://from-file.example.com",
        "env-realm",
        "flag-client",
        3.0,
    )
    assert s.issuer == "https://from-file.example.com/realms/env-realm"


def test_the_api_secret_never_appears_in_repr():
    assert "s3cret" not in repr(config.Settings(api_client_secret="s3cret"))
