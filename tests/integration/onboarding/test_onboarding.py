"""The greenfield onboarding of docs/onboarding.md, end to end, against a Keycloak of its own.

A fresh Keycloak with no realm is started in Docker on a free loopback port (never the compose one on 8080), and every
home is a temporary directory, so nothing of this machine's setup is read or changed. Runs only when
CATALYST_USERS_IT=1 and Docker is available (env-QUALITY-000002); the catalyst steps also need a catalyst checkout
(CATALYST_CHECKOUT, else `../catalyst`).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

import pytest

from catalyst_users import cli
from tests.integration.conftest import approve_device

ROOT = Path(__file__).resolve().parents[3]
IMAGE = "quay.io/keycloak/keycloak:26.4.0"  # compose.yaml's
ADMIN = {"username": "greenfield-admin", "email": "greenfield-admin@example.com", "first": "Green", "last": "Field"}

pytestmark = [
    pytest.mark.skipif(os.environ.get("CATALYST_USERS_IT") != "1", reason="integration: set CATALYST_USERS_IT=1"),
    pytest.mark.skipif(shutil.which("docker") is None, reason="integration: needs Docker"),
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _printing(secret: str, where: Path) -> str:
    """A password command, as setup stores it: run without a shell, it prints the secret, which it reads from a file
    (as a keychain command reads the keychain), so the command never holds the secret."""
    where.write_text(secret, encoding="utf-8")
    where.chmod(0o600)
    return shlex.join([sys.executable, "-c", f"print(open({str(where)!r}, encoding='utf-8').read())"])


def _wait_until_up(url: str, timeout: float = 240) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with (
            contextlib.suppress(urllib.error.URLError, ConnectionError, OSError),
            urllib.request.urlopen(f"{url}/realms/master", timeout=5) as resp,  # noqa: S310 - loopback
        ):
            if resp.status == 200:
                return
        time.sleep(2)
    raise TimeoutError(f"Keycloak did not come up at {url}")


@pytest.fixture(scope="module")
def keycloak():
    """An empty Keycloak: no realm imported, its own bootstrap admin, removed afterwards."""
    port, name = _free_port(), f"catalyst-users-onboarding-{secrets.token_hex(4)}"
    bootstrap = secrets.token_urlsafe(16)
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:8080",
         "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", f"KC_BOOTSTRAP_ADMIN_PASSWORD={bootstrap}",
         IMAGE, "start-dev"],
        check=True, capture_output=True,
    )  # fmt: skip
    try:
        url = f"http://127.0.0.1:{port}"
        _wait_until_up(url)
        yield {"url": url, "bootstrap": bootstrap}
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)


def _cli(*argv: str) -> dict:
    """catalyst-users as the UI runs it, `--json`: its answer, or the failure."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(["--json", *argv])
    assert code == 0, out.getvalue()
    return json.loads(out.getvalue())


@pytest.fixture(scope="module")
def onboarded(keycloak, tmp_path_factory):
    """Steps 3 to 5 of docs/onboarding.md, through the command line, in a home of their own."""
    home, vault = tmp_path_factory.mktemp("catalyst-users-home"), tmp_path_factory.mktemp("vault")
    password = secrets.token_urlsafe(16)
    provider = {"url": keycloak["url"], "realm": "catalyst", "definition": str(ROOT / "keycloak/realm-catalyst.json")}
    setup = [
        "setup", "--type", "keycloak", "--provider", json.dumps(provider),
        "--username", ADMIN["username"], "--password-command", _printing(password, vault / "admin"),
        "--server-admin", "admin",
        "--server-admin-password-command", _printing(keycloak["bootstrap"], vault / "server-admin"),
        "--email", ADMIN["email"], "--first-name", ADMIN["first"], "--last-name", ADMIN["last"],
        "--criterion", "greenfield", "--criterion", "other",
    ]  # fmt: skip
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("CATALYST_USERS_HOME", str(home))
        mp.delenv("CATALYST_USERS_POINTER", raising=False)
        result = {"home": home, "password": password, "setup_args": setup}
        result["setup"] = _cli(*setup)  # step 3
        result["system_before"] = _cli("whoami", "--system")  # step 4

        def approve(code):  # step 5: the admin approves the device login in the browser
            threading.Thread(target=approve_device, args=(code, ADMIN["username"], password), daemon=True).start()

        mp.setattr(cli, "_show_code", approve)
        result["login"] = _cli("login")
        result["provision"] = _cli(
            "roles", "provision", str(ROOT / "keycloak/catalyst-roles.json"),
            "--login-client", "catalyst-cli", "--login-client", "catalyst-admin-cli",
        )  # fmt: skip
        result["system_after"] = _cli("whoami", "--system")
        yield result


def test_setup_creates_the_realm_and_its_admin(onboarded, keycloak):
    assert onboarded["setup"]["outcome"] == "created"
    assert onboarded["setup"]["username"] == ADMIN["username"]
    settings_file = onboarded["home"] / "IAM" / "settings.json"
    settings = json.loads(settings_file.read_text(encoding="utf-8"))
    assert settings["provider"]["url"] == keycloak["url"] and settings["provider"]["realm"] == "catalyst"
    assert "definition" not in settings["provider"]  # used only to create the realm
    text = settings_file.read_text(encoding="utf-8")
    assert onboarded["password"] not in text and keycloak["bootstrap"] not in text  # never a secret
    assert settings_file.stat().st_mode & 0o077 == 0


def test_the_admin_is_the_system_account(onboarded, keycloak):
    who = onboarded["system_before"]
    assert who["username"] == ADMIN["username"]
    assert who["iss"] == f"{keycloak['url']}/realms/catalyst"
    assert "/catalyst-admins" in who["groups"] and "catalyst-admin" in who["roles"]


def test_the_admin_provisions_catalysts_roles_and_holds_their_grants(onboarded):
    assert onboarded["login"]["username"] == ADMIN["username"]
    assert onboarded["provision"]["created"]  # a greenfield realm lacks them
    assert "cmd:*" in onboarded["system_after"]["grants"]


def test_setup_readies_criteria_and_appoints_the_admin_to_each(onboarded):
    """id-PROVIDER-000008: onboarding adds a criterion per deployment, the catalyst-admin its first admin."""
    assert onboarded["system_before"]["administers"] == ["greenfield", "other"]
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("CATALYST_USERS_HOME", str(onboarded["home"]))
        listed = {c["name"]: c["admins"] for c in _cli("criteria", "list")}
    assert listed == {"greenfield": [ADMIN["username"]], "other": [ADMIN["username"]]}


def _token(keycloak: dict, realm: str, username: str, password: str, client: str) -> str:
    form = {
        "grant_type": "password",
        "client_id": client,
        "username": username,
        "password": password,
        "scope": "openid",
    }
    req = urllib.request.Request(  # noqa: S310 - loopback
        f"{keycloak['url']}/realms/{realm}/protocol/openid-connect/token", data=urllib.parse.urlencode(form).encode()
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        return json.load(resp)["access_token"]


def _directory(keycloak: dict, token: Callable[[], str]):
    from catalyst_users.admin import KeycloakAdmin
    from catalyst_users.config import Settings

    return KeycloakAdmin(Settings(server_url=keycloak["url"], realm="catalyst"), token)


def test_a_criterion_admin_administers_their_criterion_and_nothing_else(onboarded, keycloak):
    """id-DIR-000005, against the onboarded realm: appointed to greenfield by the catalyst-admin, Kim manages its
    groups' members and appoints another admin there, and is refused on the other criterion, on users, groups and
    roles; their token carries no grant, and catalyst-users says what they administer."""
    from catalyst_users.errors import AdminError
    from catalyst_users.provider import whoami_from_claims

    server = _directory(keycloak, lambda: _token(keycloak, "master", "admin", keycloak["bootstrap"], "admin-cli"))
    password = secrets.token_urlsafe(16)
    for username in ("kim-criterion", "lee-member"):
        user = server.create_user(username, f"{username}@example.com", username.split("-")[0].title(), "Test")
        server._call("PUT", f"/users/{user.id}", body={"emailVerified": True})
        reset = {"type": "password", "value": password, "temporary": False}
        server._call("PUT", f"/users/{user.id}/reset-password", body=reset)
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("CATALYST_USERS_HOME", str(onboarded["home"]))
        _cli("groups", "add", "/criteria/greenfield/developers")
        _cli("criteria", "add", "greenfield")  # covers the new group
        _cli("criteria", "appoint", "greenfield", "kim-criterion")

    def kim_token() -> str:
        return _token(keycloak, "catalyst", "kim-criterion", password, "catalyst-admin-cli")

    kim = _directory(keycloak, kim_token)
    kim.add_member("/criteria/greenfield/developers", "lee-member")
    assert kim.members("/criteria/greenfield/developers") == ["lee-member"]
    kim.appoint("greenfield", "lee-member")
    kim.dismiss("greenfield", "lee-member")
    # its members group (id-DIR-000006), made with the criterion and covered by Kim's permission
    kim.join_criterion("greenfield", "lee-member")
    assert kim.criterion_members("greenfield") == ["lee-member"]
    assert kim.is_criterion_member("greenfield", "lee-member")
    assert not kim.is_criterion_member("greenfield", "kim-criterion")
    kim.leave_criterion("greenfield", "lee-member")
    assert not kim.is_criterion_member("greenfield", "lee-member")
    refused = {
        "another criterion": lambda: kim.add_member("/criteria/other/admins", "lee-member"),
        "another criterion's members": lambda: kim.join_criterion("other", "lee-member"),
        "its members": lambda: kim.members("/criteria/other/admins"),
        "the catalyst-admins": lambda: kim.add_member("/catalyst-admins", "lee-member"),
        "a user": lambda: kim.create_user("eve-rogue"),
        "a group": lambda: kim.create_group("/criteria/greenfield/rogue"),
        "a role": lambda: kim.grant_role_to_group("/criteria/greenfield/developers", "tech-lead"),
    }
    for what, attempt in refused.items():
        with pytest.raises(AdminError):
            attempt()
            pytest.fail(f"a criterion-admin changed {what}")
    from catalyst_users.config import Settings
    from catalyst_users.oidc import OIDCClient

    oidc = OIDCClient(Settings(server_url=keycloak["url"], realm="catalyst", client_id="catalyst-admin-cli"))
    who = whoami_from_claims(oidc.userinfo(kim_token()), f"{keycloak['url']}/realms/catalyst", "catalyst")
    assert who.administers == ("greenfield",) and "criterion-admin" in who.roles
    assert not [g for g in who.grants if g.startswith("cmd:")]


def test_setup_again_only_signs_the_admin_in(onboarded):
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("CATALYST_USERS_HOME", str(onboarded["home"]))
        assert _cli(*onboarded["setup_args"], "--force")["outcome"] == "authenticated"


def _catalyst_checkout() -> Path | None:
    found = Path(os.environ.get("CATALYST_CHECKOUT") or ROOT.parent / "catalyst")
    return found if (found / "framework/kernel").is_dir() and (found / "scripts/catalyst").is_dir() else None


def test_catalyst_installs_onto_it_and_the_admin_signs_first(onboarded, keycloak, tmp_path):
    """Steps 6 and 7: `catalyst init` takes the machine's catalyst-users setup; the system account signs first."""
    checkout = _catalyst_checkout()
    if checkout is None:
        pytest.skip("needs a catalyst checkout (CATALYST_CHECKOUT, else ../catalyst)")
    project, catalyst_home = tmp_path / "greenfield", tmp_path / "catalyst-home"
    project.mkdir()
    env = {
        **os.environ,
        "CATALYST_HOME": str(catalyst_home),
        "CATALYST_USERS_HOME": str(onboarded["home"]),
        "PYTHONPATH": str(checkout / "scripts"),
        "GIT_AUTHOR_NAME": f"{ADMIN['first']} {ADMIN['last']}",
        "GIT_COMMITTER_NAME": f"{ADMIN['first']} {ADMIN['last']}",
    }
    env.pop("CATALYST_USERS_POINTER", None)
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)

    def catalyst(*argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "catalyst", *argv],
            check=False, cwd=project, env=env, capture_output=True, text=True, timeout=600,
        )  # fmt: skip

    init = catalyst(
        "init", "--kernel", str(checkout / "framework/kernel"), "--name", "greenfield", "--no-module",
        "--no-runtime", "--user", f"{ADMIN['first']} {ADMIN['last']}", "--git-username", ADMIN["username"],
    )  # fmt: skip
    assert init.returncode == 0, init.stdout + init.stderr
    assert sorted(p.name for p in project.iterdir() if p.name != ".git") == ["catalyst.toml"]

    criterion = catalyst_home / "projects" / "greenfield" / "criterion"
    pointer = json.loads((criterion / "IAM" / "identity.json").read_text(encoding="utf-8"))
    assert pointer["provider"] == "keycloak" and pointer["url"] == keycloak["url"]

    who = catalyst("identity", "whoami")
    assert who.returncode == 0, who.stdout + who.stderr
    assert ADMIN["username"] in who.stdout

    signers = [json.loads(line) for line in (criterion / "IAM" / "signers.jsonl").read_text().splitlines() if line]
    assert [s["username"] for s in signers] == [ADMIN["username"]]
    assert signers[0]["iss"] == f"{keycloak['url']}/realms/catalyst"

    check = catalyst("check")
    assert check.returncode == 0, check.stdout + check.stderr
