"""Create catalyst's system client in the dev realm, and keep its secret in the keychain (env-LOCAL-000003).

    uv run python keycloak/set_system_client.py [--role ROLE]...

`catalyst-system` is declared in `keycloak/realm-catalyst.json` without a secret: a confidential client whose only
flow is its service account (the client credentials grant). It is created in the running realm from that declaration
when it is missing, its service account is given each realm role asked for (and keeps those it has), and the secret
Keycloak generated is stored in the macOS keychain item whose service is `catalyst-system@catalyst-users` (account
`catalyst-system`), passed to `security` on its standard input. Neither the secret nor a token is printed or written
anywhere else. The admin API is reached as Keycloak's dev bootstrap admin (`compose.yaml`), on the loopback address
only. A client reads the secret back with `security find-generic-password -s catalyst-system@catalyst-users -w`.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Protocol

from set_admin import bootstrap_token  # the sibling script; `python keycloak/…` puts keycloak/ on the path

from catalyst_users.admin import KeycloakAdmin
from catalyst_users.config import Settings
from catalyst_users.errors import CatalystUsersError
from catalyst_users.http import Response

CLIENT_ID = "catalyst-system"
SERVICE = "catalyst-system@catalyst-users"
REALM_FILE = Path(__file__).with_name("realm-catalyst.json")


class Admin(Protocol):
    def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None) -> Response: ...


def declared_client(realm: dict[str, Any]) -> dict[str, Any]:
    """The realm file's declaration of the system client, which must carry no secret."""
    client = next((c for c in realm.get("clients", []) if c.get("clientId") == CLIENT_ID), None)
    if client is None:
        raise SystemExit(f"set_system_client: {REALM_FILE.name} declares no {CLIENT_ID} client")
    if "secret" in client:
        raise SystemExit(f"set_system_client: {REALM_FILE.name} must not hold {CLIENT_ID}'s secret")
    return client


def ensure_client(admin: Admin, declaration: dict[str, Any]) -> tuple[str, bool]:
    """The client's internal id, creating it from its declaration when the realm lacks it, else adding the declared
    protocol mappers it lacks; and whether it was created."""
    found = admin._call("GET", "/clients", params={"clientId": CLIENT_ID}).json() or []
    if not found:
        admin._call("POST", "/clients", body=declaration)
        return admin._call("GET", "/clients", params={"clientId": CLIENT_ID}).json()[0]["id"], True
    client = found[0]["id"]
    held = {m["name"] for m in admin._call("GET", f"/clients/{client}/protocol-mappers/models").json() or []}
    for mapper in declaration.get("protocolMappers", []):
        if mapper["name"] not in held:
            admin._call("POST", f"/clients/{client}/protocol-mappers/models", body=mapper)
    return client, False


def grant_roles(admin: Admin, client: str, roles: list[str]) -> list[str]:
    """Give the client's service account each realm role it lacks; the roles it was given."""
    if not roles:
        return []
    user = admin._call("GET", f"/clients/{client}/service-account-user").json()["id"]
    held = {r["name"] for r in admin._call("GET", f"/users/{user}/role-mappings/realm").json() or []}
    missing = [admin._call("GET", f"/roles/{name}").json() for name in roles if name not in held]
    if missing:
        admin._call("POST", f"/users/{user}/role-mappings/realm", body=missing)
    return [r["name"] for r in missing]


def client_secret(admin: Admin, client: str) -> str:
    """The client's secret, generating one when it has none."""
    value = (admin._call("GET", f"/clients/{client}/client-secret").json() or {}).get("value")
    if not value:
        value = admin._call("POST", f"/clients/{client}/client-secret").json()["value"]
    return value


def keychain_command(secret: str) -> str:
    """The `security -i` line that stores the secret, quoted for its parser; it goes on stdin, never argv."""
    quoted = secret.replace("\\", "\\\\").replace('"', '\\"')
    return f'add-generic-password -U -s "{SERVICE}" -a "{CLIENT_ID}" -w "{quoted}"\n'


def store_secret(secret: str) -> None:
    done = subprocess.run(
        ["security", "-i"], input=keychain_command(secret), capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        raise SystemExit(f"set_system_client: the keychain refused the item {SERVICE!r}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--role", action="append", default=[], help="a realm role for the service account (repeatable)")
    p.add_argument("--server", default="http://127.0.0.1:8080")
    args = p.parse_args(argv)

    declaration = declared_client(json.loads(REALM_FILE.read_text()))
    boot_user = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
    boot_password = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "dev-only-admin-password")
    token = bootstrap_token(args.server, boot_user, boot_password)
    admin = KeycloakAdmin(Settings(server_url=args.server, realm="catalyst"), lambda: token)
    try:
        client, created = ensure_client(admin, declaration)
        granted = grant_roles(admin, client, args.role)
        store_secret(client_secret(admin, client))
    except CatalystUsersError as err:
        print(f"set_system_client: {err}", file=sys.stderr)
        return 1
    print(f"{'created' if created else 'found'} {CLIENT_ID}; its secret is in the keychain item {SERVICE}")
    if granted:
        print(f"granted its service account: {', '.join(granted)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
