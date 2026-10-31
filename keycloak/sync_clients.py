"""Add to the running dev realm the clients the realm file declares and it lacks (env-LOCAL-000003).

    uv run python keycloak/sync_clients.py [--realm-file keycloak/realm-catalyst-tests.json]

The dev realm persists (`.keycloack/`, env-LOCAL-000002), so a client added to `keycloak/realm-catalyst.json` after
its first start never reaches it by import. Each declared client the realm lacks is created from its declaration
(which holds no secret, id-PROVIDER-000007: Keycloak generates a confidential client's), and each declared protocol
mapper a client lacks is added. It adds, never changes or deletes, and prints no secret. The admin API is reached as
Keycloak's dev bootstrap admin (`compose.yaml`), on the loopback address only. `--realm-file` names another file
of the same shape: `realm-catalyst-tests.json` holds the integration tests' client, which the dev realm does not
carry; the tests add it themselves (`tests/integration/conftest.py`).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Protocol

from set_admin import bootstrap_token  # the sibling script; `python keycloak/…` puts keycloak/ on the path

from catalyst_users.admin import KeycloakAdmin
from catalyst_users.config import Settings
from catalyst_users.errors import CatalystUsersError
from catalyst_users.http import Response
from catalyst_users.providers.keycloak import definition_problems

REALM_FILE = Path(__file__).with_name("realm-catalyst.json")


class Admin(Protocol):
    def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None) -> Response: ...


def declared_clients(realm: dict[str, Any], name: str = REALM_FILE.name) -> list[dict[str, Any]]:
    """The realm file's clients; the file must hold no person or secret."""
    if problems := definition_problems(realm):
        raise SystemExit(f"sync_clients: {name}: {problems[0]}")
    return list(realm.get("clients", []))


def sync_client(admin: Admin, declaration: dict[str, Any]) -> list[str]:
    """Create the client when the realm lacks it, else add the declared mappers it lacks; what was added."""
    client_id = declaration["clientId"]
    found = admin._call("GET", "/clients", params={"clientId": client_id}).json() or []
    if not found:
        admin._call("POST", "/clients", body=declaration)
        return [client_id]
    client = found[0]["id"]
    held = {m["name"] for m in admin._call("GET", f"/clients/{client}/protocol-mappers/models").json() or []}
    added = []
    for mapper in declaration.get("protocolMappers", []):
        if mapper["name"] not in held:
            admin._call("POST", f"/clients/{client}/protocol-mappers/models", body=mapper)
            added.append(f"{client_id}: {mapper['name']}")
    return added


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--server", default="http://127.0.0.1:8080")
    p.add_argument("--realm-file", type=Path, default=REALM_FILE, help="the realm file declaring the clients")
    args = p.parse_args(argv)

    clients = declared_clients(json.loads(args.realm_file.read_text()), args.realm_file.name)
    boot_user = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
    boot_password = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "dev-only-admin-password")
    token = bootstrap_token(args.server, boot_user, boot_password)
    admin = KeycloakAdmin(Settings(server_url=args.server, realm="catalyst"), lambda: token)
    try:
        added = [item for client in clients for item in sync_client(admin, client)]
    except CatalystUsersError as err:
        print(f"sync_clients: {err}", file=sys.stderr)
        return 1
    print(f"added: {', '.join(added)}" if added else "the realm has every declared client and mapper")
    return 0


if __name__ == "__main__":
    sys.exit(main())
