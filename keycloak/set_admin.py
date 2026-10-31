"""Make the owner an admin of the dev realm, from the macOS keychain (env-LOCAL-000002).

    uv run python keycloak/set_admin.py --email you@example.com [--sole-admin]

The username is the keychain item's account (`security find-generic-password -s <service>`, its `acct`), the
password its secret (`-w`). The user is created or updated in realm `catalyst` (email verified, enabled, the password
not temporary) and made a member of `/catalyst-admins`. The group's other members stay, and are listed; with
`--sole-admin`, they are removed from it (never deleted), so the owner is its only member. Nothing read from the
keychain is printed or written anywhere; the password travels only in the request to Keycloak. The admin API is
reached as Keycloak's dev bootstrap admin (`compose.yaml`), on the loopback address only.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

from catalyst_users.admin import KeycloakAdmin
from catalyst_users.config import Settings
from catalyst_users.errors import CatalystUsersError, NotFoundError
from catalyst_users.http import check_url

ADMINS = "/catalyst-admins"


def keychain(service: str) -> tuple[str, str]:
    """(username, password) of the keychain item, as `grep acct | cut -c 19- | tr -d '"'` and `-w` read them."""
    item = subprocess.run(
        ["security", "find-generic-password", "-s", service], capture_output=True, text=True, check=False
    )
    lines = [line for line in item.stdout.splitlines() if "acct" in line]
    if item.returncode != 0 or not lines:
        raise SystemExit(f"set_admin: no keychain item for service {service!r}")
    username = lines[0][18:].replace('"', "").strip()
    secret = subprocess.run(
        ["security", "find-generic-password", "-s", service, "-w"], capture_output=True, text=True, check=False
    )
    password = secret.stdout.rstrip("\n")
    if secret.returncode != 0 or not password or not username:
        raise SystemExit(f"set_admin: the keychain item {service!r} has no account or no password")
    return username, password


def bootstrap_token(server: str, username: str, password: str) -> str:
    """An access token of Keycloak's bootstrap admin (realm `master`), which administers every realm."""
    url = f"{server.rstrip('/')}/realms/master/protocol/openid-connect/token"
    check_url(url)
    form = urllib.parse.urlencode(
        {"grant_type": "password", "client_id": "admin-cli", "username": username, "password": password}
    ).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=form), timeout=10) as resp:  # noqa: S310 - checked
        return json.load(resp)["access_token"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--email", required=True)
    p.add_argument("--service", default="osteck@catalyst-users", help="the keychain item's service")
    p.add_argument("--server", default="http://127.0.0.1:8080")
    p.add_argument("--first-name", help="default: the first word of `git config user.name`")
    p.add_argument("--last-name", help="default: the rest of `git config user.name`")
    p.add_argument(
        "--sole-admin",
        action="store_true",
        help=f"remove every other member of {ADMINS} (never the person), so the owner is its only member",
    )
    args = p.parse_args(argv)

    username, password = keychain(args.service)
    git_name = subprocess.run(
        ["git", "config", "user.name"], capture_output=True, text=True, check=False
    ).stdout.split()
    first = args.first_name or (git_name[0] if git_name else username)
    last = args.last_name or (" ".join(git_name[1:]) if len(git_name) > 1 else username)

    boot_user = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
    boot_password = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "dev-only-admin-password")
    token = bootstrap_token(args.server, boot_user, boot_password)
    admin = KeycloakAdmin(Settings(server_url=args.server, realm="catalyst"), lambda: token)
    try:
        try:
            user = admin.user(username)
            created = False
        except NotFoundError:
            user = admin.create_user(username, args.email, first, last)
            created = True
        profile = {"email": args.email, "emailVerified": True, "enabled": True, "firstName": first, "lastName": last}
        admin._call("PUT", f"/users/{user.id}", body=profile)
        admin._call(
            "PUT", f"/users/{user.id}/reset-password", body={"type": "password", "value": password, "temporary": False}
        )
        admin.add_member(ADMINS, username)
        others = [m for m in admin.members(ADMINS) if m != username.lower()]
        if args.sole_admin:
            for other in others:
                admin.remove_member(ADMINS, other)
    except CatalystUsersError as err:
        print(f"set_admin: {err}", file=sys.stderr)
        return 1
    done = "created" if created else "updated"
    if args.sole_admin:
        print(f"{done} the realm's admin; {ADMINS} now holds only them")
        if others:
            print(f"removed from {ADMINS}: {', '.join(others)}")
    else:
        print(f"{done} the realm's admin, a member of {ADMINS}")
        if others:
            print(f"also in {ADMINS} (kept; --sole-admin removes them): {', '.join(others)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
