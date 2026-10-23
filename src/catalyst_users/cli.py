"""`catalyst-users`: a command-line facade to an identity provider (id-PROVIDER-000001, id-PROVIDER-000005).

Log in, see who you are, sign in as the local system account, and manage the directory, whatever the provider:
the built-in `keycloak` (and `static`, for tests), or one an installed package registers. `providers` lists them.

Exit codes: 0 done, 1 refused or failed, 2 usage.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from catalyst_users import __version__, config
from catalyst_users.errors import CatalystUsersError
from catalyst_users.oidc import DeviceCode
from catalyst_users.provider import Provider, Whoami, from_pointer, registered


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="catalyst-users", description=(__doc__ or "").splitlines()[0])
    p.add_argument("--version", action="version", version=f"catalyst-users {__version__}")
    p.add_argument(
        "--pointer", help="a pointer document (JSON) naming the provider and its settings (default: config.toml's)"
    )
    p.add_argument("--server", dest="server_url", help="keycloak: the server URL (default: http://localhost:8080)")
    p.add_argument("--realm", help="keycloak: the realm (default: catalyst)")
    p.add_argument("--client-id", help="keycloak: the public client for login (default: catalyst-cli)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("providers", help="the registered providers")
    sub.add_parser("login", help="log in with a code shown in your browser")
    sub.add_parser("logout", help="revoke your session and delete local credentials")
    w = sub.add_parser("whoami", help="who you are: groups and roles")
    w.add_argument("--system", action="store_true", help="the local system account instead (signs it in)")
    t = sub.add_parser("token", help="print a fresh access token (keep it secret)")
    t.add_argument("--system", action="store_true", help="the local system account's (client credentials)")

    users = sub.add_parser("users", help="users").add_subparsers(dest="action", required=True)
    u = users.add_parser("list", help="list users")
    u.add_argument("--search")
    u = users.add_parser("add", help="add a user")
    u.add_argument("username")
    u.add_argument("--email")
    u.add_argument("--first-name")
    u.add_argument("--last-name")
    u.add_argument("--temporary-password", action="store_true", help="prompt for a password to change at first login")
    for action, text in (("disable", "disable a user (users are never deleted)"), ("enable", "enable a user again")):
        users.add_parser(action, help=text).add_argument("username")
    users.add_parser("groups", help="a user's groups").add_argument("username")

    groups = sub.add_parser("groups", help="groups").add_subparsers(dest="action", required=True)
    groups.add_parser("list", help="every group, as a tree")
    groups.add_parser("add", help="create a group path, parents included").add_argument("path")
    groups.add_parser("members", help="a group's direct members").add_argument("path")
    for action in ("add-member", "remove-member"):
        g = groups.add_parser(action, help=f"{action.replace('-', ' ')} to/from a group")
        g.add_argument("path")
        g.add_argument("username")
    g = groups.add_parser("grant-role", help="grant a realm role to a group (its members inherit it)")
    g.add_argument("path")
    g.add_argument("role")

    roles = sub.add_parser("roles", help="realm roles").add_subparsers(dest="action", required=True)
    roles.add_parser("list", help="list realm roles")
    r = roles.add_parser("add", help="add a realm role")
    r.add_argument("name")
    r.add_argument("--description")
    r = roles.add_parser("grant", help="grant a realm role to a user")
    r.add_argument("username")
    r.add_argument("role")
    r = roles.add_parser("provision", help="write a catalyst roles document: roles, their grants, the claim mapper")
    r.add_argument("file", help="a catalyst roles document (roles.json, or the kernel's roles template)")
    r.add_argument("--catalyst-client", default="catalyst", help="the client whose roles are the grants")
    r.add_argument(
        "--login-client", action="append", help="a client whose tokens carry the grants (default: catalyst-cli)"
    )
    u = users.add_parser("import", help="import a catalyst users document (no passwords; never deletes)")
    u.add_argument("file", help="a catalyst users document (users.json)")
    u.add_argument("--roles", required=True, help="its roles document, to map role names to realm roles")
    return p


def _show_code(code: DeviceCode) -> None:
    print(f"Open {code.verification_uri_complete or code.verification_uri}")
    print(f"and confirm the code {code.user_code}. Waiting…", flush=True)


def _out(args: argparse.Namespace, data: Any, text: str) -> None:
    print(json.dumps(data, indent=2) if args.json else text)


def _provider(args: argparse.Namespace) -> Provider:
    overrides = {"server_url": args.server_url, "realm": args.realm, "client_id": args.client_id}
    return from_pointer(config.pointer(overrides, pointer_file=args.pointer))


def _whoami(args: argparse.Namespace, who: Whoami) -> None:
    data = {**who.signer(), "email": who.email, "groups": list(who.groups), "roles": list(who.roles)}
    data["grants"] = list(who.grants)
    text = "\n".join(
        [
            f"{who.username} ({who.name})",
            f"  subject  {who.subject}",
            f"  issuer   {who.issuer}",
            f"  groups   {', '.join(who.groups) or '-'}",
            f"  roles    {', '.join(who.roles) or '-'}",
            f"  grants   {', '.join(who.grants) or '-'}",
        ]
    )
    _out(args, data, text)


def _run(args: argparse.Namespace) -> int:
    if args.command == "providers":
        found = registered()
        _out(
            args,
            [{"name": r.name, "target": r.target, "source": r.source} for r in found.values()],
            "\n".join(f"{r.name:<12} {r.source:<12} {r.target}" for r in found.values()),
        )
        return 0
    provider = _provider(args)

    if args.command == "login":
        who = provider.login(_show_code)
        _out(args, who.signer(), f"Logged in as {who.username} ({who.name}).")
        return 0
    if args.command == "logout":
        warning = provider.logout()
        if warning:
            print(f"catalyst-users: warning: {warning}", file=sys.stderr)
        print("Logged out.")
        return 0
    if args.command == "whoami":
        _whoami(args, provider.system_whoami() if args.system else provider.whoami())
        return 0
    if args.command == "token":
        if args.system:  # printed only on this explicit request (id-AUTH-000002, id-AUTH-000006)
            token = provider.system_token()
            _out(args, token, token["access_token"])
        else:
            print(provider.token())  # printed only on this explicit request (id-AUTH-000002)
        return 0

    return {"users": _users, "groups": _groups, "roles": _roles}[args.command](args, provider)


def _users(args: argparse.Namespace, provider: Provider) -> int:
    if args.action == "import":
        users = _read_list(args.file, "users")
        report = provider.import_users(users, _read_list(args.roles, "roles"))
        _out(args, report.__dict__, f"{len(report.created)} created, {len(report.kept)} already there")
        return 0
    admin = provider.directory()
    if args.action == "list":
        users = admin.list_users(args.search)
        rows = [f"{u.username:<20} {'enabled ' if u.enabled else 'DISABLED'} {u.name}" for u in users]
        _out(args, [u.__dict__ for u in users], "\n".join(rows) or "(no users)")
    elif args.action == "add":
        password = getpass.getpass("Temporary password: ") if args.temporary_password else None
        user = admin.create_user(args.username, args.email, args.first_name, args.last_name, password)
        _out(args, user.__dict__, f"Added {user.username}.")
    elif args.action in ("disable", "enable"):
        user = admin.set_enabled(args.username, args.action == "enable")
        _out(args, user.__dict__, f"{user.username} is {'enabled' if user.enabled else 'disabled'}.")
    elif args.action == "groups":
        paths = admin.user_groups(args.username)
        _out(args, paths, "\n".join(paths) or "(no groups)")
    return 0


def _read_list(path: str, key: str) -> list:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CatalystUsersError(f"cannot read {path}: {exc}") from None
    items = data.get(key) if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise CatalystUsersError(f"{path} has no `{key}` list")
    return items


def _groups(args: argparse.Namespace, provider: Provider) -> int:
    admin = provider.directory()
    if args.action == "list":
        groups = admin.groups()
        rows = [
            "  " * g.depth + g.path.rsplit("/", 1)[-1] + (f"  [{', '.join(g.roles)}]" if g.roles else "")
            for g in groups
        ]
        _out(args, [{"path": g.path, "roles": list(g.roles)} for g in groups], "\n".join(rows) or "(no groups)")
    elif args.action == "add":
        group = admin.create_group(args.path)
        _out(args, {"path": group.path}, f"Group {group.path} exists.")
    elif args.action == "members":
        names = admin.members(args.path)
        _out(args, names, "\n".join(names) or "(no members)")
    elif args.action == "add-member":
        admin.add_member(args.path, args.username)
        _out(args, {"ok": True}, f"{args.username} is a member of {args.path}.")
    elif args.action == "remove-member":
        admin.remove_member(args.path, args.username)
        _out(args, {"ok": True}, f"{args.username} is no longer a member of {args.path}.")
    elif args.action == "grant-role":
        admin.grant_role_to_group(args.path, args.role)
        _out(args, {"ok": True}, f"Members of {args.path} and its subgroups hold {args.role}.")
    return 0


def _roles(args: argparse.Namespace, provider: Provider) -> int:
    if args.action == "provision":
        report = provider.provision_roles(
            _read_list(args.file, "roles"), args.catalyst_client, tuple(args.login_client or ("catalyst-cli",))
        )
        _out(args, report.__dict__, f"{len(report.created)} created, {len(report.kept)} already there")
        return 0
    admin = provider.directory()
    if args.action == "list":
        roles = admin.roles()
        _out(args, [{"name": n, "description": d} for n, d in roles], "\n".join(f"{n:<20} {d}" for n, d in roles))
    elif args.action == "add":
        admin.create_role(args.name, args.description)
        _out(args, {"ok": True}, f"Role {args.name} added.")
    elif args.action == "grant":
        admin.grant_role_to_user(args.username, args.role)
        _out(args, {"ok": True}, f"{args.username} holds {args.role}.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except CatalystUsersError as err:
        print(f"catalyst-users: error: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("catalyst-users: interrupted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
