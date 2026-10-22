"""`catalyst-users`: log in, see who you are, and manage the directory.

Exit codes: 0 done, 1 refused or failed, 2 usage.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence
from typing import Any

from catalyst_users import __version__, config
from catalyst_users.admin import KeycloakAdmin
from catalyst_users.errors import CatalystUsersError
from catalyst_users.oidc import DeviceCode, OIDCClient
from catalyst_users.session import Session


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="catalyst-users", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"catalyst-users {__version__}")
    p.add_argument("--server", dest="server_url", help="identity provider URL (default: http://localhost:8080)")
    p.add_argument("--realm", help="realm (default: catalyst)")
    p.add_argument("--client-id", help="public client for login (default: catalyst-cli)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("login", help="log in with a code shown in your browser")
    sub.add_parser("logout", help="revoke your session and delete local credentials")
    sub.add_parser("whoami", help="who you are: groups and roles")
    sub.add_parser("token", help="print a fresh access token (keep it secret)")

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
    return p


def _show_code(code: DeviceCode) -> None:
    print(f"Open {code.verification_uri_complete or code.verification_uri}")
    print(f"and confirm the code {code.user_code}. Waiting…", flush=True)


def _out(args: argparse.Namespace, data: Any, text: str) -> None:
    print(json.dumps(data, indent=2) if args.json else text)


def _run(args: argparse.Namespace) -> int:
    settings = config.load({"server_url": args.server_url, "realm": args.realm, "client_id": args.client_id})
    session = Session(OIDCClient(settings))

    if args.command == "login":
        who = session.login(_show_code)
        _out(args, who.signer(), f"Logged in as {who.username} ({who.name}).")
        return 0
    if args.command == "logout":
        warning = session.logout()
        if warning:
            print(f"catalyst-users: warning: {warning}", file=sys.stderr)
        print("Logged out.")
        return 0
    if args.command == "whoami":
        who = session.identity()
        data = {**who.signer(), "email": who.email, "groups": list(who.groups), "roles": list(who.roles)}
        text = "\n".join(
            [
                f"{who.username} ({who.name})",
                f"  subject  {who.subject}",
                f"  issuer   {who.issuer}",
                f"  groups   {', '.join(who.groups) or '-'}",
                f"  roles    {', '.join(who.roles) or '-'}",
            ]
        )
        _out(args, data, text)
        return 0
    if args.command == "token":
        print(session.access_token())  # printed only on this explicit request (id-AUTH-000002)
        return 0

    admin = KeycloakAdmin(settings, session.access_token)
    return {"users": _users, "groups": _groups, "roles": _roles}[args.command](args, admin)


def _users(args: argparse.Namespace, admin: KeycloakAdmin) -> int:
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


def _groups(args: argparse.Namespace, admin: KeycloakAdmin) -> int:
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


def _roles(args: argparse.Namespace, admin: KeycloakAdmin) -> int:
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
