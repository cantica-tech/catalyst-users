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
    st = sub.add_parser("setup", help="write IAM/settings.json: check, create or sign in to the provider")
    st.add_argument("--type", help="the provider's registered name, e.g. keycloak")
    st.add_argument("--provider", dest="provider_json", help="the provider's settings: a JSON file, or JSON")
    st.add_argument("--username", help="the admin's username (the local system account)")
    st.add_argument("--password-command", help="a command printing the admin's password (else it is asked for)")
    st.add_argument("--server-admin", help="the provider's own server admin, if the realm must be created")
    st.add_argument("--server-admin-password-command", help="a command printing the server admin's password")
    st.add_argument("--email", help="the admin's email, if the realm and its admin must be created")
    st.add_argument("--first-name", help="the admin's first name (default: from `git config user.name`)")
    st.add_argument("--last-name", help="the admin's last name (default: from `git config user.name`)")
    st.add_argument("--force", action="store_true", help="replace an existing IAM/settings.json")
    st.add_argument(
        "--criterion",
        action="append",
        default=[],
        help="a criterion to add, the admin appointed to it (repeatable; catalyst's deployments' project names)",
    )
    li = sub.add_parser("login", help="log in with a code shown in your browser, or --password")
    li.add_argument(
        "--password",
        action="store_true",
        help="log in with your username and password instead: read from standard input, else asked (id-AUTH-000007)",
    )
    li.add_argument("--username", help="with --password: who logs in (asked when not given)")
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
    u = users.add_parser("update", help="change a user's email or names (never the username)")
    u.add_argument("username")
    u.add_argument("--email")
    u.add_argument("--first-name")
    u.add_argument("--last-name")
    for action, text in (("disable", "disable a user (users are never deleted)"), ("enable", "enable a user again")):
        users.add_parser(action, help=text).add_argument("username")
    users.add_parser("groups", help="a user's groups").add_argument("username")
    users.add_parser("roles", help="a user's realm roles: direct, or through which groups").add_argument("username")

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
    roles.add_parser("holders", help="who holds a realm role: users, directly or through which groups").add_argument(
        "name"
    )
    r = roles.add_parser("grant", help="grant a realm role to a user")
    r.add_argument("username")
    r.add_argument("role")
    r = roles.add_parser("provision", help="write a catalyst roles document: roles, their grants, the claim mapper")
    r.add_argument("file", help="a catalyst roles document (roles.json, or the kernel's roles template)")
    r.add_argument("--catalyst-client", default="catalyst", help="the client whose roles are the grants")
    r.add_argument(
        "--login-client", action="append", help="a client whose tokens carry the grants (default: catalyst-cli)"
    )
    criteria = sub.add_parser("criteria", help="criteria and their admins").add_subparsers(dest="action", required=True)
    criteria.add_parser("list", help="the criteria you may see, with their admins")
    c = criteria.add_parser("add", help="add a criterion (the catalyst-admin's); again, it covers its new groups")
    c.add_argument("name", help="the criterion's name: its deployment's project_name")
    c.add_argument("--admin", help="appoint this user its admin")
    criteria.add_parser("admins", help="a criterion's admins").add_argument("name")
    criteria.add_parser(
        "members", help="a criterion's members (catalyst changes them, recording each change)"
    ).add_argument("name")
    for action, text in (
        ("appoint", "make a user an admin of a criterion"),
        ("dismiss", "a user no longer administers it"),
    ):
        c = criteria.add_parser(action, help=text)
        c.add_argument("name")
        c.add_argument("username")

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
    try:
        return from_pointer(config.pointer(overrides, pointer_file=args.pointer))
    except config.NoSettingsError:
        if not sys.stdin.isatty():
            raise
        print("catalyst-users: no IAM settings yet: setting up.", file=sys.stderr)
        _setup(args)
        return from_pointer(config.pointer(overrides, pointer_file=args.pointer))


# --- setup (id-PROVIDER-000006) -------------------------------------------------------------
def _ask(question: str, given: str | None, default: str | None = None) -> str:
    if given:
        return given
    if not sys.stdin.isatty():
        raise CatalystUsersError(f"setup needs {question.lower()} (no terminal to ask: pass it as an option)")
    hint = f" [{default}]" if default else ""
    answer = input(f"{question}{hint}: ").strip() or (default or "")
    if not answer:
        raise CatalystUsersError(f"setup needs {question.lower()}")
    return answer


def _provider_settings(value: str) -> dict[str, Any]:
    path = Path(value).expanduser()
    try:
        doc = json.loads(path.read_text(encoding="utf-8") if path.is_file() else value)
    except (OSError, ValueError) as exc:
        raise CatalystUsersError(f"the provider settings are neither a JSON file nor JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise CatalystUsersError("the provider settings are not a JSON object")
    return doc


def _password(command: str | None, prompt: str) -> tuple[str, str | None]:
    """The password and the command that printed it; a typed password has no command (yet)."""
    from catalyst_users.provider import secret_from_command

    if command is None and sys.stdin.isatty():
        command = input(f"{prompt}: a command printing it (Enter to type it instead): ").strip() or None
    if command:
        return secret_from_command(command, prompt), command
    if not sys.stdin.isatty():
        raise CatalystUsersError(f"setup needs {prompt.lower()}'s command (no terminal to ask)")
    password = getpass.getpass(f"{prompt}: ")
    if not password:
        raise CatalystUsersError(f"setup needs {prompt.lower()}")
    return password, None


def _credentials(username: str | None) -> tuple[str, str]:
    """A password login's username and password (id-AUTH-000007): the password one line of standard input when it is
    not a terminal, else asked without echo; never an argument, never shown."""
    if not username:
        if not sys.stdin.isatty():
            raise CatalystUsersError("login --password needs --username when standard input is not a terminal")
        username = input("Username: ").strip()
    password = sys.stdin.readline().rstrip("\r\n") if not sys.stdin.isatty() else getpass.getpass("Password: ")
    if not username or not password:
        raise CatalystUsersError("login --password needs a username and a password")
    return username, password


def _setup(args: argparse.Namespace) -> int:
    from catalyst_users import keychain
    from catalyst_users.provider import provider_class

    path = config.settings_file()
    if path.exists() and not getattr(args, "force", False):
        raise CatalystUsersError(f"{path} exists: pass --force to replace it")
    names = ", ".join(registered())
    kind = _ask(f"Provider type ({names})", getattr(args, "type", None), "keycloak")
    cls = provider_class(kind)
    settings = _provider_settings(
        _ask("Provider settings (a JSON file, or JSON)", getattr(args, "provider_json", None))
    )
    username = _ask("Admin username", getattr(args, "username", None))
    password, command = _password(getattr(args, "password_command", None), "The admin's password")

    def server_admin() -> tuple[str, str]:
        user = _ask("The provider's server admin username", getattr(args, "server_admin", None))
        secret, _ = _password(getattr(args, "server_admin_password_command", None), "The server admin's password")
        return user, secret

    def profile() -> dict[str, str]:
        import subprocess

        git = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, check=False).stdout.split()
        return {
            "email": _ask("The admin's email", getattr(args, "email", None)),
            "first_name": _ask(
                "The admin's first name", getattr(args, "first_name", None), git[0] if git else username
            ),
            "last_name": _ask(
                "The admin's last name",
                getattr(args, "last_name", None),
                " ".join(git[1:]) if len(git) > 1 else username,
            ),
        }

    criteria = tuple(getattr(args, "criterion", None) or ())
    outcome = cls.setup(settings, username, password, server_admin, ask_profile=profile, criteria=criteria)
    if command is None:  # typed: into the keychain, and the command reading it into settings.json
        where = outcome.provider.get("url") or kind
        realm = outcome.provider.get("realm")
        command = keychain.store(f"{username}@{where}" + (f"/{realm}" if realm else ""), password)
    written = config.write_settings(
        {"type": kind, "username": username, "provider": outcome.provider, "password_command": command}
    )
    _out(
        args,
        {"outcome": outcome.outcome, "settings": str(written), "type": kind, "username": username},
        f"{outcome.note}.\nWrote {written}.",
    )
    return 0


def _whoami(args: argparse.Namespace, who: Whoami) -> None:
    data = {**who.signer(), "email": who.email, "groups": list(who.groups), "roles": list(who.roles)}
    data["grants"] = list(who.grants)
    data["administers"] = list(who.administers)
    text = "\n".join(
        [
            f"{who.username} ({who.name})",
            f"  subject  {who.subject}",
            f"  issuer   {who.issuer}",
            f"  groups   {', '.join(who.groups) or '-'}",
            f"  roles    {', '.join(who.roles) or '-'}",
            f"  grants   {', '.join(who.grants) or '-'}",
            f"  administers {', '.join(who.administers) or '-'}",
        ]
    )
    _out(args, data, text)


def _run(args: argparse.Namespace) -> int:
    if args.command == "setup":
        return _setup(args)
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
        who = provider.login_password(*_credentials(args.username)) if args.password else provider.login(_show_code)
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

    return {"users": _users, "groups": _groups, "roles": _roles, "criteria": _criteria}[args.command](args, provider)


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
    elif args.action == "update":
        if args.email is None and args.first_name is None and args.last_name is None:
            raise CatalystUsersError("users update: give --email, --first-name or --last-name")
        user = admin.update_user(args.username, args.email, args.first_name, args.last_name)
        _out(args, user.__dict__, f"Updated {user.username}.")
    elif args.action in ("disable", "enable"):
        user = admin.set_enabled(args.username, args.action == "enable")
        _out(args, user.__dict__, f"{user.username} is {'enabled' if user.enabled else 'disabled'}.")
    elif args.action == "groups":
        paths = admin.user_groups(args.username)
        _out(args, paths, "\n".join(paths) or "(no groups)")
    elif args.action == "roles":
        held = admin.user_roles(args.username)
        _out(args, held, "\n".join(f"{r['name']:<24} {_how(r)}" for r in held) or "(no roles)")
    return 0


def _how(holding: dict) -> str:
    """How a role is held (id-DIR-000008): directly, through groups, or both."""
    return ", ".join((["direct"] if holding["direct"] else []) + [f"through {g}" for g in holding["groups"]])


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
    elif args.action == "holders":
        holders = admin.role_holders(args.name)
        rows = [f"{u['username']:<24} {_how(u)}" for u in holders["users"]]
        _out(args, holders, "\n".join(rows) or "(no holders)")
    elif args.action == "grant":
        admin.grant_role_to_user(args.username, args.role)
        _out(args, {"ok": True}, f"{args.username} holds {args.role}.")
    return 0


def _criteria(args: argparse.Namespace, provider: Provider) -> int:
    """Criteria and their admins (id-DIR-000005, id-PROVIDER-000008), through the facade, with your own rights."""
    if args.action == "list":
        found = provider.criteria()
        rows = [
            f"{c['name']:<24} {', '.join(c['admins']) if c['admins'] is not None else '(not visible)'}" for c in found
        ]
        _out(args, found, "\n".join(rows) or "(no criteria)")
    elif args.action == "add":
        added = provider.add_criterion(args.name, args.admin)
        _out(
            args,
            {"name": args.name, "added": added},
            f"Criterion {args.name}: " + (", ".join(added) or "already there"),
        )
    elif args.action == "admins":
        found = next((c for c in provider.criteria() if c["name"] == args.name), None)
        if found is None:
            raise CatalystUsersError(f"no criterion {args.name} (or you may not see it)")
        admins = found["admins"] or []
        _out(args, admins, "\n".join(admins) or "(no admins)")
    elif args.action == "members":
        members = provider.members(args.name)
        _out(args, members, "\n".join(members) or "(no members)")
    elif args.action == "appoint":
        provider.appoint(args.name, args.username)
        _out(args, {"ok": True}, f"{args.username} administers {args.name}.")
    elif args.action == "dismiss":
        provider.dismiss(args.name, args.username)
        _out(args, {"ok": True}, f"{args.username} no longer administers {args.name}.")
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
