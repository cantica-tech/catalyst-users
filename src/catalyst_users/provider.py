"""The facade (id-PROVIDER-000001..000005): one interface to whatever manages the people.

A pointer document chooses the backend by its registered name:

    {"provider": "keycloak", "issuer": "https://id.example.com/realms/catalyst",
     "client": "catalyst-cli", "catalyst_client": "catalyst"}

Providers are registered (id-PROVIDER-000005): the built-in ones are modules of `catalyst_users.providers`
(`keycloak`, `static`), and any installed package adds its own through the entry-point group
`catalyst_users.providers`, never replacing a built-in. `from_pointer` builds the provider; `whoami` says who is logged in, with their groups, roles and grants. A grant is
a client role of the catalyst client in the token: `cmd:<command>` (`cmd:*` every command) and
`reconcile:full|propose`. The backend resolves composites and groups, so no client needs an admin secret.

A criterion has admins (id-DIR-000005, id-PROVIDER-000008): `whoami` reports the criteria someone administers
(`administers`), never as a grant, since a grant would hold in every criterion; a client gives an admin's rights only
in a criterion that list names. It has members (id-DIR-000006): `members`, `is_member` (asked of the provider now,
never read from a token), `add_member` and `remove_member`; membership grants no command.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import re
import shlex
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from catalyst_users.errors import CatalystUsersError

STATIC_FLAG = "CATALYST_ALLOW_STATIC_IDENTITY"
CMD, RECONCILE = "cmd:", "reconcile:"
LEVELS = ("none", "propose", "full")
DEFAULT_CATALYST_CLIENT = "catalyst"
# Criteria (id-DIR-000005): the realm role of a criterion's admins, and where a group-based provider keeps criteria.
CRITERION_ADMIN = "criterion-admin"
CRITERIA_GROUP = "/criteria"
CRITERION_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


class ProviderError(CatalystUsersError):
    """A pointer that names no usable backend."""


def criterion_name(name: str) -> str:
    """A criterion's name as catalyst names a project (`project_name`): lower case, digits, `.`, `_` and `-`."""
    if not CRITERION_NAME.match(name or ""):
        raise ProviderError(f"{name!r} is not a criterion name (lower case letters, digits, '.', '_', '-')")
    return name


def administers_from_groups(groups: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """The criteria whose admins group (`/criteria/<name>/admins`) is among `groups`, exactly: a subgroup of it is
    not an admin."""
    prefix = CRITERIA_GROUP + "/"
    found = set()
    for group in groups:
        path = "/" + str(group).strip("/")
        parts = path[len(prefix) :].split("/") if path.startswith(prefix) else []
        if len(parts) == 2 and parts[0] and parts[1] == "admins":
            found.add(parts[0])
    return tuple(sorted(found))


@dataclass(frozen=True)
class Whoami:
    issuer: str
    subject: str
    username: str
    name: str
    email: str | None = None
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    grants: tuple[str, ...] = ()
    administers: tuple[str, ...] = ()

    def administers_criterion(self, name: str) -> bool:
        """An admin of the criterion `name` (id-DIR-000005); the catalyst-admin's rights are their grants."""
        return name in self.administers

    @property
    def commands(self) -> tuple[str, ...]:
        """The commands granted (`*` for every one), without the `cmd:` prefix."""
        return tuple(g[len(CMD) :] for g in self.grants if g.startswith(CMD))

    @property
    def reconciliation(self) -> str:
        """The highest reconciliation level granted: `full`, `propose` or `none`."""
        held = {g[len(RECONCILE) :] for g in self.grants if g.startswith(RECONCILE)}
        return max((lvl for lvl in LEVELS if lvl in held), key=LEVELS.index, default="none")

    def signer(self, at: datetime | None = None) -> dict[str, str]:
        """The permanent record of this identity signing something (id-SIGN-000001): `iss` + `sub` identify it."""
        moment = (at or datetime.now(UTC)).astimezone(UTC)
        return {
            "iss": self.issuer,
            "sub": self.subject,
            "username": self.username,
            "name": self.name,
            "at": moment.isoformat(timespec="seconds").replace("+00:00", "Z"),
        }

    def grants_command(self, command: str) -> bool:
        return "*" in self.commands or command.lstrip("/") in self.commands


def whoami_from_claims(claims: dict[str, Any], issuer: str, catalyst_client: str) -> Whoami:
    username = str(claims.get("preferred_username") or claims["sub"])
    given = " ".join(p for p in (claims.get("given_name"), claims.get("family_name")) if p)
    access = (claims.get("resource_access") or {}).get(catalyst_client) or {}
    groups = tuple(sorted("/" + str(g).strip("/") for g in claims.get("groups") or ()))
    return Whoami(
        issuer=str(claims.get("iss") or issuer),
        subject=str(claims["sub"]),
        username=username,
        name=str(claims.get("name") or given or username),
        email=claims.get("email"),
        groups=groups,
        roles=tuple(sorted(str(r) for r in (claims.get("realm_access") or {}).get("roles") or ())),
        grants=tuple(sorted(str(r) for r in access.get("roles") or ())),
        administers=administers_from_groups(groups),
    )


class Provider(Protocol):
    """What a provider does. An operation it cannot do raises `ProviderError` saying so (`unsupported`)."""

    kind: str
    issuer: str

    # people, with their own rights
    def login(self, show: Callable[[Any], None]) -> Whoami: ...
    def login_password(self, username: str, password: str) -> Whoami: ...
    def logout(self) -> str | None: ...
    def whoami(self, username: str | None = None) -> Whoami: ...
    def token(self) -> str: ...
    def users(self) -> list[dict[str, Any]]: ...
    def groups(self) -> list[dict[str, Any]]: ...
    def roles(self) -> list[dict[str, Any]]: ...

    # the directory, for the CLI's users/groups/roles commands (id-DIR-000001..000004)
    def directory(self) -> Any: ...
    def provision_roles(
        self, roles: list[dict[str, Any]], catalyst_client: str, login_clients: tuple[str, ...]
    ) -> Any: ...
    def import_users(self, users: list[dict[str, Any]], roles: list[dict[str, Any]]) -> Any: ...

    # criteria and their admins, with the caller's own rights (id-DIR-000005, id-PROVIDER-000008)
    def criteria(self) -> list[dict[str, Any]]: ...  # [{"name", "admins": [username, …] or None if not visible}]
    def add_criterion(self, name: str, admin: str | None = None) -> Any: ...
    def appoint(self, name: str, username: str) -> None: ...
    def dismiss(self, name: str, username: str) -> None: ...

    # a criterion's members (id-DIR-000006): asked of the provider now, never read from a token; `system=True` is a
    # server asking with the local system account's rights, having verified its caller itself
    def members(self, name: str, *, system: bool = False) -> list[str]: ...
    def is_member(self, name: str, username: str, *, system: bool = False) -> bool: ...
    def add_member(self, name: str, username: str, *, system: bool = False) -> None: ...
    def remove_member(self, name: str, username: str, *, system: bool = False) -> None: ...

    # the local system account: setup's admin (id-AUTH-000006). A provider class also has
    # `setup(settings, username, password, ask_server_admin, transport=None, criteria=()) -> SetupOutcome`
    # (id-PROVIDER-000006): it readies the provider for criteria and adds `criteria`, setup's admin appointed.
    def system_token(self) -> dict[str, Any]: ...
    def system_whoami(self) -> Whoami: ...


@dataclass(frozen=True)
class SetupOutcome:
    """What setup found (id-PROVIDER-000006): `unreachable`, `created` or `authenticated`; the provider settings to
    store in IAM/settings.json (never a realm definition or a secret); and a sentence saying so."""

    outcome: str
    provider: dict[str, Any]
    note: str


def secret_from_command(command: str | list[str], what: str) -> str:
    """The first line a command prints, run without a shell; never shown, even in an error."""
    argv = command if isinstance(command, list) else shlex.split(command)
    shown = argv[0] if argv else "(empty)"
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise ProviderError(f"{what} ({shown}) failed: {exc}") from None
    secret = done.stdout.split("\n", 1)[0].rstrip("\r")
    if done.returncode != 0 or not secret:
        reason = f"exit {done.returncode}" if done.returncode else "it printed nothing"
        raise ProviderError(f"{what} ({shown}) gave no secret: {reason}")
    return secret


def unsupported(kind: str, what: str) -> ProviderError:
    return ProviderError(f"the {kind} provider does not support {what}")


@dataclass(frozen=True)
class Registration:
    name: str
    target: str  # "module:attribute"
    source: str  # "built-in", or the distribution that registers it


ENTRY_POINT_GROUP = "catalyst_users.providers"
BUILT_IN = {
    "keycloak": "catalyst_users.providers.keycloak:KeycloakProvider",
    "static": "catalyst_users.providers.static:StaticProvider",
}


def registered() -> dict[str, Registration]:
    """Every provider by name: the built-in ones, then those installed packages register (id-PROVIDER-000005).
    An entry point never replaces a built-in provider of the same name."""
    found = {name: Registration(name, target, "built-in") for name, target in BUILT_IN.items()}
    for ep in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP):
        if ep.name not in found:
            dist = getattr(ep, "dist", None)
            found[ep.name] = Registration(ep.name, ep.value, getattr(dist, "name", None) or "entry point")
    return found


def provider_class(name: str) -> Any:
    """The class registered as `name`: `from_pointer(doc, store=…, transport=…)` builds it, `problems(doc)` checks."""
    known = registered()
    if name not in known:
        raise ProviderError(f"unknown provider {name!r} ({', '.join(known)})")
    module, _, attr = known[name].target.partition(":")
    try:
        target = getattr(importlib.import_module(module), attr)
    except (ImportError, AttributeError) as exc:
        raise ProviderError(f"the provider {name!r} ({known[name].target}) cannot be loaded: {exc}") from None
    return target


# --- the pointer ---------------------------------------------------------------------
def from_pointer(doc: dict[str, Any], store: Path | None = None, transport: Any = None) -> Provider:
    """The backend a pointer document names (id-PROVIDER-000001), through the registry."""
    return provider_class(str(doc.get("provider") or "")).from_pointer(doc, store=store, transport=transport)


def pointer_problems(doc: Any) -> list[str]:
    """What is wrong with a pointer document, for a client's checks."""
    if not isinstance(doc, dict):
        return ["the pointer is not a JSON object"]
    try:
        cls = provider_class(str(doc.get("provider") or ""))
    except ProviderError as err:
        return [str(err)]
    return list(cls.problems(doc))


def __getattr__(name: str) -> Any:
    """The built-in providers, still importable from here."""
    if name == "KeycloakProvider":
        from catalyst_users.providers.keycloak import KeycloakProvider

        return KeycloakProvider
    if name == "StaticProvider":
        from catalyst_users.providers.static import StaticProvider

        return StaticProvider
    raise AttributeError(name)
