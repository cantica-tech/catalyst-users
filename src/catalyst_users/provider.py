"""The facade (id-PROVIDER-000001..000005): one interface to whatever manages the people.

A pointer document chooses the backend by its registered name:

    {"provider": "keycloak", "issuer": "https://id.example.com/realms/catalyst",
     "client": "catalyst-cli", "catalyst_client": "catalyst"}

Providers are registered (id-PROVIDER-000005): the built-in ones are modules of `catalyst_users.providers`
(`keycloak`, `static`), and any installed package adds its own through the entry-point group
`catalyst_users.providers`, never replacing a built-in. `from_pointer` builds the provider; `whoami` says who is logged in, with their groups, roles and grants. A grant is
a client role of the catalyst client in the token: `cmd:<command>` (`cmd:*` every command) and
`reconcile:full|propose`. The backend resolves composites and groups, so no client needs an admin secret.
"""

from __future__ import annotations

import importlib
import importlib.metadata
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


class ProviderError(CatalystUsersError):
    """A pointer that names no usable backend."""


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
    return Whoami(
        issuer=str(claims.get("iss") or issuer),
        subject=str(claims["sub"]),
        username=username,
        name=str(claims.get("name") or given or username),
        email=claims.get("email"),
        groups=tuple(sorted("/" + str(g).strip("/") for g in claims.get("groups") or ())),
        roles=tuple(sorted(str(r) for r in (claims.get("realm_access") or {}).get("roles") or ())),
        grants=tuple(sorted(str(r) for r in access.get("roles") or ())),
    )


class Provider(Protocol):
    """What a provider does. An operation it cannot do raises `ProviderError` saying so (`unsupported`)."""

    kind: str
    issuer: str

    # people, with their own rights
    def login(self, show: Callable[[Any], None]) -> Whoami: ...
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

    # the local system account (id-AUTH-000006)
    def system_token(self) -> dict[str, Any]: ...
    def system_whoami(self) -> Whoami: ...


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
