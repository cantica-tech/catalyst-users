"""The facade (id-PROVIDER-000001..000004): one interface to whatever manages the people.

A pointer document chooses the backend:

    {"provider": "keycloak", "issuer": "https://id.example.com/realms/catalyst",
     "client": "catalyst-cli", "catalyst_client": "catalyst"}

`from_pointer` builds the provider; `whoami` says who is logged in, with their groups, roles and grants. A grant is
a client role of the catalyst client in the token: `cmd:<command>` (`cmd:*` every command) and
`reconcile:full|propose`. The backend resolves composites and groups, so no client needs an admin secret.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
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
    kind: str
    issuer: str

    def login(self, show: Callable[[Any], None]) -> Whoami: ...
    def logout(self) -> str | None: ...
    def whoami(self, username: str | None = None) -> Whoami: ...
    def users(self) -> list[dict[str, Any]]: ...
    def groups(self) -> list[dict[str, Any]]: ...
    def roles(self) -> list[dict[str, Any]]: ...


# --- Keycloak --------------------------------------------------------------------------
@dataclass
class KeycloakProvider:
    """A Keycloak realm, reached with the device login and userinfo; the directory through the admin API with the
    logged-in person's own rights."""

    issuer: str
    client: str = "catalyst-cli"
    catalyst_client: str = DEFAULT_CATALYST_CLIENT
    store: Path | None = None
    transport: Any = None
    timeout: float = 10.0
    kind: str = field(default="keycloak", init=False)

    def _session(self):
        from catalyst_users.credentials import CredentialStore
        from catalyst_users.http import Http
        from catalyst_users.oidc import OIDCClient
        from catalyst_users.session import Session

        oidc = OIDCClient(self._settings(), Http(self.transport, timeout=self.timeout))  # type: ignore[arg-type]
        return Session(oidc, CredentialStore(self.store))

    def _settings(self):
        return _IssuerSettings(self.issuer.rstrip("/"), self.client, timeout=self.timeout)

    def login(self, show: Callable[[Any], None]) -> Whoami:
        self._session().login(show)
        return self.whoami()

    def logout(self) -> str | None:
        return self._session().logout()

    def whoami(self, username: str | None = None) -> Whoami:
        session = self._session()
        claims = session.oidc.userinfo(session.access_token())
        who = whoami_from_claims(claims, self.issuer.rstrip("/"), self.catalyst_client)
        if username and username.lower() not in {who.username.lower(), who.subject}:
            raise ProviderError(f"logged in as {who.username}, not {username}: log in as them first")
        return who

    def _admin(self):
        from catalyst_users.admin import KeycloakAdmin
        from catalyst_users.http import Http

        session = self._session()
        base, realm = self.issuer.rstrip("/").rsplit("/realms/", 1)
        settings = _AdminSettings(f"{base}/admin/realms/{realm}", self.timeout)
        return KeycloakAdmin(settings, session.access_token, Http(self.transport, timeout=self.timeout))  # type: ignore[arg-type]

    def users(self) -> list[dict[str, Any]]:
        return [u.__dict__ for u in self._admin().list_users()]

    def groups(self) -> list[dict[str, Any]]:
        return [{"path": g.path, "roles": list(g.roles)} for g in self._admin().groups()]

    def roles(self) -> list[dict[str, Any]]:
        return [{"name": n, "description": d} for n, d in self._admin().roles()]


@dataclass(frozen=True)
class _IssuerSettings:
    """What the OIDC client reads, for an issuer given whole."""

    issuer: str
    client_id: str
    api_client_id: str = "catalyst-api"
    api_client_secret: str | None = None
    timeout: float = 10.0


@dataclass(frozen=True)
class _AdminSettings:
    admin_url: str
    timeout: float = 10.0


# --- static, for tests ----------------------------------------------------------------
@dataclass
class StaticProvider:
    """People declared in the pointer, verified by nothing (id-PROVIDER-000004): for tests only.

    `people`: `{username, name, groups, roles}`; `roles`: `{id, name, grants}` (a role's grants are `cmd:…` and
    `reconcile:…`, as the token would carry them). The logged-in person is the one named, else the only one."""

    issuer: str = "static:"
    people: list[dict[str, Any]] = field(default_factory=list)
    role_defs: list[dict[str, Any]] = field(default_factory=list)
    kind: str = field(default="static", init=False)

    def login(self, show: Callable[[Any], None]) -> Whoami:
        return self.whoami()

    def logout(self) -> str | None:
        return None

    def whoami(self, username: str | None = None) -> Whoami:
        if username:
            wanted = username.strip().lower()
            found = [p for p in self.people if wanted in {str(p.get(k, "")).lower() for k in ("username", "name")}]
        else:
            found = [p for p in self.people if p.get("active", True)]
        if len(found) != 1:
            raise ProviderError("name who is signing" if not username else f"no declared person {username!r}")
        person = found[0]
        if not person.get("active", True):
            raise ProviderError(f"{person['username']} is disabled")
        roles = tuple(sorted(str(r) for r in person.get("roles") or ()))
        grants = {g for r in self.role_defs if str(r.get("id")) in roles for g in r.get("grants") or ()}
        return Whoami(
            issuer=self.issuer,
            subject=str(person.get("subject") or person["username"]),
            username=str(person["username"]),
            name=str(person.get("name") or person["username"]),
            email=person.get("email"),
            groups=tuple(sorted(person.get("groups") or ())),
            roles=roles,
            grants=tuple(sorted(grants)),
        )

    def users(self) -> list[dict[str, Any]]:
        return [dict(p) for p in self.people]

    def groups(self) -> list[dict[str, Any]]:
        paths = sorted({g for p in self.people for g in p.get("groups") or ()})
        return [{"path": g, "roles": []} for g in paths]

    def roles(self) -> list[dict[str, Any]]:
        return [{"name": r.get("id"), "description": r.get("name") or ""} for r in self.role_defs]


# --- the pointer ---------------------------------------------------------------------
def from_pointer(doc: dict[str, Any], store: Path | None = None, transport: Any = None) -> Provider:
    """The backend a pointer document names (id-PROVIDER-000001)."""
    kind = str(doc.get("provider") or "")
    if kind == "keycloak":
        if not doc.get("issuer"):
            raise ProviderError('a "keycloak" pointer needs an "issuer"')
        return KeycloakProvider(
            issuer=str(doc["issuer"]),
            client=str(doc.get("client") or "catalyst-cli"),
            catalyst_client=str(doc.get("catalyst_client") or DEFAULT_CATALYST_CLIENT),
            store=store,
            transport=transport,
        )
    if kind == "static":
        if os.environ.get(STATIC_FLAG) != "1":
            raise ProviderError(f'the "static" provider verifies nobody: it is for tests only ({STATIC_FLAG}=1)')
        return StaticProvider(people=list(doc.get("people") or []), role_defs=list(doc.get("roles") or []))
    raise ProviderError(f"unknown provider {kind!r} (keycloak, static)")


def pointer_problems(doc: Any) -> list[str]:
    """What is wrong with a pointer document, for a client's checks."""
    if not isinstance(doc, dict):
        return ["the pointer is not a JSON object"]
    kind = doc.get("provider")
    if kind not in ("keycloak", "static"):
        return [f"unknown provider {kind!r} (keycloak, static)"]
    if kind == "keycloak" and not doc.get("issuer"):
        return ['a "keycloak" pointer needs an "issuer"']
    if kind == "static":
        return ['the "static" provider verifies nobody: for tests only']
    return []
