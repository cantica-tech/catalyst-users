"""The static provider, built in: people declared in the pointer, verified by nothing (id-PROVIDER-000004).

For tests only: it is refused unless `CATALYST_ALLOW_STATIC_IDENTITY=1`.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from catalyst_users.provider import (
    STATIC_FLAG,
    ProviderError,
    Whoami,
    administers_from_groups,
    criterion_name,
    unsupported,
)


@dataclass
class StaticProvider:
    """People declared in the pointer, verified by nothing (id-PROVIDER-000004): for tests only.

    `people`: `{username, name, groups, roles}`; `roles`: `{id, name, grants}` (a role's grants are `cmd:…` and
    `reconcile:…`, as the token would carry them). The logged-in person is the one named, else the only one. A
    person administers the criteria of their `/criteria/<name>/admins` groups (id-DIR-000005) and is a member of those
    of their `/criteria/<name>/members` groups (id-DIR-000006)."""

    issuer: str = "static:"
    people: list[dict[str, Any]] = field(default_factory=list)
    role_defs: list[dict[str, Any]] = field(default_factory=list)
    kind: str = field(default="static", init=False)

    @classmethod
    def from_pointer(
        cls, doc: dict[str, Any], store: Path | None = None, transport: Any = None, credentials: Path | None = None
    ) -> StaticProvider:
        if os.environ.get(STATIC_FLAG) != "1":
            raise ProviderError(f'the "static" provider verifies nobody: it is for tests only ({STATIC_FLAG}=1)')
        return cls(people=list(doc.get("people") or []), role_defs=list(doc.get("roles") or []))

    @classmethod
    def setup(
        cls,
        settings: dict[str, Any],
        username: str,
        password: str,
        ask_server_admin: Any,
        transport: Any = None,
        **_: Any,
    ):
        raise unsupported("static", "setup")

    @staticmethod
    def problems(doc: dict[str, Any]) -> list[str]:
        return ['the "static" provider verifies nobody: for tests only']

    def login(self, show: Callable[[Any], None]) -> Whoami:
        return self.whoami()

    def login_password(self, username: str, password: str) -> Whoami:
        raise unsupported(self.kind, "a password login")

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
        groups = tuple(sorted(person.get("groups") or ()))
        return Whoami(
            issuer=self.issuer,
            subject=str(person.get("subject") or person["username"]),
            username=str(person["username"]),
            name=str(person.get("name") or person["username"]),
            email=person.get("email"),
            groups=groups,
            roles=roles,
            grants=tuple(sorted(grants)),
            administers=administers_from_groups(groups),
        )

    def users(self) -> list[dict[str, Any]]:
        return [dict(p) for p in self.people]

    def groups(self) -> list[dict[str, Any]]:
        paths = sorted({g for p in self.people for g in p.get("groups") or ()})
        return [{"path": g, "roles": []} for g in paths]

    def roles(self) -> list[dict[str, Any]]:
        return [{"name": r.get("id"), "description": r.get("name") or ""} for r in self.role_defs]

    def token(self) -> str:
        raise unsupported(self.kind, "tokens")

    def directory(self) -> Any:
        raise unsupported(self.kind, "directory changes")

    def provision_roles(self, roles: list[dict[str, Any]], catalyst_client: str, login_clients: tuple[str, ...]) -> Any:
        raise unsupported(self.kind, "provisioning roles")

    def import_users(self, users: list[dict[str, Any]], roles: list[dict[str, Any]]) -> Any:
        raise unsupported(self.kind, "importing users")

    def criteria(self) -> list[dict[str, Any]]:
        names = sorted({c for p in self.people for c in administers_from_groups(p.get("groups") or ())})
        return [
            {
                "name": c,
                "admins": sorted(
                    p["username"] for p in self.people if c in administers_from_groups(p.get("groups") or ())
                ),
            }
            for c in names
        ]

    def add_criterion(self, name: str, admin: str | None = None) -> Any:
        raise unsupported(self.kind, "adding criteria")

    def appoint(self, name: str, username: str) -> None:
        raise unsupported(self.kind, "appointing admins")

    def dismiss(self, name: str, username: str) -> None:
        raise unsupported(self.kind, "dismissing admins")

    def members(self, name: str, *, system: bool = False) -> list[str]:
        group = f"/criteria/{criterion_name(name)}/members"
        return sorted(
            p["username"] for p in self.people if group in {"/" + str(g).strip("/") for g in p.get("groups") or ()}
        )

    def is_member(self, name: str, username: str, *, system: bool = False) -> bool:
        return username in self.members(name)

    def add_member(self, name: str, username: str, *, system: bool = False) -> None:
        raise unsupported(self.kind, "changing members")

    def remove_member(self, name: str, username: str, *, system: bool = False) -> None:
        raise unsupported(self.kind, "changing members")

    def system_token(self) -> dict[str, Any]:
        raise unsupported(self.kind, "a system account")

    def system_whoami(self) -> Whoami:
        raise unsupported(self.kind, "a system account")
