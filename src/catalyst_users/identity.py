"""Who someone is, as the identity provider says: groups, roles, signer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


def _group_path(path: str) -> str:
    return "/" + path.strip("/")


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    username: str
    name: str
    email: str | None = None
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    client_id: str | None = None
    expires_at: float | None = None

    @classmethod
    def from_claims(cls, claims: dict[str, Any], issuer: str | None = None) -> Identity:
        username = claims.get("preferred_username") or claims.get("username") or claims["sub"]
        given_family = " ".join(p for p in (claims.get("given_name"), claims.get("family_name")) if p)
        realm_access = claims.get("realm_access") or {}
        return cls(
            issuer=claims.get("iss") or issuer or "",
            subject=claims["sub"],
            username=username,
            name=claims.get("name") or given_family or username,
            email=claims.get("email"),
            groups=tuple(sorted(_group_path(g) for g in claims.get("groups") or ())),
            roles=tuple(sorted(realm_access.get("roles") or ())),
            client_id=claims.get("client_id") or claims.get("azp"),
            expires_at=claims.get("exp"),
        )

    def has_role(self, role: str) -> bool:
        """`role` among the effective realm roles (Keycloak resolves group inheritance, id-DIR-000003)."""
        return role in self.roles

    def in_group(self, path: str) -> bool:
        """Member of `path` or of any group under it (id-DIR-000003)."""
        wanted = _group_path(path)
        return any(g == wanted or g.startswith(wanted + "/") for g in self.groups)

    def signer(self, at: datetime | None = None) -> dict[str, str]:
        """The permanent record of this person signing something (id-SIGN-000001):
        `iss` + `sub` identify them; username and name are a snapshot."""
        moment = (at or datetime.now(UTC)).astimezone(UTC)
        return {
            "iss": self.issuer,
            "sub": self.subject,
            "username": self.username,
            "name": self.name,
            "at": moment.isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
