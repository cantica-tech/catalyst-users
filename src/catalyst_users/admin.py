"""The directory: Keycloak's admin REST API with the caller's own token
(id-DIR-000001, id-DIR-000004). There is no way to delete a user (id-DIR-000002)."""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from catalyst_users.config import Settings
from catalyst_users.errors import AdminError, NotFoundError
from catalyst_users.http import Http, Response


@dataclass(frozen=True)
class User:
    id: str
    username: str
    email: str | None
    name: str
    enabled: bool

    @classmethod
    def from_rep(cls, rep: dict[str, Any]) -> User:
        name = " ".join(p for p in (rep.get("firstName"), rep.get("lastName")) if p)
        return cls(rep["id"], rep["username"], rep.get("email"), name, bool(rep.get("enabled", True)))


@dataclass(frozen=True)
class Group:
    id: str
    path: str
    roles: tuple[str, ...] = ()

    @property
    def depth(self) -> int:
        return self.path.count("/") - 1


def _path(path: str) -> str:
    return "/" + path.strip("/")


class KeycloakAdmin:
    def __init__(self, settings: Settings, token: Callable[[], str], http: Http | None = None) -> None:
        self.base = settings.admin_url
        self.token = token
        self.http = http or Http(timeout=settings.timeout)

    def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None) -> Response:
        resp = self.http.request(method, self.base + path, params=params, json_body=body, bearer=self.token())
        if resp.ok:
            return resp
        if resp.status in (401, 403):
            raise AdminError(resp.status, "not allowed: your account lacks the realm-management rights for this")
        if resp.status == 404:
            raise NotFoundError(path)
        if resp.status == 409:
            raise AdminError(409, "already exists")
        detail = ""
        try:
            payload = resp.json() or {}
            detail = payload.get("errorMessage") or payload.get("error") or ""
        except ValueError:
            pass
        raise AdminError(resp.status, f"the directory refused the change (HTTP {resp.status}) {detail}".strip())

    @staticmethod
    def _created_id(resp: Response) -> str:
        location = next((v for k, v in resp.headers.items() if k.lower() == "location"), "")
        return location.rstrip("/").rsplit("/", 1)[-1]

    # --- users ---------------------------------------------------------------

    def list_users(self, search: str | None = None, limit: int = 100) -> list[User]:
        reps = self._call(
            "GET", "/users", params={"search": search, "max": limit, "briefRepresentation": "true"}
        ).json()
        return [User.from_rep(r) for r in reps]

    def user(self, username: str) -> User:
        reps = self._call("GET", "/users", params={"username": username, "exact": "true"}).json()
        if not reps:
            raise NotFoundError(f"user {username}")
        return User.from_rep(reps[0])

    def create_user(
        self,
        username: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        temporary_password: str | None = None,
    ) -> User:
        rep = {"username": username, "enabled": True, "email": email, "firstName": first_name, "lastName": last_name}
        user_id = self._created_id(self._call("POST", "/users", body={k: v for k, v in rep.items() if v is not None}))
        if temporary_password:
            self._call(
                "PUT",
                f"/users/{user_id}/reset-password",
                body={"type": "password", "value": temporary_password, "temporary": True},
            )
        return self.user(username)

    def set_enabled(self, username: str, enabled: bool) -> User:
        """Disable or re-enable; a user is never deleted (id-DIR-000002)."""
        self._call("PUT", f"/users/{self.user(username).id}", body={"enabled": enabled})
        return self.user(username)

    def user_groups(self, username: str) -> list[str]:
        reps = self._call("GET", f"/users/{self.user(username).id}/groups").json()
        return sorted(r["path"] for r in reps)

    # --- groups --------------------------------------------------------------

    def group(self, path: str) -> Group:
        quoted = "/".join(urllib.parse.quote(part, safe="") for part in _path(path).strip("/").split("/"))
        rep = self._call("GET", f"/group-by-path/{quoted}").json()
        return Group(rep["id"], rep["path"], tuple(sorted(rep.get("realmRoles") or ())))

    def groups(self) -> list[Group]:
        """Every group, parents before children, as a depth-first tree."""
        return list(self._walk(self._call("GET", "/groups", params={"briefRepresentation": "false"}).json()))

    def _walk(self, reps: list[dict[str, Any]]) -> Iterator[Group]:
        for rep in sorted(reps, key=lambda r: r["name"]):
            yield Group(rep["id"], rep["path"], tuple(sorted(rep.get("realmRoles") or ())))
            children = rep.get("subGroups") or []
            if not children and rep.get("subGroupCount"):
                children = self._call(
                    "GET", f"/groups/{rep['id']}/children", params={"briefRepresentation": "false", "max": 1000}
                ).json()
            yield from self._walk(children)

    def create_group(self, path: str) -> Group:
        """Create `path` and any missing parent, like `mkdir -p`."""
        parent: Group | None = None
        parts = _path(path).strip("/").split("/")
        for i, name in enumerate(parts):
            current = "/" + "/".join(parts[: i + 1])
            try:
                parent = self.group(current)
                continue
            except NotFoundError:
                pass
            where = f"/groups/{parent.id}/children" if parent else "/groups"
            self._call("POST", where, body={"name": name})
            parent = self.group(current)
        assert parent is not None  # noqa: S101 - a path has at least one part
        return parent

    def members(self, path: str) -> list[str]:
        reps = self._call("GET", f"/groups/{self.group(path).id}/members", params={"max": 1000}).json()
        return sorted(r["username"] for r in reps)

    def add_member(self, path: str, username: str) -> None:
        self._call("PUT", f"/users/{self.user(username).id}/groups/{self.group(path).id}")

    def remove_member(self, path: str, username: str) -> None:
        self._call("DELETE", f"/users/{self.user(username).id}/groups/{self.group(path).id}")

    # --- realm roles ---------------------------------------------------------

    def roles(self) -> list[tuple[str, str]]:
        reps = self._call("GET", "/roles").json()
        return sorted((r["name"], r.get("description") or "") for r in reps)

    def create_role(self, name: str, description: str | None = None) -> None:
        self._call("POST", "/roles", body={"name": name, **({"description": description} if description else {})})

    def _role(self, name: str) -> dict[str, Any]:
        return self._call("GET", f"/roles/{urllib.parse.quote(name, safe='')}").json()

    def grant_role_to_group(self, path: str, role: str) -> None:
        self._call("POST", f"/groups/{self.group(path).id}/role-mappings/realm", body=[self._role(role)])

    def grant_role_to_user(self, username: str, role: str) -> None:
        self._call("POST", f"/users/{self.user(username).id}/role-mappings/realm", body=[self._role(role)])
