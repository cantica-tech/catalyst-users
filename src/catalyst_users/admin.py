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

    def update_user(
        self,
        username: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> User:
        """Change the details given, and only them (id-DIR-000007); none given changes nothing. A changed email is no
        longer verified. The username is never changed: what people signed names them by it."""
        user = self.user(username)
        rep = {"email": email, "firstName": first_name, "lastName": last_name}
        changes = {k: v for k, v in rep.items() if v is not None}
        if not changes:
            return user
        if email is not None and email != user.email:
            changes["emailVerified"] = False
        self._call("PUT", f"/users/{user.id}", body=changes)
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

    # --- criteria (id-DIR-000005, id-PROVIDER-000008) -------------------------
    # A criterion is the group /criteria/<name>; its admins, /criteria/<name>/admins, hold the realm role
    # criterion-admin. The realm's fine-grained admin permissions (FGAP v2, Keycloak 26.2+) give that group the
    # membership of its criterion's groups and the sight of users, nothing else. A permission on a group does not
    # reach its subgroups, so each criterion's permission names every group under it; `add_criterion` again
    # covers groups added since.

    def prepare_criteria(self) -> list[str]:
        """The realm, ready for criteria: fine-grained admin permissions on, the role and the /criteria group.
        Adds what is missing, changes nothing else; returns what it added."""
        from catalyst_users.provider import CRITERIA_GROUP, CRITERION_ADMIN

        added = []
        realm = self._call("GET", "").json()
        if not realm.get("adminPermissionsEnabled"):
            self._call("PUT", "", body={**realm, "adminPermissionsEnabled": True})
            added.append("fine-grained admin permissions")
        if CRITERION_ADMIN not in {name for name, _ in self.roles()}:
            self.create_role(CRITERION_ADMIN, "catalyst: Criterion Admin (every right, in the criteria it administers)")
            added.append(f"role {CRITERION_ADMIN}")
        try:
            self.group(CRITERIA_GROUP)
        except NotFoundError:
            self.create_group(CRITERIA_GROUP)
            added.append(f"group {CRITERIA_GROUP}")
        return added

    def criteria(self) -> list[dict[str, Any]]:
        """Each criterion the caller may see, with its admins (None when the caller may not read them)."""
        from catalyst_users.provider import CRITERIA_GROUP

        prefix = CRITERIA_GROUP + "/"
        names = sorted({g.path[len(prefix) :].split("/")[0] for g in self.groups() if g.path.startswith(prefix)})
        out = []
        for name in names:
            try:
                admins: list[str] | None = self.members(f"{prefix}{name}/admins")
            except (AdminError, NotFoundError):
                admins = None
            out.append({"name": name, "admins": admins})
        return out

    def add_criterion(self, name: str) -> list[str]:
        """The criterion `name`: its group, its admins group holding criterion-admin, and the permissions that let
        those admins manage its groups' members. Idempotent; returns what it added or refreshed."""
        from catalyst_users.provider import CRITERIA_GROUP, CRITERION_ADMIN, criterion_name

        criterion = f"{CRITERIA_GROUP}/{criterion_name(name)}"
        added = self.prepare_criteria()
        try:
            self.group(f"{criterion}/admins")
        except NotFoundError:
            self.create_group(f"{criterion}/admins")
            added.append(f"group {criterion}/admins")
        if CRITERION_ADMIN not in self.group(f"{criterion}/admins").roles:
            self.grant_role_to_group(f"{criterion}/admins", CRITERION_ADMIN)
            added.append(f"{CRITERION_ADMIN} on {criterion}/admins")
        try:  # its members (id-DIR-000006), before the permission that names every group under it
            self.group(f"{criterion}/members")
        except NotFoundError:
            self.create_group(f"{criterion}/members")
            added.append(f"group {criterion}/members")
        added += self._criterion_permissions(name, criterion)
        return added

    def appoint(self, name: str, username: str) -> None:
        from catalyst_users.provider import CRITERIA_GROUP, criterion_name

        self.add_member(f"{CRITERIA_GROUP}/{criterion_name(name)}/admins", username)

    def dismiss(self, name: str, username: str) -> None:
        """Removes the membership, never the person (id-DIR-000002)."""
        from catalyst_users.provider import CRITERIA_GROUP, criterion_name

        self.remove_member(f"{CRITERIA_GROUP}/{criterion_name(name)}/admins", username)

    # --- a criterion's members (id-DIR-000006) ----------------------------------
    # /criteria/<name>/members. Whether someone is a member is read from their groups now, never from a token.

    @staticmethod
    def _members_group(name: str) -> str:
        from catalyst_users.provider import CRITERIA_GROUP, criterion_name

        return f"{CRITERIA_GROUP}/{criterion_name(name)}/members"

    def criterion_members(self, name: str) -> list[str]:
        return self.members(self._members_group(name))

    def is_criterion_member(self, name: str, username: str) -> bool:
        group = self._members_group(name)
        try:
            return group in self.user_groups(username)
        except NotFoundError:
            return False

    def join_criterion(self, name: str, username: str) -> None:
        """Adds a person of the realm; one the realm does not know is refused (NotFoundError)."""
        self.add_member(self._members_group(name), username)

    def leave_criterion(self, name: str, username: str) -> None:
        """Removes the membership, never the person (id-DIR-000002)."""
        self.remove_member(self._members_group(name), username)

    def _authz(self) -> str:
        found = self._call("GET", "/clients", params={"clientId": "admin-permissions"}).json()
        if not found:
            raise AdminError(400, "the realm has no fine-grained admin permissions (admin-permissions client)")
        return f"/clients/{found[0]['id']}/authz/resource-server"

    def _named(self, authz: str, kind: str, name: str) -> dict[str, Any] | None:
        reps = self._call("GET", f"{authz}/{kind}", params={"name": name, "first": 0, "max": 100}).json()
        return next((r for r in reps if r.get("name") == name), None)

    def _subtree(self, path: str) -> list[Group]:
        return [g for g in self.groups() if g.path == path or g.path.startswith(path + "/")]

    def _criterion_permissions(self, name: str, criterion: str) -> list[str]:
        authz, added = self._authz(), []
        policy_name = f"criterion {name}: its admins"
        policy = self._named(authz, "policy", policy_name)
        if policy is None:
            admins = self.group(f"{criterion}/admins")
            self._call(
                "POST",
                f"{authz}/policy/group",
                body={
                    "name": policy_name,
                    "groups": [{"id": admins.id, "extendChildren": False}],
                    "logic": "POSITIVE",
                },
            )
            policy = self._named(authz, "policy", policy_name)
            added.append(f"policy {policy_name}")
        assert policy is not None  # noqa: S101 - just created
        groups = sorted(g.id for g in self._subtree(criterion))
        perm_name = f"criterion {name}: its groups"
        body = {
            "name": perm_name,
            "resourceType": "Groups",
            "scopes": ["view", "view-members", "manage-members", "manage-membership"],
            "resources": groups,
            "policies": [policy["id"]],
            "decisionStrategy": "UNANIMOUS",
        }
        found = self._named(authz, "permission", perm_name)
        if found is None:
            self._call("POST", f"{authz}/permission/scope", body=body)
            added.append(f"permission {perm_name}")
        elif sorted(self._resources(authz, found["id"])) != groups:
            self._call("PUT", f"{authz}/permission/scope/{found['id']}", body={**body, "id": found["id"]})
            added.append(f"permission {perm_name} (now {len(groups)} groups)")
        return added + self._users_permission(authz, policy["id"])

    def _users_permission(self, authz: str, policy_id: str) -> list[str]:
        """One permission over every user, shared by all criteria's admins: the realm's permissions decide
        unanimously, so a permission per criterion on the same users would let each criterion's veto the others'.
        Affirmative, it lets any criterion's admins find a user and put them in the groups they may manage."""
        perm_name = "criteria: their admins find users"
        found = self._named(authz, "permission", perm_name)
        held = [str(p["id"]) for p in self._associated(authz, found["id"])] if found else []
        if policy_id in held:
            return []
        body = {
            "name": perm_name,
            "resourceType": "Users",
            "scopes": ["view", "manage-group-membership"],
            "resources": [],
            "policies": [*held, policy_id],
            "decisionStrategy": "AFFIRMATIVE",
        }
        if found is None:
            self._call("POST", f"{authz}/permission/scope", body=body)
            return [f"permission {perm_name}"]
        self._call("PUT", f"{authz}/permission/scope/{found['id']}", body={**body, "id": found["id"]})
        return [f"permission {perm_name} (now {len(body['policies'])} criteria)"]

    def _resources(self, authz: str, permission_id: str) -> list[str]:
        """The group ids a Groups permission names (FGAP v2 keeps each as a resource named by the group's id)."""
        reps = self._call("GET", f"{authz}/policy/{permission_id}/resources").json()
        return [str(r.get("name")) for r in reps]

    def _associated(self, authz: str, permission_id: str) -> list[dict[str, Any]]:
        return self._call("GET", f"{authz}/policy/{permission_id}/associatedPolicies").json()
