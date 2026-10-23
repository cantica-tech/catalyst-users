"""Write a catalyst roles document into Keycloak, and import a catalyst users document (id-PROVIDER-000003).

A role (`name`, optional `id` or `provider_role`, `actions`, `reconciliation`) becomes:

- a realm role, its id the role's `id`, else its `provider_role`, else the slug of its name; its display name in the
  attribute `catalyst.name`;
- a client role of the catalyst client per command it grants (`/create …` → `cmd:create`, `*` → `cmd:*`; the role
  named `Admin` grants `cmd:*`) and per reconciliation level (`reconcile:full`, `reconcile:propose`);
- the realm role a composite of those client roles.

The catalyst client is created if missing, and each login client gets the mapper that puts the catalyst client's
roles into userinfo, the access token and introspection. Everything is added if missing; nothing is deleted.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from catalyst_users.admin import KeycloakAdmin
from catalyst_users.errors import NotFoundError

MAPPER = "catalyst grants"


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def role_id(role: dict[str, Any]) -> str:
    return str(role.get("id") or role.get("provider_role") or slug(str(role["name"])))


def grants_of(role: dict[str, Any]) -> list[str]:
    """The client roles a catalyst role grants: its commands and its reconciliation level."""
    out: set[str] = set()
    for action in role.get("actions") or ():
        text = str(action).strip()
        if text == "*":
            out.add("cmd:*")
        elif text.startswith("/") and (command := text[1:].split()[0] if text[1:].split() else ""):
            out.add(f"cmd:{command}")
    if str(role.get("name")) == "Admin":
        out.add("cmd:*")
    level = str(role.get("reconciliation") or "none")
    if level in ("full", "propose"):
        out.add(f"reconcile:{level}")
    return sorted(out)


@dataclass
class Report:
    created: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)


def _q(name: str) -> str:
    return urllib.parse.quote(name, safe="")


def _client(admin: KeycloakAdmin, client_id: str) -> dict[str, Any] | None:
    found = admin._call("GET", "/clients", params={"clientId": client_id}).json()
    return found[0] if found else None


def ensure_client(admin: KeycloakAdmin, client_id: str, report: Report) -> dict[str, Any]:
    found = _client(admin, client_id)
    if found:
        report.kept.append(f"client {client_id}")
        return found
    admin._call(
        "POST",
        "/clients",
        body={
            "clientId": client_id,
            "name": "catalyst (grants: its roles are the commands catalyst roles may run)",
            "enabled": True,
            "publicClient": False,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
        },
    )
    report.created.append(f"client {client_id}")
    created = _client(admin, client_id)
    assert created is not None  # noqa: S101 - just created
    return created


def ensure_mapper(admin: KeycloakAdmin, login_client: str, catalyst_client: str, report: Report) -> None:
    client = _client(admin, login_client)
    if client is None:
        raise NotFoundError(f"client {login_client}")
    models = admin._call("GET", f"/clients/{client['id']}/protocol-mappers/models").json()
    if any(m.get("name") == MAPPER for m in models):
        report.kept.append(f"mapper on {login_client}")
        return
    admin._call(
        "POST",
        f"/clients/{client['id']}/protocol-mappers/models",
        body={
            "name": MAPPER,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-client-role-mapper",
            "config": {
                "usermodel.clientRoleMapping.clientId": catalyst_client,
                "claim.name": "resource_access.${client_id}.roles",
                "multivalued": "true",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "false",
                "userinfo.token.claim": "true",
                "introspection.token.claim": "true",
            },
        },
    )
    report.created.append(f"mapper on {login_client}")


def _client_role(admin: KeycloakAdmin, client: dict[str, Any], name: str, report: Report) -> dict[str, Any]:
    path = f"/clients/{client['id']}/roles/{_q(name)}"
    try:
        rep = admin._call("GET", path).json()
        report.kept.append(f"grant {name}")
        return rep
    except NotFoundError:
        admin._call("POST", f"/clients/{client['id']}/roles", body={"name": name})
        report.created.append(f"grant {name}")
        return admin._call("GET", path).json()


def _realm_role(admin: KeycloakAdmin, rid: str, display: str, report: Report) -> None:
    try:
        rep = admin._call("GET", f"/roles/{_q(rid)}").json()
        attributes = rep.get("attributes") or {}
        if attributes.get("catalyst.name") != [display]:
            admin._call(
                "PUT",
                f"/roles/{_q(rid)}",
                body={**rep, "attributes": {**attributes, "catalyst.name": [display]}},
            )
        report.kept.append(f"role {rid}")
    except NotFoundError:
        admin._call(
            "POST", "/roles", body={"name": rid, "description": display, "attributes": {"catalyst.name": [display]}}
        )
        report.created.append(f"role {rid}")


def provision(
    admin: KeycloakAdmin,
    roles: list[dict[str, Any]],
    catalyst_client: str = "catalyst",
    login_clients: tuple[str, ...] = ("catalyst-cli",),
) -> Report:
    report = Report()
    client = ensure_client(admin, catalyst_client, report)
    for login in login_clients:
        ensure_mapper(admin, login, catalyst_client, report)
    for role in roles:
        rid = role_id(role)
        _realm_role(admin, rid, str(role["name"]), report)
        reps = [_client_role(admin, client, g, report) for g in grants_of(role)]
        if reps:
            admin._call("POST", f"/roles/{_q(rid)}/composites", body=reps)
    return report


def import_users(admin: KeycloakAdmin, users: list[dict[str, Any]], roles: list[dict[str, Any]]) -> Report:
    """Each user of a catalyst users document, created without a password (they set one through the backend),
    enabled as recorded, holding the realm roles their role names map to. A user who exists is left as is."""
    report = Report()
    ids = {str(r["name"]): role_id(r) for r in roles}
    for user in users:
        username = str(user.get("git_username") or slug(str(user["name"])))
        try:
            admin.user(username)
            report.kept.append(f"user {username}")
            continue
        except NotFoundError:
            pass
        first, _, last = str(user.get("name") or username).partition(" ")
        admin.create_user(username, first_name=first, last_name=last or None)
        if user.get("active") is False:
            admin.set_enabled(username, False)
        for name in user.get("roles") or ():
            if name in ids:
                admin.grant_role_to_user(username, ids[name])
        report.created.append(f"user {username}")
    return report
