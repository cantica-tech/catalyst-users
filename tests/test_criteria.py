"""Criteria and their admins (id-DIR-000005, id-PROVIDER-000008): `administers`, whatever the provider; Keycloak's
groups and fine-grained admin permissions; provisioning a criterion-scoped role; the command line."""

from __future__ import annotations

import json
import urllib.parse

import pytest

from catalyst_users import cli, provision
from catalyst_users.admin import KeycloakAdmin
from catalyst_users.http import Http, Request
from catalyst_users.provider import (
    STATIC_FLAG,
    ProviderError,
    StaticProvider,
    administers_from_groups,
    criterion_name,
    whoami_from_claims,
)
from tests.conftest import ADMIN, ISSUER, reply

AUTHZ = f"{ADMIN}/clients/ap/authz/resource-server"


def test_administers_is_the_admins_groups_of_criteria_exactly():
    groups = ["/criteria/catalyst/admins", "criteria/catalyst-ui/admins/", "/criteria/kb", "/criteria/x/admins/sub"]
    assert administers_from_groups(groups) == ("catalyst", "catalyst-ui")
    assert administers_from_groups(["/catalyst-admins", "/elsewhere/criteria/a/admins"]) == ()
    who = whoami_from_claims({"sub": "s", "groups": ["/criteria/catalyst/admins"]}, ISSUER, "catalyst")
    assert who.administers == ("catalyst",) and who.administers_criterion("catalyst")
    assert not who.administers_criterion("catalyst-ui") and who.grants == ()


def test_a_criterion_name_is_a_project_name():
    assert criterion_name("catalyst-users-kb") == "catalyst-users-kb"
    for bad in ("", "Catalyst", "a/b", "-x", "a b"):
        with pytest.raises(ProviderError, match="not a criterion name"):
            criterion_name(bad)


def test_a_criterion_scoped_role_is_provisioned_without_grants():
    role = {"name": "Criterion Admin", "id": "criterion-admin", "actions": ["*"], "reconciliation": "full"}
    assert provision.grants_of(role) == ["cmd:*", "reconcile:full"]
    assert provision.grants_of({**role, "scope": "criterion"}) == []


def test_the_static_provider_reports_criteria_and_changes_none(monkeypatch):
    monkeypatch.setenv(STATIC_FLAG, "1")
    people = [
        {"username": "ann", "groups": ["/criteria/catalyst/admins"]},
        {"username": "bob", "groups": ["/criteria/catalyst/admins", "/criteria/kb/admins"], "active": False},
    ]
    static = StaticProvider.from_pointer({"provider": "static", "people": people})
    assert static.whoami("ann").administers == ("catalyst",)
    assert static.criteria() == [{"name": "catalyst", "admins": ["ann", "bob"]}, {"name": "kb", "admins": ["bob"]}]
    for call in (
        lambda: static.add_criterion("x"),
        lambda: static.appoint("x", "ann"),
        lambda: static.dismiss("x", "a"),
    ):
        with pytest.raises(ProviderError, match="does not support"):
            call()


class Realm:
    """Enough of a Keycloak realm, behind the fake transport, for criteria: groups, a role, FGAP's authz."""

    def __init__(self, transport, ready: bool = True) -> None:
        self.t = transport
        self.realm = {"realm": "catalyst", "adminPermissionsEnabled": ready}
        self.groups: dict[str, dict] = {}
        self.policies: list[dict] = []
        self.permissions: list[dict] = []
        self.role_mappings: list[tuple[str, str]] = []
        self.roles = ["tech-lead"] + (["criterion-admin"] if ready else [])
        if ready:
            self._group("/criteria")
        t = transport
        t.on("GET", ADMIN, lambda r: reply(body=self.realm))
        t.on("PUT", ADMIN, self._put_realm)
        t.on("GET", f"{ADMIN}/roles", lambda r: reply(body=[{"name": n} for n in self.roles]))
        t.on("POST", f"{ADMIN}/roles", self._post_role)
        t.on("GET", f"{ADMIN}/roles/criterion-admin", reply(body={"id": "r-ca", "name": "criterion-admin"}))
        t.on("GET", f"{ADMIN}/groups", lambda r: reply(body=self._tree("")))
        t.on("POST", f"{ADMIN}/groups", lambda r: self._post_group("", r))
        t.on("GET", f"{ADMIN}/clients", reply(body=[{"id": "ap", "clientId": "admin-permissions"}]))
        t.on("GET", f"{AUTHZ}/policy", lambda r: self._named(self.policies + self.permissions, r))
        t.on("GET", f"{AUTHZ}/permission", lambda r: self._named(self.permissions, r))
        t.on("POST", f"{AUTHZ}/policy/group", lambda r: self._add(self.policies, r))
        t.on("POST", f"{AUTHZ}/permission/scope", lambda r: self._add(self.permissions, r))

    def _group(self, path: str) -> dict:
        gid = "g" + path.replace("/", "-")
        group = {"id": gid, "path": path, "name": path.rsplit("/", 1)[-1], "realmRoles": []}
        self.groups[path] = group
        self.t.on("GET", f"{ADMIN}/group-by-path/{path.strip('/')}", lambda r: reply(body=self.groups[path]))
        self.t.on("POST", f"{ADMIN}/groups/{gid}/children", lambda r: self._post_group(path, r))
        self.t.on("POST", f"{ADMIN}/groups/{gid}/role-mappings/realm", lambda r: self._map(path, r))
        return group

    def _tree(self, parent: str) -> list[dict]:
        kids = [g for p, g in self.groups.items() if p.rsplit("/", 1)[0] == parent]
        return [{**g, "subGroups": self._tree(g["path"])} for g in kids]

    def _put_realm(self, request: Request):
        self.realm = json.loads(request.body)
        return reply(204)

    def _post_role(self, request: Request):
        self.roles.append(json.loads(request.body)["name"])
        return reply(201)

    def _post_group(self, parent: str, request: Request):
        self._group(f"{parent}/{json.loads(request.body)['name']}")
        return reply(201)

    def _map(self, path: str, request: Request):
        for role in json.loads(request.body):
            self.groups[path]["realmRoles"].append(role["name"])
            self.role_mappings.append((path, role["name"]))
        return reply(204)

    def _named(self, items: list[dict], request: Request):
        name = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(request.url).query)).get("name", "")
        return reply(body=[i for i in items if name in i["name"]])

    def _add(self, items: list[dict], request: Request):
        item = {**json.loads(request.body), "id": f"p{len(self.policies) + len(self.permissions)}"}
        items.append(item)
        self.t.on("PUT", f"{AUTHZ}/permission/scope/{item['id']}", lambda r: self._put_permission(item, r))
        self.t.on("GET", f"{AUTHZ}/policy/{item['id']}/resources", lambda r: self._resources(item))
        self.t.on("GET", f"{AUTHZ}/policy/{item['id']}/associatedPolicies", lambda r: self._associated(item))
        return reply(201)

    def _put_permission(self, item: dict, request: Request):
        item.update(json.loads(request.body))
        return reply(204)

    def _associated(self, item: dict):
        return reply(body=[p for p in self.policies if p["id"] in (item.get("policies") or ())])

    def _resources(self, item: dict):
        return reply(body=[{"name": rid} for rid in item.get("resources") or ()])

    def permission(self, name: str) -> dict:
        return next(p for p in self.permissions if p["name"] == name)


def _admin(transport) -> KeycloakAdmin:
    class S:
        admin_url, timeout = ADMIN, 10.0

    return KeycloakAdmin(S(), lambda: "at", Http(transport))  # type: ignore[arg-type]


def test_a_criterion_is_its_groups_its_admins_role_and_their_permissions(transport):
    realm = Realm(transport)
    added = _admin(transport).add_criterion("alpha")
    assert {"/criteria/alpha", "/criteria/alpha/admins"} <= set(realm.groups)
    assert realm.role_mappings == [("/criteria/alpha/admins", "criterion-admin")]
    (policy,) = realm.policies
    assert policy["groups"] == [{"id": "g-criteria-alpha-admins", "extendChildren": False}]
    groups = realm.permission("criterion alpha: its groups")
    assert groups["resourceType"] == "Groups" and groups["policies"] == [policy["id"]]
    assert sorted(groups["resources"]) == ["g-criteria-alpha", "g-criteria-alpha-admins"]
    assert set(groups["scopes"]) == {"view", "view-members", "manage-members", "manage-membership"}
    users = realm.permission("criteria: their admins find users")
    assert users["resourceType"] == "Users" and users["resources"] == [] and users["policies"] == [policy["id"]]
    assert set(users["scopes"]) == {"view", "manage-group-membership"} and users["decisionStrategy"] == "AFFIRMATIVE"
    assert "permission criterion alpha: its groups" in added


def test_adding_a_criterion_again_changes_nothing_but_covers_its_new_groups(transport):
    realm = Realm(transport)
    admin = _admin(transport)
    admin.add_criterion("alpha")
    assert admin.add_criterion("alpha") == []
    admin.create_group("/criteria/alpha/developers")
    assert admin.add_criterion("alpha") == ["permission criterion alpha: its groups (now 3 groups)"]
    assert "g-criteria-alpha-developers" in realm.permission("criterion alpha: its groups")["resources"]
    assert len(realm.policies) == 1 and len(realm.permissions) == 2 and len(realm.role_mappings) == 1


def test_every_criterions_admins_share_one_affirmative_permission_on_users(transport):
    """The realm decides unanimously: a Users permission per criterion would let one criterion's veto another's."""
    realm = Realm(transport)
    admin = _admin(transport)
    admin.add_criterion("alpha")
    assert admin.add_criterion("beta")[-1] == "permission criteria: their admins find users (now 2 criteria)"
    users = [p for p in realm.permissions if p["resourceType"] == "Users"]
    assert len(users) == 1 and users[0]["policies"] == [p["id"] for p in realm.policies]
    assert realm.permission("criterion beta: its groups")["policies"] == [realm.policies[1]["id"]]


def test_an_unready_realm_is_readied_first(transport):
    realm = Realm(transport, ready=False)
    added = _admin(transport).add_criterion("alpha")
    assert realm.realm["adminPermissionsEnabled"] is True and "criterion-admin" in realm.roles
    assert added[:3] == ["fine-grained admin permissions", "role criterion-admin", "group /criteria"]


def test_criteria_lists_each_with_its_admins_or_none_when_not_visible(transport):
    realm = Realm(transport)
    admin = _admin(transport)
    admin.add_criterion("alpha")
    admin.add_criterion("beta")
    transport.on("GET", f"{ADMIN}/groups/g-criteria-alpha-admins/members", reply(body=[{"username": "ann"}]))
    transport.on("GET", f"{ADMIN}/groups/g-criteria-beta-admins/members", reply(403))
    assert admin.criteria() == [{"name": "alpha", "admins": ["ann"]}, {"name": "beta", "admins": None}]
    assert "/criteria/beta" in realm.groups


def test_appoint_and_dismiss_change_the_admins_group_only(transport):
    Realm(transport)
    admin = _admin(transport)
    admin.add_criterion("alpha")
    transport.on("GET", f"{ADMIN}/users", reply(body=[{"id": "u-ann", "username": "ann"}]))
    transport.on("PUT", f"{ADMIN}/users/u-ann/groups/g-criteria-alpha-admins", reply(204))
    transport.on("DELETE", f"{ADMIN}/users/u-ann/groups/g-criteria-alpha-admins", reply(204))
    admin.appoint("alpha", "ann")
    admin.dismiss("alpha", "ann")
    assert ("PUT", f"{ADMIN}/users/u-ann/groups/g-criteria-alpha-admins") in transport.calls()
    assert ("DELETE", f"{ADMIN}/users/u-ann/groups/g-criteria-alpha-admins") in transport.calls()
    assert not [c for c in transport.calls("DELETE") if c[1].removeprefix(ADMIN) == "/users/u-ann"]
    with pytest.raises(ProviderError, match="not a criterion name"):
        admin.appoint("../catalyst-admins", "ann")


def test_the_command_line_lists_criteria_and_refuses_what_the_provider_cannot_do(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(STATIC_FLAG, "1")
    pointer = tmp_path / "pointer.json"
    people = [{"username": "ann", "groups": ["/criteria/catalyst/admins"]}]
    pointer.write_text(json.dumps({"provider": "static", "people": people}))
    assert cli.main(["--pointer", str(pointer), "criteria", "list"]) == 0
    assert "catalyst" in capsys.readouterr().out
    assert cli.main(["--pointer", str(pointer), "--json", "criteria", "admins", "catalyst"]) == 0
    assert json.loads(capsys.readouterr().out) == ["ann"]
    assert cli.main(["--pointer", str(pointer), "--json", "whoami"]) == 0
    assert json.loads(capsys.readouterr().out)["administers"] == ["catalyst"]
    assert cli.main(["--pointer", str(pointer), "criteria", "appoint", "catalyst", "bob"]) == 1
    assert "does not support appointing admins" in capsys.readouterr().err
