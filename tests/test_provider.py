"""The facade (id-PROVIDER-000001..000004): the pointer, the grants in a token, provisioning and import, and the
static backend's guard."""

import json

import pytest

from catalyst_users import provision
from catalyst_users.admin import KeycloakAdmin
from catalyst_users.http import Http
from catalyst_users.provider import (
    STATIC_FLAG,
    KeycloakProvider,
    ProviderError,
    StaticProvider,
    from_pointer,
    pointer_problems,
    whoami_from_claims,
)
from tests.conftest import ADMIN, ISSUER, OIDC, reply

CLAIMS = {
    "sub": "s-bob",
    "preferred_username": "bob",
    "name": "Bob Maintainer",
    "groups": ["/cantica-tech/catalyst/maintainers"],
    "realm_access": {"roles": ["tech-lead", "release-manager"]},
    "resource_access": {"catalyst": {"roles": ["cmd:create", "cmd:freeze", "reconcile:propose", "reconcile:full"]}},
}
TEMPLATE = [
    {
        "name": "Tech Lead / Architect",
        "id": "tech-lead",
        "actions": ["approve rules", "/create", "/freeze"],
        "reconciliation": "full",
    },
    {"name": "Stakeholder", "actions": ["propose ideas"], "reconciliation": "none"},
    {"name": "Admin", "provider_role": "catalyst-admin", "actions": ["/user-add"], "reconciliation": "full"},
    {
        "name": "Developer",
        "actions": ["/create-req (implementation-driven)", "/status on tasks"],
        "reconciliation": "propose",
    },
]


def test_grants_commands_and_reconciliation_come_from_the_token():
    who = whoami_from_claims(CLAIMS, ISSUER, "catalyst")
    assert (who.username, who.groups, who.roles) == (
        "bob",
        ("/cantica-tech/catalyst/maintainers",),
        ("release-manager", "tech-lead"),
    )
    assert who.commands == ("create", "freeze") and who.reconciliation == "full"
    assert who.grants_command("/freeze") and not who.grants_command("approve")
    assert whoami_from_claims({**CLAIMS, "resource_access": {}}, ISSUER, "catalyst").reconciliation == "none"
    assert whoami_from_claims(
        {"sub": "x", "resource_access": {"catalyst": {"roles": ["cmd:*"]}}}, ISSUER, "catalyst"
    ).grants_command("anything")


def test_the_keycloak_provider_reads_userinfo(settings, transport, tmp_path):
    import time

    from catalyst_users.credentials import CredentialStore
    from catalyst_users.oidc import Tokens

    store = tmp_path / "creds.json"
    CredentialStore(store).save(ISSUER, "catalyst-cli", Tokens("at", "rt", time.time() + 300))
    transport.on("GET", f"{OIDC}/userinfo", reply(body=CLAIMS))
    who = KeycloakProvider(ISSUER, store=store, transport=transport).whoami()
    assert who.grants == ("cmd:create", "cmd:freeze", "reconcile:full", "reconcile:propose")
    with pytest.raises(ProviderError, match="not alice"):
        KeycloakProvider(ISSUER, store=store, transport=transport).whoami("alice")


def test_the_pointer_chooses_the_backend(monkeypatch):
    monkeypatch.delenv(STATIC_FLAG, raising=False)
    kc = from_pointer({"provider": "keycloak", "issuer": ISSUER})
    assert isinstance(kc, KeycloakProvider) and kc.catalyst_client == "catalyst" and kc.client == "catalyst-cli"
    with pytest.raises(ProviderError, match="needs an"):
        from_pointer({"provider": "keycloak"})
    with pytest.raises(ProviderError, match="unknown provider"):
        from_pointer({"provider": "ldap"})
    with pytest.raises(ProviderError, match="tests only"):
        from_pointer({"provider": "static", "people": []})
    monkeypatch.setenv(STATIC_FLAG, "1")
    assert isinstance(from_pointer({"provider": "static"}), StaticProvider)
    assert pointer_problems({"provider": "keycloak", "issuer": ISSUER}) == []
    assert pointer_problems({"provider": "static"}) and pointer_problems([]) and pointer_problems({"provider": "x"})


def test_the_static_backend_declares_people_and_their_grants():
    p = StaticProvider(
        people=[
            {"username": "ada", "name": "Ada", "roles": ["admin"], "groups": ["/g"]},
            {"username": "old", "roles": ["dev"], "active": False},
        ],
        role_defs=[{"id": "admin", "grants": ["cmd:*", "reconcile:full"]}, {"id": "dev", "grants": ["cmd:create"]}],
    )
    who = p.whoami()  # the only active person
    assert (who.username, who.grants, who.reconciliation, who.groups) == (
        "ada",
        ("cmd:*", "reconcile:full"),
        "full",
        ("/g",),
    )
    with pytest.raises(ProviderError, match="disabled"):
        p.whoami("old")
    with pytest.raises(ProviderError, match="no declared person"):
        p.whoami("eve")


def test_a_role_grants_its_commands_and_its_level():
    assert provision.grants_of(TEMPLATE[0]) == ["cmd:create", "cmd:freeze", "reconcile:full"]
    assert provision.grants_of(TEMPLATE[1]) == []  # descriptive actions grant nothing
    assert provision.grants_of(TEMPLATE[2]) == ["cmd:*", "cmd:user-add", "reconcile:full"]  # Admin: everything
    assert provision.grants_of(TEMPLATE[3]) == ["cmd:create-req", "cmd:status", "reconcile:propose"]
    assert [provision.role_id(r) for r in TEMPLATE] == ["tech-lead", "stakeholder", "catalyst-admin", "developer"]


class Realm:
    """A small fake of Keycloak's admin API: clients, client roles, realm roles, composites, mappers, users."""

    def __init__(self, transport):
        self.clients = {"catalyst-cli": {"id": "c-cli", "clientId": "catalyst-cli", "mappers": []}}
        self.client_roles: dict[str, set] = {}
        self.realm_roles: dict[str, dict] = {}
        self.composites: dict[str, set] = {}
        self.users: dict[str, dict] = {}
        t = transport
        t.on("GET", f"{ADMIN}/clients", self.get_clients)
        t.on("POST", f"{ADMIN}/clients", self.post_client)
        self.t = t

    def get_clients(self, req):
        cid = req.url.split("clientId=")[1]
        c = self.clients.get(cid)
        return reply(body=[c] if c else [])

    def post_client(self, req):
        body = json.loads(req.body)
        cid = body["clientId"]
        self.clients[cid] = {"id": f"c-{cid}", "clientId": cid, "mappers": []}
        self._client_routes(self.clients[cid])
        return reply(201)

    def _client_routes(self, c):
        cid = c["id"]
        roles = self.client_roles.setdefault(cid, set())

        def get_role(req):
            name = req.url.rsplit("/", 1)[1].replace("%3A", ":").replace("%2A", "*")
            return reply(body={"id": f"r-{name}", "name": name}) if name in roles else reply(404)

        def post_role(req):
            roles.add(json.loads(req.body)["name"])
            for name in roles:  # every role path becomes reachable
                self.t.on(
                    "GET", f"{ADMIN}/clients/{cid}/roles/{name.replace(':', '%3A').replace('*', '%2A')}", get_role
                )
            return reply(201)

        self.t.on("POST", f"{ADMIN}/clients/{cid}/roles", post_role)

    def mappers_for(self, cid):
        c = next(c for c in self.clients.values() if c["id"] == cid)
        self.t.on("GET", f"{ADMIN}/clients/{cid}/protocol-mappers/models", lambda r: reply(body=c["mappers"]))

        def add(req):
            c["mappers"].append(json.loads(req.body))
            return reply(201)

        self.t.on("POST", f"{ADMIN}/clients/{cid}/protocol-mappers/models", add)


def _admin(settings, transport):
    return KeycloakAdmin(settings, lambda: "admin-token", Http(transport))


def test_provisioning_creates_the_client_mapper_roles_and_composites(settings, transport):
    realm = Realm(transport)
    realm.mappers_for("c-cli")
    posted = []

    def realm_role(req):
        name = req.url.rsplit("/roles/", 1)[1]
        return reply(body={"name": name, "attributes": {}}) if name in realm.realm_roles else reply(404)

    def new_realm_role(req):
        body = json.loads(req.body)
        realm.realm_roles[body["name"]] = body
        return reply(201)

    def composites(req):
        posted.append((req.url.split("/roles/")[1].split("/")[0], [r["name"] for r in json.loads(req.body)]))
        return reply(204)

    for r in TEMPLATE:
        rid = provision.role_id(r)
        transport.on("GET", f"{ADMIN}/roles/{rid}", realm_role)
        transport.on("PUT", f"{ADMIN}/roles/{rid}", reply(204))
        transport.on("POST", f"{ADMIN}/roles/{rid}/composites", composites)
    transport.on("POST", f"{ADMIN}/roles", new_realm_role)
    report = provision.provision(_admin(settings, transport), TEMPLATE)
    assert "client catalyst" in report.created and "mapper on catalyst-cli" in report.created
    mapper = realm.clients["catalyst-cli"]["mappers"][0]
    assert mapper["config"]["usermodel.clientRoleMapping.clientId"] == "catalyst"
    assert mapper["config"]["userinfo.token.claim"] == "true"
    assert realm.realm_roles["tech-lead"]["attributes"] == {"catalyst.name": ["Tech Lead / Architect"]}
    assert ("tech-lead", ["cmd:create", "cmd:freeze", "reconcile:full"]) in posted
    assert not any(rid == "stakeholder" for rid, _ in posted)  # nothing to compose
    assert transport.calls("DELETE") == []
    again = provision.provision(_admin(settings, transport), TEMPLATE)  # idempotent
    assert "client catalyst" in again.kept and "mapper on catalyst-cli" in again.kept and "role tech-lead" in again.kept


def test_import_creates_missing_users_with_their_mapped_roles(settings, transport):
    created, granted = [], []
    known = {"ada": {"id": "u-ada", "username": "ada", "enabled": True}}

    def get_users(req):
        name = req.url.split("username=")[1].split("&")[0]
        return reply(body=[known[name]] if name in known else [])

    def post_user(req):
        body = json.loads(req.body)
        known[body["username"]] = {"id": f"u-{body['username']}", "username": body["username"], "enabled": True}
        created.append(body)
        return reply(201, headers={"Location": f"{ADMIN}/users/u-{body['username']}"})

    transport.on("GET", f"{ADMIN}/users", get_users)
    transport.on("POST", f"{ADMIN}/users", post_user)
    transport.on("GET", f"{ADMIN}/roles/developer", reply(body={"id": "r1", "name": "developer"}))
    transport.on("POST", f"{ADMIN}/users/u-grace/role-mappings/realm", lambda r: granted.append(r.body) or reply(204))
    users = [
        {"name": "Ada Lovelace", "git_username": "ada", "roles": ["Admin"]},
        {"name": "Grace Hopper", "git_username": "grace", "roles": ["Developer", "Unknown"]},
    ]
    report = provision.import_users(_admin(settings, transport), users, TEMPLATE)
    assert report.kept == ["user ada"] and report.created == ["user grace"]
    assert created[0] == {"username": "grace", "enabled": True, "firstName": "Grace", "lastName": "Hopper"}
    assert len(granted) == 1  # Developer mapped; Unknown names no role
