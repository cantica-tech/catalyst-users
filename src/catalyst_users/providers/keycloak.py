"""The Keycloak provider, built in (id-PROVIDER-000001, id-PROVIDER-000005, id-PROVIDER-000006).

A person logs in with the device grant and is read from userinfo; the directory is the admin API with the logged-in
person's own rights. The local system account is setup's admin, signed in with the password grant on the realm's
`password_client`; the password is the first line `password_command` prints, run without a shell (id-AUTH-000006).
Its settings, as `IAM/settings.json` stores them:

    {"url": "http://localhost:8080", "realm": "catalyst", "client": "catalyst-cli",
     "password_client": "catalyst-admin-cli", "catalyst_client": "catalyst"}

Setup's JSON adds `definition`, the realm to create when it is missing (a path, or the realm itself), never stored.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from catalyst_users.errors import CatalystUsersError, OIDCError, ProviderUnavailableError
from catalyst_users.provider import (
    DEFAULT_CATALYST_CLIENT,
    ProviderError,
    SetupOutcome,
    Whoami,
    secret_from_command,
    whoami_from_claims,
)

DEFAULT_PASSWORD_CLIENT = "catalyst-admin-cli"  # noqa: S105 - a client ID, not a password
DEFAULT_ADMIN_GROUP = "/catalyst-admins"
SERVER_ADMIN_REALM = "master"
# What a realm definition may not hold (id-PROVIDER-000007): people, and secrets.
PEOPLE_KEYS = ("users", "federatedUsers")
SECRET_KEYS = ("secret", "credentials", "password", "clientSecret")


@dataclass
class KeycloakProvider:
    """A Keycloak realm, reached with the device login and userinfo; the directory through the admin API with the
    logged-in person's own rights. `credentials` is where a logged-in person's tokens are kept between commands
    (catalyst-users' home by default, `config.home()`): the people themselves live only in Keycloak."""

    issuer: str
    client: str = "catalyst-cli"
    catalyst_client: str = DEFAULT_CATALYST_CLIENT
    credentials: Path | None = None
    transport: Any = None
    timeout: float = 10.0
    username: str | None = None
    password_command: str | list[str] | None = field(default=None, repr=False)
    password_client: str = DEFAULT_PASSWORD_CLIENT
    kind: str = field(default="keycloak", init=False)

    @classmethod
    def from_pointer(
        cls, doc: dict[str, Any], store: Path | None = None, transport: Any = None, credentials: Path | None = None
    ) -> KeycloakProvider:
        if problems := cls.problems(doc):
            raise ProviderError(problems[0])
        return cls(
            issuer=_issuer(doc),
            client=str(doc.get("client") or "catalyst-cli"),
            catalyst_client=str(doc.get("catalyst_client") or DEFAULT_CATALYST_CLIENT),
            credentials=credentials or store,
            transport=transport,
            timeout=float(doc.get("timeout") or 10.0),
            username=doc.get("username") or None,
            password_command=doc.get("password_command") or None,
            password_client=str(doc.get("password_client") or DEFAULT_PASSWORD_CLIENT),
        )

    @staticmethod
    def problems(doc: dict[str, Any]) -> list[str]:
        return [] if doc.get("issuer") or doc.get("url") else ['a "keycloak" pointer needs a "url" (or an "issuer")']

    # --- setup (id-PROVIDER-000006) --------------------------------------------------------
    @classmethod
    def setup(
        cls,
        settings: dict[str, Any],
        username: str,
        password: str,
        ask_server_admin: Callable[[], tuple[str, str]],
        transport: Any = None,
        ask_profile: Callable[[], dict[str, str]] | None = None,
        criteria: tuple[str, ...] = (),
    ) -> SetupOutcome:
        """Check the realm at the URL: unreachable, keep the JSON; missing, create it and its admin (their profile,
        `email`, `first_name`, `last_name`, from `ask_profile`: Keycloak signs no one in without it), then sign in;
        present, sign in only. A refused sign-in raises, so nothing is written. Signed in, the realm is readied for
        criteria, and each of `criteria` added with the admin appointed (id-PROVIDER-000008)."""
        from catalyst_users.http import Http, check_url

        url = str(settings.get("url") or "").rstrip("/")
        if not url:
            raise ProviderError('the keycloak settings need a "url", e.g. "http://localhost:8080"')
        definition = _definition(settings.get("definition"))
        realm = str(settings.get("realm") or (definition or {}).get("realm") or "catalyst")
        stored: dict[str, Any] = {
            "url": url,
            "realm": realm,
            "client": str(settings.get("client") or "catalyst-cli"),
            "password_client": str(settings.get("password_client") or DEFAULT_PASSWORD_CLIENT),
            "catalyst_client": str(settings.get("catalyst_client") or DEFAULT_CATALYST_CLIENT),
        }
        timeout = float(settings.get("timeout") or 10.0)
        if settings.get("timeout"):
            stored["timeout"] = timeout
        http = Http(transport, timeout=timeout)
        discovery = f"{url}/realms/{realm}/.well-known/openid-configuration"
        check_url(discovery)
        try:
            resp = http.request("GET", discovery)
        except ProviderUnavailableError as err:
            return SetupOutcome("unreachable", stored, f"Keycloak is not up at {url} ({err}): settings kept, unchecked")
        created = False
        if resp.status == 404:
            if definition is None:
                raise ProviderError(f'the realm {realm} does not exist at {url}, and the settings have no "definition"')
            profile = ask_profile() if ask_profile else {}
            _create_realm(http, url, realm, definition, ask_server_admin, username, password, profile, settings)
            created = True
        elif not resp.ok:
            raise ProviderError(f"Keycloak answered HTTP {resp.status} for the realm {realm} at {url}")
        provider = cls.from_pointer({**stored, "username": username}, transport=transport)
        tokens = provider._sign_in(password)
        from catalyst_users.admin import KeycloakAdmin

        admin = KeycloakAdmin(_AdminSettings(f"{url}/admin/realms/{realm}", timeout), lambda: tokens.access_token, http)  # type: ignore[arg-type]
        try:
            readied = admin.prepare_criteria()
            for name in criteria:
                readied += _add_criterion(admin, name, username)
        except CatalystUsersError as err:
            raise ProviderError(
                f"{username} is signed in, but the realm {realm} is not ready for criteria: {err}"
            ) from None
        done = f"; criteria: {', '.join(readied)}" if readied else ""
        if created:
            return SetupOutcome(
                "created", stored, f"created the realm {realm} and its admin {username}, signed in{done}"
            )
        return SetupOutcome("authenticated", stored, f"the realm {realm} exists: signed {username} in{done}")

    # --- people --------------------------------------------------------------------------
    def _oidc(self, client: str | None = None):
        from catalyst_users.http import Http
        from catalyst_users.oidc import OIDCClient

        settings = _IssuerSettings(self.issuer.rstrip("/"), client or self.client, timeout=self.timeout)
        return OIDCClient(settings, Http(self.transport, timeout=self.timeout))  # type: ignore[arg-type]

    def _session(self, client: str | None = None):
        """The session of the client the stored login came from: the login client's (device login), else the password
        client's (a password login, id-AUTH-000007), whose tokens only that client refreshes and revokes."""
        from catalyst_users.credentials import CredentialStore
        from catalyst_users.session import Session

        store = CredentialStore(self.credentials)
        if client is None:
            issuer = self.issuer.rstrip("/")
            password_login = store.load(issuer, self.password_client) is not None
            client = self.password_client if password_login and store.load(issuer, self.client) is None else self.client
        return Session(self._oidc(client), store)

    def login(self, show: Callable[[Any], None]) -> Whoami:
        self._session(self.client).login(show)
        return self.whoami()

    def login_password(self, username: str, password: str) -> Whoami:
        """A person's password login through `password_client` (id-AUTH-000007); the password goes only to the provider."""
        self._session(self.password_client).login_password(username, password)
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

    def token(self) -> str:
        return self._session().access_token()

    # --- the directory -----------------------------------------------------------------
    def directory(self, system: bool = False):
        """The realm's directory with the caller's own rights (id-DIR-000004), or, `system=True`, the local system
        account's: a server's, once it has verified its caller itself (id-DIR-000006)."""
        from catalyst_users.admin import KeycloakAdmin
        from catalyst_users.http import Http

        token = (lambda: self.system_token()["access_token"]) if system else self._session().access_token
        base, realm = self.issuer.rstrip("/").rsplit("/realms/", 1)
        settings = _AdminSettings(f"{base}/admin/realms/{realm}", self.timeout)
        return KeycloakAdmin(settings, token, Http(self.transport, timeout=self.timeout))  # type: ignore[arg-type]

    def users(self) -> list[dict[str, Any]]:
        return [u.__dict__ for u in self.directory().list_users()]

    def groups(self) -> list[dict[str, Any]]:
        return [{"path": g.path, "roles": list(g.roles)} for g in self.directory().groups()]

    def roles(self) -> list[dict[str, Any]]:
        return [{"name": n, "description": d} for n, d in self.directory().roles()]

    def provision_roles(self, roles: list[dict[str, Any]], catalyst_client: str, login_clients: tuple[str, ...]):
        from catalyst_users import provision

        return provision.provision(self.directory(), roles, catalyst_client, login_clients)

    def import_users(self, users: list[dict[str, Any]], roles: list[dict[str, Any]]):
        from catalyst_users import provision

        return provision.import_users(self.directory(), users, roles)

    # --- criteria (id-DIR-000005, id-PROVIDER-000008) -----------------------------------------
    def criteria(self) -> list[dict[str, Any]]:
        return self.directory().criteria()

    def add_criterion(self, name: str, admin: str | None = None) -> list[str]:
        return _add_criterion(self.directory(), name, admin)

    def appoint(self, name: str, username: str) -> None:
        self.directory().appoint(name, username)

    def dismiss(self, name: str, username: str) -> None:
        self.directory().dismiss(name, username)

    # --- a criterion's members (id-DIR-000006) -------------------------------------------------
    def members(self, name: str, *, system: bool = False) -> list[str]:
        return self.directory(system).criterion_members(name)

    def is_member(self, name: str, username: str, *, system: bool = False) -> bool:
        return self.directory(system).is_criterion_member(name, username)

    def add_member(self, name: str, username: str, *, system: bool = False) -> None:
        from catalyst_users.errors import NotFoundError

        directory = self.directory(system)
        try:
            directory.user(username)
        except NotFoundError:
            raise ProviderError(f"{username} is not a person of the realm {self.issuer}") from None
        directory.join_criterion(name, username)

    def remove_member(self, name: str, username: str, *, system: bool = False) -> None:
        self.directory(system).leave_criterion(name, username)

    # --- the local system account: setup's admin (id-AUTH-000006) ---------------------------
    def _sign_in(self, password: str, oidc: Any = None):
        if not self.username:
            raise ProviderError("the system account has no username: run `catalyst-users setup`")
        try:
            oidc = oidc or self._oidc(self.password_client)
            return oidc.password_grant(self.password_client, self.username, password)
        except OIDCError as err:
            if err.error in ("unauthorized_client", "invalid_client"):
                raise ProviderError(
                    f"the realm has no client {self.password_client} allowing a password sign-in "
                    "(on a dev realm, keycloak/sync_clients.py adds it)"
                ) from None
            raise ProviderError(f"Keycloak refused {self.username}'s sign-in at {self.issuer}: {err}") from None

    def _system_tokens(self, oidc: Any = None):
        if not self.password_command:
            raise ProviderError("the system account has no password_command: run `catalyst-users setup`")
        password = secret_from_command(self.password_command, "the system account's password_command")
        return self._sign_in(password, oidc)

    def system_token(self) -> dict[str, Any]:
        tokens = self._system_tokens()
        return {"access_token": tokens.access_token, "token_type": "Bearer", "expires_at": tokens.expires_at}

    def system_whoami(self) -> Whoami:
        oidc = self._oidc(self.password_client)
        claims = oidc.userinfo(self._system_tokens(oidc).access_token)
        return whoami_from_claims(claims, self.issuer.rstrip("/"), self.catalyst_client)


def definition_problems(definition: Any) -> list[str]:
    """What a realm definition holds that it may not: people or secrets (id-PROVIDER-000007)."""
    if not isinstance(definition, dict):
        return ["the realm definition is not a JSON object"]
    found = [f"`{key}`" for key in PEOPLE_KEYS if definition.get(key)]

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}.{key}" if path else key
                if key in SECRET_KEYS and value not in (None, "", [], {}):
                    found.append(f"`{here}`")
                elif key not in PEOPLE_KEYS:
                    walk(value, here)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    walk(definition, "")
    return [f"the realm definition holds a person or a secret: {', '.join(found)}"] if found else []


def _definition(value: Any) -> dict[str, Any] | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            value = json.loads(Path(value).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProviderError(f"cannot read the realm definition {value}: {exc}") from None
    if problems := definition_problems(value):
        raise ProviderError(problems[0])
    return value


def _create_realm(
    http: Any,
    url: str,
    realm: str,
    definition: dict[str, Any],
    ask_server_admin: Callable[[], tuple[str, str]],
    username: str,
    password: str,
    profile: dict[str, str],
    settings: dict[str, Any],
) -> None:
    """The realm from its definition, as Keycloak's server admin (asked for, used once); then its admin, a member of
    the admin group, with the password, not temporary."""
    from catalyst_users.admin import KeycloakAdmin

    if definition.get("realm") not in (None, realm):
        raise ProviderError(f"the realm definition is for {definition.get('realm')!r}, not {realm!r}")
    server_user, server_password = ask_server_admin()
    resp = http.request(
        "POST",
        f"{url}/realms/{SERVER_ADMIN_REALM}/protocol/openid-connect/token",
        form={"grant_type": "password", "client_id": "admin-cli", "username": server_user, "password": server_password},
    )
    if not resp.ok:
        raise ProviderError(f"Keycloak's server admin {server_user} was refused (HTTP {resp.status})")
    token = resp.json()["access_token"]
    created = http.request("POST", f"{url}/admin/realms", json_body={**definition, "realm": realm}, bearer=token)
    if not created.ok:
        raise ProviderError(f"Keycloak did not create the realm {realm} (HTTP {created.status})")
    admin = KeycloakAdmin(_AdminSettings(f"{url}/admin/realms/{realm}", http.timeout), lambda: token, http)  # type: ignore[arg-type]
    try:
        user = admin.create_user(username, profile.get("email"), profile.get("first_name"), profile.get("last_name"))
        admin._call("PUT", f"/users/{user.id}", body={"emailVerified": True})
        admin._call(
            "PUT", f"/users/{user.id}/reset-password", body={"type": "password", "value": password, "temporary": False}
        )
        admin.add_member(str(settings.get("admin_group") or DEFAULT_ADMIN_GROUP), username)
    except CatalystUsersError as err:
        raise ProviderError(f"the realm {realm} was created, but not its admin {username}: {err}") from None


def _add_criterion(admin: Any, name: str, appointee: str | None) -> list[str]:
    added = admin.add_criterion(name)
    if appointee:
        admin.appoint(name, appointee)
        added.append(f"{appointee} administers {name}")
    return added


def _issuer(doc: dict[str, Any]) -> str:
    if doc.get("issuer"):
        return str(doc["issuer"])
    return f"{str(doc['url']).rstrip('/')}/realms/{doc.get('realm') or 'catalyst'}"


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
