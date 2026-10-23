"""The Keycloak provider, built in (id-PROVIDER-000001, id-PROVIDER-000005).

A person logs in with the device grant and is read from userinfo; the directory is the admin API with the logged-in
person's own rights. The local system account is a confidential client's service account, signing in with the client
credentials grant; its secret is the first line `secret_command` prints, run without a shell (id-AUTH-000006).

    {"provider": "keycloak", "issuer": "http://localhost:8080/realms/catalyst", "client": "catalyst-cli",
     "catalyst_client": "catalyst", "system_client": "catalyst-system",
     "secret_command": "security find-generic-password -s catalyst-system@catalyst-users -w"}
"""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from catalyst_users.provider import (
    DEFAULT_CATALYST_CLIENT,
    ProviderError,
    Whoami,
    whoami_from_claims,
)

DEFAULT_SYSTEM_CLIENT = "catalyst-system"


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
    system_client: str = DEFAULT_SYSTEM_CLIENT
    secret_command: str | list[str] | None = field(default=None, repr=False)
    kind: str = field(default="keycloak", init=False)

    @classmethod
    def from_pointer(cls, doc: dict[str, Any], store: Path | None = None, transport: Any = None) -> KeycloakProvider:
        if problems := cls.problems(doc):
            raise ProviderError(problems[0])
        return cls(
            issuer=str(doc["issuer"]),
            client=str(doc.get("client") or "catalyst-cli"),
            catalyst_client=str(doc.get("catalyst_client") or DEFAULT_CATALYST_CLIENT),
            store=store,
            transport=transport,
            timeout=float(doc.get("timeout") or 10.0),
            system_client=str(doc.get("system_client") or DEFAULT_SYSTEM_CLIENT),
            secret_command=doc.get("secret_command") or None,
        )

    @staticmethod
    def problems(doc: dict[str, Any]) -> list[str]:
        return [] if doc.get("issuer") else ['a "keycloak" pointer needs an "issuer"']

    # --- people ------------------------------------------------------------------------
    def _oidc(self):
        from catalyst_users.http import Http
        from catalyst_users.oidc import OIDCClient

        return OIDCClient(self._settings(), Http(self.transport, timeout=self.timeout))  # type: ignore[arg-type]

    def _session(self):
        from catalyst_users.credentials import CredentialStore
        from catalyst_users.session import Session

        return Session(self._oidc(), CredentialStore(self.store))

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

    def token(self) -> str:
        return self._session().access_token()

    # --- the directory -----------------------------------------------------------------
    def directory(self):
        from catalyst_users.admin import KeycloakAdmin
        from catalyst_users.http import Http

        session = self._session()
        base, realm = self.issuer.rstrip("/").rsplit("/realms/", 1)
        settings = _AdminSettings(f"{base}/admin/realms/{realm}", self.timeout)
        return KeycloakAdmin(settings, session.access_token, Http(self.transport, timeout=self.timeout))  # type: ignore[arg-type]

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

    # --- the local system account (id-AUTH-000006) ---------------------------------------
    def _system_secret(self) -> str:
        if not self.secret_command:
            raise ProviderError("the system account has no secret_command in the keycloak provider's settings")
        argv = self.secret_command if isinstance(self.secret_command, list) else shlex.split(self.secret_command)
        shown = " ".join(argv[:1])
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderError(f"the system account's secret_command ({shown}) failed: {exc}") from None
        secret = done.stdout.split("\n", 1)[0].rstrip("\r")
        if done.returncode != 0 or not secret:
            reason = f"exit {done.returncode}" if done.returncode else "it printed nothing"
            raise ProviderError(f"the system account's secret_command ({shown}) gave no secret: {reason}")
        return secret

    def system_token(self) -> dict[str, Any]:
        tokens = self._oidc().client_credentials(self.system_client, self._system_secret())
        return {"access_token": tokens.access_token, "token_type": "Bearer", "expires_at": tokens.expires_at}

    def system_whoami(self) -> Whoami:
        oidc = self._oidc()
        tokens = oidc.client_credentials(self.system_client, self._system_secret())
        return whoami_from_claims(oidc.userinfo(tokens.access_token), self.issuer.rstrip("/"), self.catalyst_client)


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
