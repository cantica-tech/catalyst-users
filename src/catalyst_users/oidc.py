"""The OIDC client: discovery, device login (RFC 8628), refresh, revocation,
userinfo and introspection (RFC 7662), against one realm."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from catalyst_users.config import Settings
from catalyst_users.errors import (
    LoginDeniedError,
    LoginExpiredError,
    OIDCError,
    ProviderUnavailableError,
)
from catalyst_users.http import Http, Response, check_url

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


@dataclass(frozen=True)
class Endpoints:
    issuer: str
    token: str
    device_authorization: str
    introspection: str
    userinfo: str
    revocation: str


@dataclass(frozen=True)
class Tokens:
    access_token: str
    refresh_token: str | None
    expires_at: float
    refresh_expires_at: float | None = None
    token_type: str = "Bearer"  # noqa: S105 - a token type, not a secret
    scope: str = ""

    def __repr__(self) -> str:  # never show a token (id-AUTH-000002)
        return f"Tokens(expires_at={self.expires_at}, refresh_expires_at={self.refresh_expires_at})"

    @classmethod
    def from_response(cls, payload: dict[str, Any], now: float, previous: Tokens | None = None) -> Tokens:
        refresh_in = payload.get("refresh_expires_in")
        return cls(
            access_token=payload["access_token"],
            refresh_token=payload.get("refresh_token") or (previous.refresh_token if previous else None),
            expires_at=now + float(payload.get("expires_in", 0)),
            refresh_expires_at=now + float(refresh_in) if refresh_in else None,
            token_type=payload.get("token_type", "Bearer"),
            scope=payload.get("scope", ""),
        )

    def expires_within(self, seconds: float, now: float) -> bool:
        return self.expires_at - now <= seconds

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Tokens:
        fields: dict[str, Any] = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**fields)


@dataclass(frozen=True)
class DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None
    expires_at: float
    interval: float


def _error(resp: Response) -> OIDCError:
    try:
        body = resp.json() or {}
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    return OIDCError(body.get("error", f"http_{resp.status}"), body.get("error_description", ""))


class OIDCClient:
    def __init__(
        self,
        settings: Settings,
        http: Http | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.http = http or Http(timeout=settings.timeout)
        self.clock = clock
        self.sleep = sleep
        self._endpoints: Endpoints | None = None

    @property
    def endpoints(self) -> Endpoints:
        if self._endpoints is None:
            resp = self.http.request("GET", f"{self.settings.issuer}/.well-known/openid-configuration")
            if not resp.ok:
                raise ProviderUnavailableError(f"discovery failed with HTTP {resp.status}")
            meta = resp.json()
            if meta.get("issuer") != self.settings.issuer:
                raise ProviderUnavailableError(
                    f"discovery returned issuer {meta.get('issuer')!r}, expected {self.settings.issuer!r}"
                )
            endpoints = Endpoints(
                issuer=meta["issuer"],
                token=meta["token_endpoint"],
                device_authorization=meta["device_authorization_endpoint"],
                introspection=meta["introspection_endpoint"],
                userinfo=meta["userinfo_endpoint"],
                revocation=meta["revocation_endpoint"],
            )
            for url in asdict(endpoints).values():
                check_url(url)
            self._endpoints = endpoints
        return self._endpoints

    # --- device login (id-AUTH-000001) ---------------------------------------

    def start_device_login(self, scope: str = "openid") -> DeviceCode:
        resp = self.http.request(
            "POST", self.endpoints.device_authorization, form={"client_id": self.settings.client_id, "scope": scope}
        )
        if not resp.ok:
            raise _error(resp)
        data = resp.json()
        return DeviceCode(
            device_code=data["device_code"],
            user_code=data["user_code"],
            verification_uri=data["verification_uri"],
            verification_uri_complete=data.get("verification_uri_complete"),
            expires_at=self.clock() + float(data.get("expires_in", 600)),
            interval=float(data.get("interval", 5)),
        )

    def poll_device_login(self, code: DeviceCode) -> Tokens:
        interval = code.interval
        while True:
            if self.clock() >= code.expires_at:
                raise LoginExpiredError("the login code expired before it was approved: run `login` again")
            self.sleep(interval)
            resp = self.http.request(
                "POST",
                self.endpoints.token,
                form={
                    "grant_type": DEVICE_GRANT,
                    "device_code": code.device_code,
                    "client_id": self.settings.client_id,
                },
            )
            if resp.ok:
                return Tokens.from_response(resp.json(), self.clock())
            err = _error(resp)
            if err.error == "authorization_pending":
                continue
            if err.error == "slow_down":
                interval += 5
                continue
            if err.error == "access_denied":
                raise LoginDeniedError("the login was declined")
            if err.error == "expired_token":
                raise LoginExpiredError("the login code expired before it was approved: run `login` again")
            raise err

    # --- tokens (id-AUTH-000003) ---------------------------------------------

    # --- the local admin account (id-AUTH-000006, id-PROVIDER-000006) ----------

    def password_grant(self, client_id: str, username: str, password: str, scope: str = "openid") -> Tokens:
        """Tokens for the local admin account; its password travels only in this request (id-AUTH-000001)."""
        resp = self.http.request(
            "POST",
            self.endpoints.token,
            form={
                "grant_type": "password",
                "client_id": client_id,
                "username": username,
                "password": password,
                "scope": scope,
            },
        )
        if not resp.ok:
            raise _error(resp)
        return Tokens.from_response(resp.json(), self.clock())

    def refresh(self, tokens: Tokens) -> Tokens:
        if not tokens.refresh_token:
            raise OIDCError("invalid_grant", "no refresh token")
        resp = self.http.request(
            "POST",
            self.endpoints.token,
            form={
                "grant_type": "refresh_token",
                "refresh_token": tokens.refresh_token,
                "client_id": self.settings.client_id,
            },
        )
        if not resp.ok:
            raise _error(resp)
        return Tokens.from_response(resp.json(), self.clock(), previous=tokens)

    def revoke(self, tokens: Tokens) -> None:
        token, hint = (
            (tokens.refresh_token, "refresh_token") if tokens.refresh_token else (tokens.access_token, "access_token")
        )
        resp = self.http.request(
            "POST",
            self.endpoints.revocation,
            form={"token": token, "token_type_hint": hint, "client_id": self.settings.client_id},
        )
        if not resp.ok:
            raise _error(resp)

    def userinfo(self, access_token: str) -> dict[str, Any]:
        resp = self.http.request("GET", self.endpoints.userinfo, bearer=access_token)
        if not resp.ok:
            raise _error(resp)
        return resp.json()

    # --- services (id-AUTH-000004) -------------------------------------------

    def introspect(self, token: str) -> dict[str, Any]:
        """The provider's view of `token`, asked with the service's confidential client."""
        if not self.settings.api_client_secret:
            raise ProviderUnavailableError(
                "introspection needs the API client secret (CATALYST_USERS_API_CLIENT_SECRET)"
            )
        resp = self.http.request(
            "POST",
            self.endpoints.introspection,
            form={"token": token, "token_type_hint": "access_token"},
            basic=(self.settings.api_client_id, self.settings.api_client_secret),
        )
        if not resp.ok:
            raise ProviderUnavailableError(f"introspection failed with HTTP {resp.status}")
        return resp.json()

    def accepts(self, claims: dict[str, Any]) -> bool:
        """Whether introspected claims make a token acceptable to this service."""
        if claims.get("active") is not True or claims.get("iss") != self.settings.issuer:
            return False
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud] if aud else []
        if self.settings.api_client_id not in audiences:
            return False
        exp = claims.get("exp")
        return isinstance(exp, (int, float)) and exp > self.clock()
