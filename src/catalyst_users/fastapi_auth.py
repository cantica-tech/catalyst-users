"""FastAPI integration (needs the `fastapi` extra).

    auth = KeycloakAuth()                      # settings from CATALYST_USERS_*

    @app.get("/me")
    def me(who: Identity = Depends(auth)): ...

    @app.post("/release", dependencies=[Depends(auth.require_roles("release-manager"))])
    def release(): ...

A token is accepted only on active introspection with this issuer and audience
(id-AUTH-000004); failures answer 401, 403 or 503 and never say more
(id-API-000001).
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from catalyst_users import config
from catalyst_users.config import Settings
from catalyst_users.errors import CatalystUsersError
from catalyst_users.identity import Identity
from catalyst_users.oidc import OIDCClient

_bearer = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated", {"WWW-Authenticate": "Bearer"})


def _forbidden() -> HTTPException:
    return HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")


def _unavailable() -> HTTPException:
    return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "identity provider unavailable")


class KeycloakAuth:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        oidc: OIDCClient | None = None,
        cache_ttl: float = 30.0,
        cache_size: int = 10_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings or (oidc.settings if oidc else config.load())
        if not self.settings.api_client_secret:
            raise ValueError("KeycloakAuth needs the API client secret (CATALYST_USERS_API_CLIENT_SECRET)")
        self.oidc = oidc or OIDCClient(self.settings, clock=clock)
        self.cache_ttl = min(cache_ttl, 30.0)  # never more than 30 s (id-AUTH-000004)
        self.cache_size = cache_size
        self.clock = clock
        self._cache: dict[str, tuple[float, Identity]] = {}

    def __call__(self, credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Identity:
        if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
            raise _unauthorized()
        return self.identify(credentials.credentials)

    def identify(self, token: str) -> Identity:
        key = hashlib.sha256(token.encode()).hexdigest()  # the cache never holds the token itself
        now = self.clock()
        cached = self._cache.get(key)
        if cached and cached[0] > now:
            return cached[1]
        try:
            claims = self.oidc.introspect(token)
        except CatalystUsersError:  # unreachable, misconfigured or refusing the service's client
            raise _unavailable() from None
        if not self.oidc.accepts(claims):
            self._cache.pop(key, None)
            raise _unauthorized()
        identity = Identity.from_claims(claims, issuer=self.settings.issuer)
        self._remember(key, min(now + self.cache_ttl, float(claims["exp"])), identity)
        return identity

    def _remember(self, key: str, until: float, identity: Identity) -> None:
        if len(self._cache) >= self.cache_size:
            now = self.clock()
            for k in [k for k, (exp, _) in self._cache.items() if exp <= now]:
                del self._cache[k]
            while len(self._cache) >= self.cache_size:
                del self._cache[next(iter(self._cache))]  # oldest first
        self._cache[key] = (until, identity)

    def require_roles(self, *roles: str) -> Callable[..., Identity]:
        """A dependency: the identity must hold every role in `roles` (id-API-000002)."""

        def dependency(identity: Identity = Depends(self)) -> Identity:
            if not all(identity.has_role(r) for r in roles):
                raise _forbidden()
            return identity

        return dependency

    def require_groups(self, *paths: str) -> Callable[..., Identity]:
        """A dependency: the identity must be in every group of `paths`, or under it (id-DIR-000003)."""

        def dependency(identity: Identity = Depends(self)) -> Identity:
            if not all(identity.in_group(p) for p in paths):
                raise _forbidden()
            return identity

        return dependency
