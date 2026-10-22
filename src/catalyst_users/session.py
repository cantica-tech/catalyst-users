"""The logged-in person: login, a fresh access token, who they are, logout."""

from __future__ import annotations

from collections.abc import Callable

from catalyst_users.credentials import CredentialStore
from catalyst_users.errors import CatalystUsersError, NotLoggedInError, OIDCError
from catalyst_users.identity import Identity
from catalyst_users.oidc import DeviceCode, OIDCClient, Tokens

REFRESH_MARGIN = 30.0  # seconds (id-AUTH-000003)


class Session:
    def __init__(self, oidc: OIDCClient, store: CredentialStore | None = None) -> None:
        self.oidc = oidc
        self.store = store or CredentialStore()

    @property
    def _key(self) -> tuple[str, str]:
        return self.oidc.settings.issuer, self.oidc.settings.client_id

    def login(self, show: Callable[[DeviceCode], None]) -> Identity:
        """Device login (id-AUTH-000001): `show` tells the person where to go."""
        code = self.oidc.start_device_login()
        show(code)
        tokens = self.oidc.poll_device_login(code)
        self.store.save(*self._key, tokens)
        return self.identity()

    def tokens(self) -> Tokens:
        """Stored tokens, refreshed when the access token expires within 30 seconds."""
        tokens = self.store.load(*self._key)
        if tokens is None:
            raise NotLoggedInError()
        if tokens.expires_within(REFRESH_MARGIN, self.oidc.clock()):
            try:
                tokens = self.oidc.refresh(tokens)
            except OIDCError:
                raise NotLoggedInError() from None
            self.store.save(*self._key, tokens)
        return tokens

    def access_token(self) -> str:
        return self.tokens().access_token

    def identity(self) -> Identity:
        claims = self.oidc.userinfo(self.access_token())
        return Identity.from_claims(claims, issuer=self.oidc.settings.issuer)

    def logout(self) -> str | None:
        """Revoke at the provider, then delete the local file whatever happened.
        Returns a warning when revocation failed (id-AUTH-000003)."""
        tokens = self.store.load(*self._key)
        warning = None
        if tokens is not None:
            try:
                self.oidc.revoke(tokens)
            except CatalystUsersError as err:
                warning = f"the provider did not confirm revocation ({err}); the local credentials are deleted anyway"
        self.store.delete()
        return warning
