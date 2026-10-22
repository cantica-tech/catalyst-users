"""The exceptions catalyst-users raises. Messages never contain a token (id-AUTH-000002)."""

from __future__ import annotations


class CatalystUsersError(Exception):
    """Base of every error this package raises on purpose."""


class InsecureURLError(CatalystUsersError):
    """A provider URL is not HTTPS and not on a loopback host (id-AUTH-000005)."""


class ProviderUnavailableError(CatalystUsersError):
    """The identity provider could not be reached, or answered unexpectedly."""


class OIDCError(CatalystUsersError):
    """The provider answered an OAuth/OIDC request with an error."""

    def __init__(self, error: str, description: str = "") -> None:
        self.error = error
        self.description = description
        super().__init__(f"{error}: {description}" if description else error)


class LoginDeniedError(CatalystUsersError):
    """The person declined the device login."""


class LoginExpiredError(CatalystUsersError):
    """The device code expired before the person approved it."""


class NotLoggedInError(CatalystUsersError):
    """No usable credentials: log in first."""

    def __init__(self) -> None:
        super().__init__("not logged in: run `catalyst-users login`")


class AdminError(CatalystUsersError):
    """The admin API refused or failed a directory change."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(message)


class NotFoundError(AdminError):
    def __init__(self, what: str) -> None:
        super().__init__(404, f"not found: {what}")
