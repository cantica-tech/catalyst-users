# Changelog

## 0.1.0 — 2026-10-23

The first release: stage one of moving users and groups out of catalyst criteria.

- **Core**, standard library only: device login (RFC 8628), owner-only token storage, refresh and revocation,
  introspection (RFC 7662) with issuer and audience checks, HTTPS-only provider calls without redirects.
- **Directory** in Keycloak with the caller's own rights: users (disabled, never deleted), nested groups with
  inherited roles, realm roles.
- **Signers** recorded by issuer and subject, with a name snapshot.
- **`catalyst-users` CLI**: `login`, `whoami`, `token`, `logout`, `users`, `groups`, `roles`.
- **FastAPI integration**: identity, role and group dependencies; 401, 403, 503.
- A pinned local Keycloak with a dev-only realm; CI with Ruff, unit tests on Python 3.11 and 3.13, Keycloak
  integration tests and `catalyst trace`.
