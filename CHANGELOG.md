# Changelog

## 0.2.0 — 2026-10-23

The facade (REQ-000005, catalyst design 29): catalyst-users is how catalyst reaches people, whatever manages them.

- Added: `catalyst_users.provider`: a `Provider` interface built from a pointer document (`provider`, `issuer`,
  `client`, `catalyst_client`); `KeycloakProvider`; `whoami` with groups, roles and grants.
- Added: grants are the catalyst client's roles in the token: `cmd:<command>` (`cmd:*` every one) and
  `reconcile:full|propose`; a role is a realm role composed of the grants it gives.
- Added: `catalyst-users roles provision FILE` writes a catalyst roles document into the realm (roles, grants,
  composites, the claim mapper; adds only); `catalyst-users users import FILE --roles FILE` brings a catalyst
  `users.json` in; `whoami` shows the grants. `keycloak/catalyst-roles.json`: catalyst's roles for the dev realm.
- Added: a `static` backend for tests only, refused unless `CATALYST_ALLOW_STATIC_IDENTITY=1`.
- Changed: the dev realm has the `catalyst` client and the grants mapper on its login clients.

## 0.1.1 — 2026-10-23

- Fixed: `Tokens.from_dict` passes only the fields stored, so a type checker sees no `None` where a string or a
  number is required (no behaviour change).
- Changed: the dev Keycloak keeps its database in `.keycloack/` (never in git), so users survive a recreate; the
  realm file seeds a first start only.
- Added: `keycloak/set_admin.py` makes the owner the dev realm's only admin, reading their username and password
  from the macOS keychain; the realm file no longer makes a dev user an admin, and the integration tests use
  Keycloak's bootstrap admin.

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
