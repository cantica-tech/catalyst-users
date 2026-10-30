# Changelog

## 0.10.0 — 2026-10-30

Who holds which role is read both ways (REQ-000015, `id-DIR-000008`).

- Added: `catalyst-users users roles NAME` lists the realm roles a person holds, each directly or through which
  groups (a parent group's included); `catalyst-users roles holders ROLE` lists the groups granted a role and who
  holds it, the same way, a subgroup's members included. Both agree; a role reached only through a composite role is
  in neither. `KeycloakAdmin.user_roles` and `role_holders`; reading changes nothing.

## 0.9.0 — 2026-10-30

A person may log in with their username and password (REQ-000014, `id-AUTH-000007`).

- Added: `catalyst-users login --password [--username NAME]` logs a person in without the provider's web page. The
  password is read from standard input (one line) when it is not a terminal, else asked without echo; it is sent
  once, to the provider's token endpoint through its password client (Keycloak: `password_client`), and never stored,
  logged or shown. The tokens are kept as a device login's, and refreshed and revoked through the client that issued
  them. `id-AUTH-000001` is amended: a person's password passes through catalyst-users only on this request.
- Added: `Provider.login_password(username, password)`; the static provider refuses it.

## 0.8.0 — 2026-10-30

A person's details can be changed (REQ-000013, `id-DIR-000007`).

- Added: `KeycloakAdmin.update_user(username, email, first_name, last_name)` and `catalyst-users users update NAME
  [--email --first-name --last-name]` change only the details given, with the caller's own rights. A changed email is
  no longer verified. The username is never changed: what people signed names them by it. The static provider
  refuses, as for every directory change.

## 0.7.0 — 2026-10-25

A criterion's members (REQ-000012, `id-DIR-000006`).

- Added: the facade's `members`, `is_member`, `add_member` and `remove_member`. `is_member` asks the provider now,
  never a token's group claims (a snapshot taken at login); `add_member` refuses anyone the realm does not know;
  removing removes the membership, never the person. Each call uses the caller's rights, or the local system
  account's with `system=True`, for a server that has verified its caller itself.
- Added: Keycloak keeps a criterion's members in `/criteria/<name>/members`, made by `criteria add` (and by adding
  a criterion made before this version again) and covered by its admins' permissions. `static` reads members from
  its people's groups and changes none.
- Added: `catalyst-users criteria members NAME`, which lists them. No command changes them: catalyst does, recording
  each change (`docs/membership.md`).

## 0.6.0 — 2026-10-25

catalyst-users' home is in catalyst's (REQ-000010).

- Changed: the settings, `config.toml` and credentials live in `~/.catalyst/users` (`$CATALYST_HOME/users` when
  catalyst's home is moved; `CATALYST_USERS_HOME` still names another), beside catalyst's `projects/`. A sandbox moves
  both with one variable.
- Added: a `~/.catalyst-users` made by an earlier version is moved there once, the first time it is used, and a link
  to it left in its place so an earlier catalyst-users, vendored by catalyst, still finds the settings. Beside an
  existing new home it is ignored, and said so; a home a variable names never adopts it.

## 0.5.0 — 2026-10-24

Criteria and their admins: the `criterion-admin` (REQ-000009).

- Added: two admin roles, whatever the provider. The `catalyst-admin` administers every criterion and the
  directory; a `criterion-admin` administers only the criteria they were appointed to (every catalyst command there,
  and the membership of that criterion's groups, its admins included), never a user, a group or a role.
- Added: `whoami` reports `administers`, the criteria someone administers. It is never a grant: a `cmd:` grant would
  hold in every criterion. The `Criterion Admin` role (`"scope": "criterion"`) is provisioned with no grant.
- Added: the facade's `criteria`, `add_criterion`, `appoint` and `dismiss`, and `catalyst-users criteria list | add |
  admins | appoint | dismiss`. Keycloak: a criterion is `/criteria/<name>`, its admins `/criteria/<name>/admins`
  (holding `criterion-admin`), confined by the realm's fine-grained admin permissions; `static` reports criteria
  from its people and changes none.
- Changed: setup readies the realm for criteria (the role, `/criteria`, fine-grained admin permissions; only what is
  missing) and `setup --criterion NAME` (repeatable) adds criteria with the admin appointed: onboarding catalyst and
  each of its criteria. `keycloak/realm-catalyst.json` declares them.
- Added: `docs/onboarding.md`, a greenfield onboarding from one JSON document, and its end-to-end test against a
  Keycloak of its own (`tests/integration/onboarding`), which proves a criterion-admin's confinement.

## 0.4.1 — 2026-10-24

- Fixed: typing only, no behaviour change: the provider table read from `config.toml`, the settings setup stores,
  and the admin client setup builds are typed so that pyright reports nothing (catalyst vendors this code).

## 0.4.0 — 2026-10-23

Setup, and the admin as the local system account (REQ-000008).

- Added: `catalyst-users setup` writes `~/.catalyst-users/IAM/settings.json` (`0600`): the provider's type, the
  admin's username, the connection settings and a password command, never a secret. The provider checks itself: not
  up, the JSON is kept unchecked; up without its realm, the realm is created from the JSON's `definition` as the
  server admin (asked for, used once) and the admin with it; up with its realm, the admin is signed in only. A typed
  password goes into the OS keychain, and the command that reads it is stored.
- Changed: with no settings, a command asks for setup in a terminal and refuses otherwise; `--pointer`, explicit
  Keycloak flags or environment, and `config.toml` still choose the provider.
- Changed: the local system account is setup's admin, signed in with the password grant on the realm's
  `catalyst-admin-cli` client; `catalyst-system` and `keycloak/set_system_client.py` are removed.
- Changed: a realm definition holding a person or a secret is refused. `keycloak/realm-catalyst.json` no longer seeds
  users or the API client's secret; the integration tests create their people through the bootstrap admin.
- Added: `keycloak/sync_clients.py` adds the clients the realm file declares to a running dev realm.
- Changed: the provider's token directory is named `credentials` (`store` still accepted).

## 0.3.0 — 2026-10-23

A command-line facade to any identity provider (REQ-000007), and the local system account (REQ-000006).

- Added: providers are registered by name. The built-in ones are modules of `catalyst_users.providers` (`keycloak`,
  `static`); an installed package adds its own through the entry-point group `catalyst_users.providers`, never
  replacing a built-in one. `catalyst-users providers` lists them.
- Added: the provider is chosen by a pointer: `--pointer FILE` or `CATALYST_USERS_POINTER`, else `config.toml`'s
  `provider = "<name>"` with its `[<name>]` table, else the local dev Keycloak as before.
- Changed: every CLI command goes through the provider; `--server`, `--realm` and `--client-id` are Keycloak's
  settings and keep working.
- Added: the local system account, a machine identity: `token --system` and `whoami --system`. Keycloak's is the
  service account of the confidential client `catalyst-system` (client credentials), its secret the first line of
  `secret_command`, run without a shell and never stored or printed.
- Added: the dev realm declares `catalyst-system` without a secret; `keycloak/set_system_client.py` creates it in a
  running realm and keeps the generated secret in the macOS keychain.

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
