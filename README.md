# catalyst-users

A command-line **facade to an identity provider**: users, groups, roles and
sign-in, whatever manages them. Keycloak is the built-in provider; others are
registered by installed packages ([Providers](#providers)). A small
standard-library-only Python core, the `catalyst-users` command line, and a
FastAPI integration.

This is stage one of moving users and groups out of catalyst criteria
(see [docs/development/python-identity-libraries.md](docs/development/python-identity-libraries.md) §10).
Stage two integrates it into catalyst; the core imports only the standard
library so that catalyst's single-file CLI can carry it.

## Quick start (local Keycloak)

```sh
uv sync --all-extras                 # Python 3.11+, the fastapi extra and the dev tools
docker compose up -d                 # Keycloak 26.4.0 on 127.0.0.1:8080, realm "catalyst"

uv run catalyst-users setup          # asks for the provider, its settings, the admin and their password
uv run catalyst-users whoami --system
```

`setup` ([below](#setup)) writes `~/.catalyst/users/IAM/settings.json`; until it exists, a command asks for it in a
terminal and refuses otherwise.

The realm in [keycloak/realm-catalyst.json](keycloak/realm-catalyst.json)
is **for development only**. It holds the realm, a nested group tree, roles that mirror catalyst's, and the clients,
and **no person and no secret** (`id-PROVIDER-000007`); Keycloak generates the confidential clients' secrets:

```text
cantica-tech            [stakeholder]
  catalyst
    developers          [developer]
    maintainers         [release-manager, tech-lead]
catalyst-admins         [catalyst-admin, realm-admin]  (the admin setup creates, or set_admin.py)
criteria                                               (setup --criterion / criteria add: one per deployment)
  <name>
    admins              [criterion-admin]
```

The realm has Keycloak's fine-grained admin permissions on, so a criterion's admins manage the members of its groups
and nothing else ([Criteria](#criteria-and-their-admins)).

Keycloak keeps its database in `.keycloack/` on the host (never in git), so
users and changes survive `docker compose up -d --force-recreate`; delete
that directory to start again from the realm file. A client added to the realm file later reaches a running realm
with `uv run python keycloak/sync_clients.py`, which adds what it lacks and changes nothing else.

On a realm imported by compose, `keycloak/set_admin.py` makes you its admin: it reads your
username and password from the macOS keychain (the item whose service is
`osteck@catalyst-users`, or `--service`), creates or updates you in the realm,
and makes you a member of `catalyst-admins`. The group's other members stay, and are listed; `--sole-admin` removes
them from it (never deletes them), so you are its only member. Nothing it reads is written or printed:

```sh
uv run python keycloak/set_admin.py --email you@example.com [--sole-admin]
```

The realm file declares no client for tests. The integration tests' own client, `catalyst-tests` (a password grant
for the test people), is in [keycloak/realm-catalyst-tests.json](keycloak/realm-catalyst-tests.json); the tests add
it to the realm they run against when it lacks it, as `sync_clients.py --realm-file keycloak/realm-catalyst-tests.json`
does.

## The command line

Every command goes through the configured provider ([Configuration](#configuration)).

| Command | What it does |
| --- | --- |
| `providers` | The registered providers, and where each comes from. |
| `login [--password [--username NAME]]` | Device login: shows a link and a code, waits for you to approve in the browser; no password passes through catalyst-users. With `--password`: your username and password instead, the password read from standard input (one line) or asked without echo, sent only to the provider's token endpoint through its password client, never stored or shown (`id-AUTH-000007`). |
| `whoami [--json] [--system]` | Your username, subject, issuer, groups, roles, catalyst grants and the criteria you administer; with `--system`, the local system account's. |
| `token [--json] [--system]` | Prints a fresh access token, to pass to an API; with `--system`, the local system account's, signed in with the password grant ([below](#the-local-system-account)). Keep it secret. |
| `logout` | Revokes your session at Keycloak and deletes the local credentials. |
| `users list [--search S]`, `add NAME [--email --first-name --last-name --temporary-password]`, `update NAME [--email --first-name --last-name]`, `disable NAME`, `enable NAME`, `groups NAME`, `roles NAME`, `import FILE --roles FILE` | Users. They are disabled, never deleted. `roles` lists a person's realm roles, each directly or through which groups. `update` changes only the details given; a changed email is no longer verified; the username never changes. `import` brings a catalyst `users.json` in, without passwords. |
| `groups list`, `add PATH`, `members PATH`, `add-member PATH NAME`, `remove-member PATH NAME`, `grant-role PATH ROLE` | Nested groups. `add /a/b/c` creates any missing parents. |
| `roles list`, `add NAME [--description D]`, `grant NAME ROLE`, `holders NAME`, `provision FILE [--login-client C]` | Realm roles. `holders` lists the groups granted a role and who holds it, directly or through which groups. `provision` writes a catalyst roles document: each role and what it may run (below). |
| `criteria list`, `add NAME [--admin USER]`, `admins NAME`, `members NAME`, `appoint NAME USER`, `dismiss NAME USER` | Criteria, their admins and their members ([below](#criteria-and-their-admins)). `add` is the catalyst-admin's, and idempotent. `members` only lists: catalyst changes members, recording each change ([docs/membership.md](docs/membership.md)). |

Global options: `--pointer FILE`, `--json`, and Keycloak's `--server`, `--realm`, `--client-id`, before or after the
command (`catalyst-users whoami --json` is `catalyst-users --json whoami`). Exit codes: 0 done, 1 refused or failed,
2 usage.

Directory commands act with **your own** token: Keycloak decides what your
account may change. catalyst-users holds no admin secret.

## Providers

A provider is a class registered under a name; a pointer names it (`id-PROVIDER-000005`).

- **Built in**: the modules of `catalyst_users.providers`: `keycloak`, and `static` (tests only).
- **Registered by a package**: an entry point in the group `catalyst_users.providers`. It never replaces a built-in
  provider of the same name.

```toml
# the pyproject.toml of a package that adds a provider
[project.entry-points."catalyst_users.providers"]
acme = "acme_identity.provider:AcmeProvider"
```

The class builds itself from a pointer and checks one, and implements the operations of
`catalyst_users.provider.Provider`. An operation it cannot do raises `ProviderError`
(`catalyst_users.provider.unsupported(kind, what)` words it):

```python
@dataclass
class AcmeProvider:
    tenant: str
    kind: str = "acme"
    issuer: str = "https://acme.example.com"

    @classmethod
    def from_pointer(cls, doc, store=None, transport=None):
        return cls(tenant=doc["tenant"])

    @staticmethod
    def problems(doc):
        return [] if doc.get("tenant") else ['an "acme" pointer needs a "tenant"']

    def whoami(self, username=None) -> Whoami: ...

    # login, logout, token, users, groups, roles, directory, provision_roles, import_users,
    # system_token, system_whoami
```

## Setup

`catalyst-users setup` asks for (or takes as options): the provider's registered name (`--type`), its settings as JSON
(`--provider`, a file or JSON), the admin's username (`--username`), and their password or a command printing it
(`--password-command`). The provider then checks itself (`id-PROVIDER-000006`):

| The provider | Setup |
| --- | --- |
| not up | writes the settings from the JSON alone, unchecked, and fails (exit 1): start it and run `setup --force` |
| up, without its realm | creates the realm from the JSON's `definition`, as the provider's server admin (asked for, used once, never stored), then the admin (email and names asked for: Keycloak signs no one in without them) in `/catalyst-admins`, and signs them in |
| up, with its realm | signs the admin in, and nothing else |

A refused sign-in writes nothing. Keycloak's JSON:

```json
{"url": "http://localhost:8080", "realm": "catalyst", "definition": "keycloak/realm-catalyst.json"}
```

`definition` (a path, or the realm itself) is used only to create the realm, and refused if it holds a person or a
secret. `~/.catalyst/users/IAM/settings.json` (`0600`, in a `0700` directory) then holds the type, the username, the
connection settings and the password command, never a secret. A typed password goes into the OS keychain (macOS
`security`, else `secret-tool`), and the command that reads it is stored. `--force` replaces existing settings.

## The local system account

The account a client such as catalyst uses locally, on the system's behalf, is setup's admin (`id-AUTH-000006`).
`catalyst-users token --system` prints its access token, and `whoami --system` says who it is, each signing it in
with the username and the first line the password command prints, run without a shell. Keycloak signs it in with the
password grant on `catalyst-admin-cli`, a public client of the realm whose only flow is that grant, and whose tokens
carry the groups, roles, catalyst grants and API audience. Keycloak's built-in `admin-cli` would check the password
but carries none of them. A person who is not the admin still logs in with the device grant.

The password command is a program and its arguments, never a shell line: no pipes, variables or `~`. Written as a
string, it is split by the platform's rules. On macOS and Linux they are a POSIX shell's (`shlex`): quote an argument
with spaces in `'…'` or `"…"`, and a backslash escapes the next character. On Windows they are the ones a Windows
program applies to its own command line, so `C:\Tools\pw.exe --account owner` keeps its backslashes: put a path with
spaces in double quotes (`"C:\Program Files\pw\pw.exe" -a owner`); a backslash is literal except right before a
double quote, where `\"` is a literal quote. In settings.json, `password_command` may also be a JSON list, the program
and each argument as they are, with no quoting at all:
`"password_command": ["C:\\Program Files\\pw\\pw.exe", "-a", "owner"]`.

## The facade, and catalyst's grants

`catalyst_users.provider` is how a client such as catalyst reaches people,
whatever manages them. A pointer document chooses the backend:

```json
{"provider": "keycloak", "issuer": "https://id.example.com/realms/catalyst", "client": "catalyst-cli", "catalyst_client": "catalyst"}
```

`from_pointer(doc).whoami()` returns who is logged in, with their groups,
roles and **grants**. A grant is a client role of the `catalyst` client:

- `cmd:<command>` grants a command, and `cmd:*` grants all of them;
- `reconcile:full` or `reconcile:propose` sets the reconciliation level.

Each catalyst role is a realm role whose composites are the grants it gives,
and groups give roles. The token carries the effective grants, so no client
needs an admin secret to know what someone may do.

`catalyst-users roles provision keycloak/catalyst-roles.json` writes catalyst's
roles into the realm: the realm roles, their grants and the claim mapper. It
adds and never deletes. A role scoped to a criterion (`"scope": "criterion"`) is
written with no grant. A `static` backend, with people declared in the pointer
and nothing verified, exists for tests only: it is refused unless
`CATALYST_ALLOW_STATIC_IDENTITY=1`.

### Criteria and their admins

Two admin roles, whatever the provider (`id-DIR-000005`): the **catalyst-admin** administers every criterion and the
directory, and alone creates a criterion; a **criterion-admin** administers only the criteria they were appointed
to: every catalyst command there, and the membership of that criterion's groups (appointing its other admins), never
a user, a group or a role. A criterion's scope is never a grant (a grant would hold in every criterion): the provider
reports `administers`, the criteria someone administers, and catalyst gives an admin's rights only in a deployment
whose `project_name` that list names. Every provider reports it (empty without criteria); one that cannot add or
appoint says so (`id-PROVIDER-000008`).

With Keycloak, a criterion is the group `/criteria/<name>`; `/criteria/<name>/admins` holds `criterion-admin`, and
fine-grained admin permissions give it the membership of the groups under `/criteria/<name>`, plus the sight of users
(one permission shared by every criterion's admins, since the realm's permissions decide unanimously). `setup
--criterion NAME` (repeatable) readies the realm and adds those criteria with the admin appointed; `criteria add NAME`
adds one later, and again covers groups added under it since. See [docs/onboarding.md](docs/onboarding.md).

A criterion also has **members** (`id-DIR-000006`): with Keycloak, `/criteria/<name>/members`, made with the
criterion and covered by its admins' permissions. The facade's `members`, `is_member`, `add_member` and
`remove_member` reach them, with the caller's rights or, `system=True`, the local system account's (a server's, once
it has verified its caller). `is_member` asks the provider now, never a token's group claims; `add_member` refuses
anyone the realm does not know. catalyst's server checks membership on every request and records every change in
a ledger of its own, so a member added any other way (the provider's console, `groups add-member`) gets no access
until catalyst adopts it. See [docs/membership.md](docs/membership.md).

## FastAPI

```python
from fastapi import Depends, FastAPI
from catalyst_users.fastapi_auth import KeycloakAuth
from catalyst_users.identity import Identity

auth = KeycloakAuth()  # reads CATALYST_USERS_* (needs CATALYST_USERS_API_CLIENT_SECRET)
app = FastAPI()


@app.get("/me")
def me(who: Identity = Depends(auth)):
    return who.signer()


@app.post("/releases", dependencies=[Depends(auth.require_roles("release-manager"))])
def release(): ...


in_catalyst = auth.require_groups("/cantica-tech/catalyst")  # members of any subgroup count


@app.get("/backlog")
def backlog(who: Identity = Depends(in_catalyst)): ...
```

- **401** (with `WWW-Authenticate: Bearer`): a token is missing, malformed or not accepted.
- **403**: the token is accepted, but a required role or group is missing.
- **503**: Keycloak can't be reached.

A runnable example is in [examples/api.py](examples/api.py).

## Configuration

The provider is chosen by a pointer: `--pointer FILE` (JSON) or `CATALYST_USERS_POINTER`, else
`~/.catalyst/users/IAM/settings.json` ([setup](#setup)), else `config.toml`'s `provider` with its table, else explicit
Keycloak settings (flags or environment). Explicit settings win over settings.json, but when they name its own
provider (the same issuer, a loopback host spelled `localhost`, `127.0.0.1` or `::1` alike), settings.json's system
account is kept, and the provider is reached as they spell it. With none of them, a command asks for setup.

```json
{
  "type": "keycloak",
  "username": "owner",
  "provider": {"url": "http://localhost:8080", "realm": "catalyst", "client": "catalyst-cli",
               "password_client": "catalyst-admin-cli", "catalyst_client": "catalyst"},
  "password_command": "security find-generic-password -s catalyst-users -a owner@http://localhost:8080/catalyst -w"
}
```

Keycloak's settings also come from (lowest precedence first): built-in defaults, then
`config.toml`'s top-level keys, then environment variables, then command-line
flags. Given explicitly (environment or flags), they win over the `[keycloak]` table.

| Setting | Environment | Default |
| --- | --- | --- |
| `server_url` | `CATALYST_USERS_SERVER` | `http://localhost:8080` |
| `realm` | `CATALYST_USERS_REALM` | `catalyst` |
| `client_id` | `CATALYST_USERS_CLIENT_ID` | `catalyst-cli` (public, device login) |
| `api_client_id` | `CATALYST_USERS_API_CLIENT_ID` | `catalyst-api` (confidential, introspection) |
| `api_client_secret` | `CATALYST_USERS_API_CLIENT_SECRET` | none; services need it |
| `timeout` | `CATALYST_USERS_TIMEOUT` | `10` seconds |

catalyst-users' home is `users/` in catalyst's: `~/.catalyst/users`, or `$CATALYST_HOME/users`; `CATALYST_USERS_HOME`
names another. A `~/.catalyst-users` made by an earlier version is moved there once, the first time it is used,
and a link to it left in its place, so an earlier catalyst-users (vendored by catalyst) still finds it.

Keycloak builds its issuer from the host you call, and refuses a token at a host other than the one that issued
it: use the same host (`localhost` or `127.0.0.1`) for the CLI and for services. catalyst-users treats the loopback
spellings as one provider when it matches issuers (`config.same_issuer`): settings.json's system account, discovery's
issuer, and an introspected token's `iss`.

## Security model

- **Login** uses the OAuth 2.0 device authorization grant (RFC 8628) on a
  public client, and Keycloak asks for consent.
- **Tokens** are stored in `~/.catalyst/users/credentials.json`: the
  directory is `0700`, the file `0600`, and every write is atomic. Tokens
  never appear in logs, errors or output, except through `token`. An access
  token is refreshed when it has less than 30 seconds left.
- **Services** accept a token only when Keycloak's introspection endpoint
  (RFC 7662) says it is active, its issuer matches, and its audience
  contains `catalyst-api`. Results are cached for at most 30 seconds, never
  past the token's expiry, and keyed by the token's SHA-256. Revoking a
  session takes effect within that window.
- **Transport**: HTTPS is required except for loopback hosts, redirects are
  never followed, and every call has a timeout.
- **Signers**: `Identity.signer()` records issuer and subject, which
  identify the person permanently, plus a snapshot of their username and
  name. A username is never the key.
- **Users** are never deleted, only disabled, so past signatures stay
  resolvable.

## Development

```sh
uv run ruff check && uv run ruff format --check
uv run pytest                                   # unit tests, no network
CATALYST_USERS_IT=1 uv run pytest               # also against the compose Keycloak
rm -rf .keycloack && docker compose up -d --force-recreate   # reset the dev realm (integration runs leave it-* users)
```

The integration tests administer the realm as a `master` admin: compose.yaml's bootstrap admin, or, on a persistent
dev Keycloak whose bootstrap admin was replaced, the one named by `CATALYST_USERS_IT_ADMIN` with a command printing
their password in `CATALYST_USERS_IT_ADMIN_PASSWORD_COMMAND` (e.g. a keychain lookup; the password is never shown).

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs on every push to `development` and every pull
request:

- Ruff and the unit tests, on Python 3.11 and 3.13.
- The integration tests, against the same pinned Keycloak.
- `catalyst trace`: every commit must cite a work item or rule ID, or be a `chore:`. To read the private criterion,
  CI uses a read-only deploy key, stored as the `CRITERION_DEPLOY_KEY` secret.

## Layout

| Path | What |
| --- | --- |
| `src/catalyst_users/` | `config`, `http`, `oidc`, `identity`, `credentials`, `session`, `admin`, `provider` (the facade and its registry), `providers/` (the built-in providers), `cli` (stdlib only) and `fastapi_auth` (the `fastapi` extra) |
| `tests/` | Unit tests with a fake transport; `tests/integration/` runs against Keycloak |
| `keycloak/realm-catalyst.json` | The dev realm: clients, mappers, roles and groups; no person, no secret |
| `compose.yaml` | The pinned local Keycloak |
| `examples/api.py` | An example protected service |
| `docs/` | Research and decisions |
| `.standards/` | The cantica-tech Ruff standard (synced; never edit) |

## Governance

This project is managed by catalyst (`catalyst.toml`). Its rules live in
the criterion: `catalyst where` shows where, and `catalyst list rules`
lists them. The rules are `env-…` (toolchain) and `id-…` (identity
behaviour). Every change is recorded in the journal.
