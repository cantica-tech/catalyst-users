# Deploying catalyst's identity service

One host, Docker Compose, a reverse proxy in front: Keycloak on Postgres, provisioned for catalyst by catalyst-users.
This is the production shape of the [dev `compose.yaml`](../compose.yaml) (which runs `start-dev` on H2 with its
admin password in the file) and of the hand-typed identity steps of catalyst's `beta/QUICKSTART.md` §1, made
non-interactive. Criteria are shared through git, as catalyst does by default; a `catalyst serve` server is not
part of this deployment.

## Files

| File | What it is |
| --- | --- |
| `compose.yaml` | `postgres`, `keycloak` (`kc.sh start`, loopback ports for the proxy), and the one-shot `provision` |
| `Dockerfile` | The provisioning image: catalyst-users with its `keycloak/` scripts, as an unprivileged user |
| `provision.sh` | What `provision` runs: setup, sign-in, roles and grants, clients, `whoami --system` |
| `make-secrets.sh` | Generates the three secret files under `secrets/` (`0600`; kept once written) |
| `.env.example` | The settings; copy to `.env`. No secret is a setting |

`secrets/` and `.env` are never committed (the repository's `.gitignore`).

## Steps

```sh
cd deploy
cp .env.example .env && "$EDITOR" .env     # KC_HOSTNAME, the admin, the criteria
./make-secrets.sh                           # or write secrets/* yourself, one line each
docker compose up -d --wait keycloak        # Postgres, then Keycloak; waits for /health/ready
docker compose run --rm provision           # creates the realm, the admin, the criteria, the roles
```

Put the reverse proxy in front of `127.0.0.1:8080` for `KC_HOSTNAME`, terminating TLS and setting
`X-Forwarded-*` (`KC_PROXY_HEADERS=xforwarded`). Keycloak's own admin console is at `$KC_HOSTNAME/admin/`, as the
bootstrap admin; restrict it at the proxy if the host is public.

## What provisioning does

`provision.sh` runs, in order, each against the Keycloak on the compose network:

1. `catalyst-users setup --force --type keycloak …`: the realm is absent, so it is created from
   [`keycloak/realm-catalyst.json`](../keycloak/realm-catalyst.json) (groups, roles, clients; no person and no
   secret in it), then the catalyst admin and each `CATALYST_CRITERIA` entry with the admin appointed. On a re-run
   the realm exists, so setup only signs the admin in; `criteria add` then adds any criterion still missing.
2. `catalyst-users login --password` as the admin, the password on standard input from the secret file: a
   container has no browser for the device flow.
3. `catalyst-users roles provision keycloak/catalyst-roles.json`: catalyst's roles, their grants and the claim
   mapper. Adds, never deletes.
4. `keycloak/sync_clients.py`: clients the definition declares and the realm lacks, for a definition that grew
   since the realm was created.
5. `catalyst-users whoami --system`: the smoke test, and what catalyst will see.

The container keeps catalyst-users' settings and the admin's session in the `provision-home` volume; the settings
hold the password *command* (`cat /run/secrets/catalyst_admin_password`), never the password.

## After it

- **A person joins:** a catalyst-admin runs `catalyst-users users add <name> --email … --temporary-password`, and
  appoints or adds them to a criterion (`criteria appoint`, `groups add-member /criteria/<name>/members <name>`).
  On their machine they run `catalyst-users setup --type keycloak --provider '{"url": "<KC_HOSTNAME>", "realm":
  "catalyst"}' --username <name> --password-command …`, then `catalyst-users login`.
- **A deployment points here:** `catalyst identity configure --provider keycloak --issuer <KC_HOSTNAME>/realms/catalyst`.
- **A new criterion:** add it to `CATALYST_CRITERIA` and re-run `provision`, or `catalyst-users criteria add <name>`.
- **Backups:** the `postgres-data` volume is the realm, its people and their credentials; `pg_dump` it. The
  `provision-home` volume is reproducible.
- **Upgrading Keycloak:** change `KEYCLOAK_VERSION`, `docker compose up -d keycloak`; Keycloak migrates the schema.

## Known limits

- The realm is created by `setup` from the definition rather than imported by Keycloak, so `setup` can create the
  admin too. The two paths produce the same realm.
- Keycloak generates the confidential clients' secrets (`catalyst-api`, `catalyst`). A service that introspects
  tokens (`catalyst serve --identity-issuer`) reads `catalyst-api`'s from the admin console; nothing here does.
- No `catalyst serve`, no catalyst-mcp over HTTP (read-only there), no Kubernetes. Each would be another layer on
  this one.
