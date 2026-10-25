# Onboarding: a greenfield setup from the UI

How a new person on a new machine goes from nothing to a catalyst deployment whose people are catalyst-users', by
entering **one JSON document** in the UI. This is the process the UI will follow; each step names the command it
runs, so the same steps can be run by hand today.

**Status (2026-10-24):** every command below exists (catalyst-users 0.4.1, catalyst 0.106.1). The UI does not have
the onboarding form yet: today "Set up catalyst… → Create a brand new deployment" hands the work to an agent. The
[last section](#what-the-ui-needs) lists what the UI must add.

**Tested:** `tests/integration/onboarding/test_onboarding.py` runs steps 3 to 7 against a Keycloak of its own (Docker,
a free loopback port, no realm imported) with every home in a temporary directory:
`CATALYST_USERS_IT=1 uv run pytest tests/integration/onboarding`. Steps 6 and 7 need a catalyst checkout
(`CATALYST_CHECKOUT`, else `../catalyst`). It also proves a [criterion-admin](#admins-catalyst-admin-and-criterion-admin)
manages their criterion's members and is refused on another criterion, and on users, groups and roles.

## Greenfield means

| Piece                            | At the start                             | At the end                                                       |
| -------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| The identity provider (Keycloak) | running, **no `catalyst` realm**         | the realm, its groups, roles, clients and grants                 |
| catalyst-users on this machine   | no `~/.catalyst/users/IAM/settings.json` | settings naming the provider and the admin (the system account)  |
| The admin                        | does not exist                           | a person in the realm, in `/catalyst-admins`                     |
| The criterion                    | none                                     | `/criteria/<name>`, the admin its first criterion-admin          |
| The project                      | a folder (a git repository), no catalyst | `catalyst.toml`, its criterion in `~/.catalyst/projects/<name>/` |
| The signers ledger               | none                                     | the admin's first signature and their `userid`                   |

## The onboarding JSON

The one document the UI asks for. It holds **no secret**: every password is a command that prints it (or the UI asks
for it in a masked field and stores it in the OS keychain, as `catalyst-users setup` does). The UI refuses a document
with a `password`, `secret` or `token` value.

```json
{
  "iam": {
    "type": "keycloak",
    "provider": {
      "url": "http://localhost:8081",
      "realm": "catalyst",
      "definition": "~/sources/catalyst-users/keycloak/realm-catalyst.json"
    },
    "admin": {
      "username": "oliviersteck",
      "email": "olivier@cantica-tech.com",
      "first_name": "Olivier",
      "last_name": "Steck",
      "password_command": "security find-generic-password -s greenfield@catalyst-users -w"
    },
    "server_admin": {
      "username": "admin",
      "password_command": "printf dev-only-admin-password"
    },
    "roles": "~/sources/catalyst-users/keycloak/catalyst-roles.json"
  },
  "deployment": {
    "name": "greenfield",
    "project": "~/sandbox/greenfield",
    "module": "software-engineering",
    "kernel": "0.106.1",
    "rule_docs": [{ "file": "business-rules.md", "prefix": "br" }],
    "agent": "claude-code"
  }
}
```

| Field              | Means                                                                                                                                             | Used by step |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| `iam.type`         | the provider's registered name (`catalyst-users providers` lists them)                                                                            | 3            |
| `iam.provider`     | the provider's settings; `definition` (a path or the realm itself) is used only to create the realm, and refused if it holds a person or a secret | 3            |
| `iam.admin`        | the first person: the realm's admin and this machine's system account; email and names because Keycloak signs no one in without them              | 3            |
| `iam.server_admin` | Keycloak's own server admin, used once to create the realm, never stored                                                                          | 3            |
| `iam.roles`        | catalyst's roles and the grants each gives                                                                                                        | 5            |
| `deployment.name`  | the deployment's `project_name`, and its criterion in the provider (`setup --criterion`)                                                          | 3, 6         |
| `deployment.*`     | `catalyst init`'s options                                                                                                                         | 6            |

`server_admin` is needed only when the realm does not exist; `rule_docs` may be empty (rule documents can come later).

## Step by step

### 1. Prerequisites (once per machine)

- Python 3.11+, [uv](https://docs.astral.sh/uv/), Docker, git.
- catalyst-users: a checkout, `uv sync --all-extras`.
- catalyst: a release (`catalyst.pyz` and its `framework/kernel`) from the distribution repository.
- VS Code with the catalyst extension, its **IAM → Command** setting naming catalyst-users, e.g.
  `uv run --project ~/sources/catalyst-users catalyst-users`.

### 2. A greenfield sandbox, beside the existing setup

So the test touches nothing of the current deployments, everything gets its own place:

```sh
# an empty Keycloak on port 8081: no realm imported, its own database
docker run -d --name keycloak-greenfield -p 127.0.0.1:8081:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=dev-only-admin-password \
  quay.io/keycloak/keycloak:26.4.0 start-dev

export CATALYST_HOME=~/sandbox/home/catalyst   # instead of ~/.catalyst (catalyst-users' home too: its users/)
mkdir -p ~/sandbox/greenfield && git -C ~/sandbox/greenfield init

# a VS Code of its own, which inherits those variables
code --user-data-dir ~/sandbox/home/vscode ~/sandbox/greenfield
```

The compose service on port 8080 imports the realm at start (`--import-realm`), so it is never greenfield; port 8081
is. Remember to put the admin's password in the keychain first if `password_command` reads it from there
(`security add-generic-password -s greenfield@catalyst-users -a oliviersteck -w`).

### 3. The UI asks for the JSON, and sets catalyst-users up

The extension finds no deployment in the folder and offers **Set up catalyst… → Create a brand new deployment**. The
UI shows the onboarding JSON (the template above, prefilled where it can: the git user's name and email), checks it,
then runs:

```sh
catalyst-users setup --type keycloak \
  --provider '{"url": "http://localhost:8081", "realm": "catalyst", "definition": "…/realm-catalyst.json"}' \
  --username oliviersteck --password-command "security find-generic-password -s greenfield@catalyst-users -w" \
  --server-admin admin --server-admin-password-command "printf dev-only-admin-password" \
  --email olivier@cantica-tech.com --first-name Olivier --last-name Steck \
  --criterion greenfield
```

catalyst-users then checks the provider:

| Keycloak                      | What setup does                                                                                                  |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| not up                        | writes the settings from the JSON alone, unchecked (the UI says so, and stops: the next steps need it)           |
| up, **no realm** (greenfield) | creates the realm from `definition` as the server admin, then the admin in `/catalyst-admins`, and signs them in |
| up, with the realm            | signs the admin in, and nothing else                                                                             |

Signed in, setup readies the realm for criteria (the role `criterion-admin`, the group `/criteria`, and Keycloak's
fine-grained admin permissions, each only if missing) and adds each `--criterion`, the admin appointed to it
(`id-PROVIDER-000008`). A refused sign-in writes nothing. On success it writes `$CATALYST_HOME/users/IAM/settings.json` (type, username,
connection settings, password command; never a secret).

### 4. The UI checks the system account

```sh
catalyst-users --json whoami --system
```

The extension's **Check IAM Account** command already does this. Expected: the admin's username, issuer
`http://localhost:8081/realms/catalyst`, groups `/catalyst-admins` and `/criteria/greenfield/admins`, roles
`catalyst-admin` and `criterion-admin`, administers `greenfield`.

### 5. The UI provisions catalyst's roles

```sh
catalyst-users login     # the admin approves the device login in the browser (link and code shown)
catalyst-users roles provision ~/sources/catalyst-users/keycloak/catalyst-roles.json \
  --login-client catalyst-cli --login-client catalyst-admin-cli
```

Writes each catalyst role as a realm role whose composites are its grants (`cmd:<command>`, `reconcile:<level>`), and
the claim mapper that puts the grants in the token. It adds and never deletes, so it is safe to repeat. It runs with
the admin's **own** login (the system account does not administer the directory): catalyst-users holds no admin
secret, Keycloak decides what the admin may change. Both login clients get the mapper: `catalyst-cli` for people's
device logins, `catalyst-admin-cli` for the system account, whose `whoami --system` then shows `cmd:*`. The
`Criterion Admin` role is `"scope": "criterion"`: it is written with **no** grant, since a grant would hold in every
criterion; its rights come from the criteria its holder administers.

### 6. The UI installs catalyst into the project

From the project's root:

```sh
python3 catalyst.pyz init --kernel <release>/framework/kernel \
  --name greenfield --module software-engineering \
  --rule-doc business-rules.md:br --agent claude-code
```

With no `--identity-issuer`, `init` points the deployment at the provider this machine's catalyst-users is set up for
(step 3): the criterion's `IAM/identity.json` names `http://localhost:8081/realms/catalyst`. The criterion goes to
`$CATALYST_HOME/projects/greenfield/criterion`; `catalyst.toml` is the only file added to the project.

### 7. The first signature

```sh
catalyst identity whoami
catalyst check
```

No one is logged in, so the system account (the admin) signs: catalyst allocates their `userid` and writes the first
line of the criterion's `IAM/signers.jsonl` (issuer, subject, username, name). From then on, every ID they create
ends with that `userid`. `catalyst check` passes.

### 8. The UI shows the deployment

The chain inspector, the Studio and the Team view open on the new deployment. The Team view says people, roles and
grants are managed in catalyst-users.

### 9. After onboarding (not part of this flow)

- **Other people**: `catalyst-users users add NAME --email …` (or `users import`), into a group; each then logs in
  with `catalyst identity login` (the device grant: no password passes through catalyst).
- **The criterion's own admins**: `catalyst-users criteria appoint greenfield NAME` (below).
- **Sharing the criterion**: `catalyst criterion create <url>`.
- **Rule documents and their analysis**: `BOOTSTRAP.md` §2's judgment steps, an agent's work.

## Admins: catalyst-admin and criterion-admin

Two admin roles, whatever the provider (`id-DIR-000005`):

| Role              | Administers                                         | May                                                                                                                       |
| ----------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `catalyst-admin`  | every criterion, and the directory                  | everything: users, groups, roles; creates a criterion and appoints its first admins                                      |
| `criterion-admin` | the criteria they were appointed to, and no other   | in each: every catalyst command at reconciliation `full`; the membership of that criterion's groups, its admins included |

A criterion-admin creates no user, group or role and grants no role. With Keycloak a criterion is the group
`/criteria/<name>`: its admins are the members of `/criteria/<name>/admins` (which holds `criterion-admin`), and the
realm's fine-grained admin permissions let them manage the members of the groups under `/criteria/<name>`. catalyst
gives them an admin's rights only in the deployment whose `project_name` is `<name>` (catalyst-users' `whoami`
reports `administers`).

```sh
catalyst-users criteria list                           # the criteria you may see, and their admins
catalyst-users criteria add NAME [--admin USER]        # the catalyst-admin: a criterion (again: covers its new groups)
catalyst-users criteria appoint NAME USER              # the catalyst-admin, or NAME's admins
catalyst-users criteria dismiss NAME USER              # a membership removed, never the person
catalyst-users groups add /criteria/NAME/developers    # the catalyst-admin; then `criteria add NAME` again
catalyst-users groups add-member /criteria/NAME/developers USER   # NAME's admins too
```

### Onboarding catalyst and its existing criteria

A realm that was onboarded before criteria existed, such as the dev realm the current deployments sign through, gets
them from the catalyst-admin, once, with their own login. Setup readies the realm and adds one criterion per
deployment (`project_name`), the catalyst-admin appointed to each:

```sh
catalyst-users setup --force --type keycloak --provider '{"url": "http://localhost:8080", "realm": "catalyst"}' \
  --username <admin> --password-command "<as before>" \
  --criterion catalyst --criterion catalyst-ui --criterion catalyst-users --criterion catalyst-users-kb
catalyst-users roles provision keycloak/catalyst-roles.json --login-client catalyst-cli --login-client catalyst-admin-cli
```

or, with setup left as it is, `catalyst-users criteria add <name> --admin <admin>` per deployment. Both add what is
missing and change nothing else.

## Resetting the sandbox

```sh
docker rm -f keycloak-greenfield
rm -rf ~/sandbox/home ~/sandbox/greenfield
security delete-generic-password -s greenfield@catalyst-users
```

Nothing of `~/.catalyst` (catalyst-users' home included) or the Keycloak on port 8080 is touched.

## What the UI needs

| Today                                                                  | To add                                                                                                        |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| "Create a brand new deployment" hands off to an agent                  | an onboarding editor: the JSON template, validated (schema, no secret values, paths that exist)               |
| **IAM → Command** names catalyst-users; **Check IAM Account** (step 4) | running `setup` (step 3) and `roles provision` (step 5) with the JSON's values, showing their output          |
| nothing                                                                | a masked field for a password not given as a command, stored in the keychain by catalyst-users                |
| connecting to an existing criterion repo                               | running `catalyst init` (step 6) with the release the UI carries, then `identity whoami` and `check` (step 7) |
| each step's failure is a terminal's                                    | each step shown with its outcome; a failed step stops the flow and nothing after it runs                      |

Open points:

- **The JSON's home**: kept in the project (no: only `catalyst.toml` may be there), in the criterion (it does not
  exist yet at step 3), or only in the UI's memory for the flow. Proposed: not kept; catalyst-users' settings and the
  criterion hold everything it produced.
- **A provider other than Keycloak**: `iam.provider` is the provider's own settings, so the form follows the
  registered provider's schema; only Keycloak's is defined today.
