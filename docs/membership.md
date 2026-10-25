# Membership: who belongs to a project

How catalyst decides who is a member of a project (a criterion), and what catalyst-users' part in it is. This
summarizes catalyst's design 32, "Project membership" (in the catalyst repository, `docs/design/32-project-membership.md`),
and design 30, "Visibility", from catalyst-users' side.

**Status (2026-10-25): being built.** catalyst-users' part is in 0.7.0 (`id-DIR-000006`): the membership calls, the
Keycloak members group and `criteria members`. What exists is marked **today**; catalyst's server side follows.

## In one paragraph

The identity provider (Keycloak today, any other through an adapter) holds each project's members as a group.
catalyst never asks the provider directly: it asks catalyst-users. `catalyst serve`, which embeds catalyst-users,
keeps an encrypted ledger per project recording every change to its membership. The criterion holds only daily
fingerprints of that ledger, so a stolen or corrupted clone neither reveals nor rewrites who belongs. A person gets in
only when the provider **and** the ledger both name them.

## The rules

| Rule                                  | What it means                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------------------------------- |
| The realm, no exception               | Only people registered with the deployment's provider can be members. No guest, no override.      |
| The provider is only a provider       | catalyst depends on catalyst-users, never on Keycloak. Changing provider changes an adapter.      |
| Membership stays within its project   | One ledger per project. Nothing of it goes anywhere but that project's server and criterion.      |
| No member list in a clone             | The criterion is cloned onto many systems; it holds only fingerprints.                            |
| Fail closed                           | The provider and the ledger must agree. A change made in the provider's console grants nothing.   |
| Admin alone holds the master key      | With break-glass access for other admins, any use of which the Admin is told about at once.       |
| No server, admins only                | A criterion shared by git alone has no ledger, so only its admins have access to it.            |

## Who manages members

| Who                  | Where                  | May                                                                 |
| -------------------- | ---------------------- | ------------------------------------------------------------------- |
| **catalyst-admin**   | every criterion        | create criteria, appoint criterion-admins, add and remove members   |
| **criterion-admin**  | their own criteria     | add and remove members, appoint their criterion's other admins      |
| a member             | their project          | reach the project within their clearance; nothing more              |

**Today**: the two admin roles, `criteria add`, `appoint` and `dismiss` exist, and a criterion-admin already manages
the membership of the groups under `/criteria/<name>` ([README](../README.md#criteria-and-their-admins)).
Membership grants no command: grants (`cmd:<command>`…) stay as they are.

## Where things live

| Place                          | Holds                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------ |
| The provider                   | `/criteria/<name>/admins` (**today**) and `/criteria/<name>/members` (new)                  |
| catalyst-users                 | no state of its own: a library, a CLI and a FastAPI dependency, not a service              |
| `catalyst serve`               | each project's membership and user-groups ledgers, encrypted; the member sets in memory    |
| The criterion                  | the ledgers' fingerprints, once a day, in its journal                                      |

### Physically

`catalyst serve` keeps one SQLite database per criterion, by default `~/.catalyst/serve/serve.db` on the machine that
runs it (elsewhere with `--db`). That machine is whichever host the deployment chooses: the Admin's own while they
are alone, a machine or container the organization controls once others join.

| What                                        | Physically                                                                                   |
| ------------------------------------------- | -------------------------------------------------------------------------------------------- |
| The membership and user-groups ledgers      | two tables in the criterion's server database: ciphertext, salt, nonce, signature, head      |
| The project's data key                      | the same database, wrapped by the master key, so useless alone                               |
| The master key and the server's signing key | never in the database: the server machine's keychain, or a key-management service           |
| The member sets                             | the server process's memory, rebuilt from the ledgers when it starts                         |
| The fingerprints                            | the criterion's journal: every admin's clone and the criterion's remote                      |

A copy of the database (a backup, a stolen disk) holds ciphertext and a data key it cannot unwrap. The database is
backed up; the break-glass shares are the master key's backup. If the master key and every share were lost, the
Admin would open new ledgers from the provider's groups, citing the old ledger's last fingerprint.

## When a ledger is opened

1. **Once per server machine**: `catalyst serve key init` makes the master key and the signing key in the keychain;
   `catalyst serve key escrow` splits the break-glass copy.
2. **In the provider**: `catalyst-users criteria add NAME --admin alice` makes `/criteria/NAME/admins` and
   `/criteria/NAME/members`.
3. **The criterion's first server start** (`catalyst serve --criterion NAME`) opens its ledgers:
   - makes the project's data key, wrapped by the master key;
   - writes entry 0, "ledger opened by the Admin for NAME, provider `<issuer>`";
   - adopts each person already in the provider's members group, once the Admin confirms the list, since failing
     closed would otherwise lock them out;
   - writes the first fingerprint at once, then one daily.

## No server, admins only

A criterion shared through git alone (no `catalyst serve`) has no ledger, and anyone who can read its remote reads
all of it, so membership cannot protect anything there. Such a criterion has admins only: the catalyst-admin and its
criterion-admins. `catalyst members add` on it is refused, saying why; adding a member who is not an admin needs the
criterion's server first.

## What catalyst-users adds

### The membership interface

**Today** (0.7.0). Every provider implements four calls beside its existing `criteria`, `add_criterion`, `appoint`
and `dismiss`, each with the caller's own rights or, `system=True`, the local system account's (a server's, once it
has verified its caller):

| Call                                  | Answers or does                                                            |
| ------------------------------------- | -------------------------------------------------------------------------- |
| `members(name)`                       | the usernames in the criterion's members group                             |
| `is_member(name, username)`           | whether the person is in it **now**, asked of the provider, not a token     |
| `add_member(name, username)`          | adds a person of the realm; refuses anyone the provider does not know       |
| `remove_member(name, username)`       | removes them                                                               |

`is_member` asks the provider, never a token's `groups` claim: that claim is a snapshot taken at login and would still
say "member" after a removal. A provider that cannot do one of these says so, as for criteria (`id-PROVIDER-000008`).

### The Keycloak adapter

`/criteria/<name>/members` is created with the criterion (`setup --criterion`, `criteria add`), beside `admins`. The
fine-grained permissions that already give criterion-admins the membership of the groups under `/criteria/<name>`
cover it. **Today** (0.7.0); adding a criterion made before 0.7.0 again creates it.

### The CLI

**Today** (0.7.0): `catalyst-users criteria members NAME` lists the members. There is no command to add or remove one here: changes go
through `catalyst members add|remove`, so the ledger records them. A member added with the provider's console, or
with any tool other than catalyst, is refused access until it is adopted (below).

## How it works, with an example

alice is criterion-admin of `catalyst-users`; bob is a person of the realm.

1. **alice adds bob:**

   ```text
   $ catalyst members add bob --project catalyst-users --reason "reviews the onboarding flow"
   added bob to catalyst-users (ledger entry 4)
   ```

   The server verifies alice's token and that she administers `catalyst-users` (through catalyst-users), checks bob is
   a person of the realm, calls `add_member("catalyst-users", "bob")`, and appends a ledger entry.

2. **bob works**, through the server, with no clone. Each request: his token verified, `is_member` asked of the
   provider, the ledger checked, the answer filtered by his clearance.

3. **alice removes bob**: `catalyst members remove bob …`. His next request gets `403`, though his token is still
   valid.

4. **Someone adds mallory in the provider's console.** She gets `403`: the ledger does not name her. `catalyst check`
   reports the drift, and the Admin removes her or adopts the change with a reason (`catalyst members adopt`).

## The ledger, briefly

- **An entry**: who was added or removed, by whom, when and why.
- **Signed by the server** (Ed25519), with a hash of the actor's token: people hold no signing keys.
- **Chained**: each entry's hash seals every one before it.
- **Encrypted at rest** with the project's own key (ChaCha20-Poly1305 or AES-GCM, Python's `cryptography`). That key
  is wrapped by the master key, held in the OS keychain or a key-management service.
- **Fingerprinted daily** into the project's criterion, whether anything changed or not, so the fingerprints reveal
  neither who, nor how many, nor when. A rewritten ledger no longer matches them.

**Break-glass**: the Admin's master key is also split among other admins (for example any 2 of 3, Shamir's secret
sharing). Using it is written to every ledger, the Admin is told at once, and the key is replaced.

## User groups

A user group (a `UG-` ID, design 30) assigns an entity to several members of a project at once. Its members are
recorded the same way: in a ledger on the server, fingerprinted into the criterion, never listed in a clone. They
must be members of the project; only an admin may add a person of the realm from outside it.

## Changing provider

1. Write an adapter for the new provider, registered through the `catalyst_users.providers` entry point.
2. Recreate each `/criteria/<name>/members` group from the ledger, the record of who is a member.
3. `catalyst check` confirms the provider and the ledger agree.

catalyst and the criteria do not change: the ledger names people by catalyst's user IDs, not the provider's.

## What catalyst-users must build

1. The four membership calls, in the provider protocol and the Keycloak adapter.
2. `/criteria/<name>/members` created by `setup --criterion` and `criteria add`.
3. `criteria members NAME` in the CLI.
4. Tests: a criterion-admin manages members of their criterion only; `is_member` follows a removal at once; a person
   outside the realm is refused.
