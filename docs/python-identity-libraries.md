# Python libraries for users, roles, groups, authentication and signed tokens

*Research note, 2026-10-22. Status and versions were checked online on that
date. Where a fact comes only from a secondary source, the text says so.*

## 1. What we need

| # | Need | Meaning |
| --- | --- | --- |
| 1 | User accounts | Create, verify, disable and delete accounts; store passwords safely. |
| 2 | Roles | Named sets of permissions. |
| 3 | Groups | A group holds users, roles **or other groups**, so membership nests. |
| 4 | Authentication | Login (password, then MFA or passkeys), plus enterprise single sign-on (OIDC, SAML, LDAP/AD). |
| 5 | Signed tokens | Tamper-proof, verifiable tokens carrying identity and group IDs; optionally, signatures on records. |

Constraints: **very simple**, **very secure**, **runs standalone**, and
**plugs easily into an enterprise identity system**.

## 2. Verdict

No single Python library covers all five needs at production quality. The
simple, secure approach combines three small libraries, each the best at one
job, behind one design rule:

> **The application trusts only signed tokens.** Standalone, it issues them
> itself. In an enterprise, the company's identity provider (Entra ID, Okta,
> Keycloak, ZITADEL) issues them, and the application does not change.

| Need | Pick | Runner-up |
| --- | --- | --- |
| Password hashing | **pwdlib** (with Argon2), on **argon2-cffi** | argon2-cffi used directly |
| Roles + nested groups | **PyCasbin** + its SQLAlchemy adapter | OpenFGA (when per-object sharing matters) |
| Signed tokens | **PyJWT** ≥ latest 2.x, or **joserfc** ≥ 1.7.3, with EdDSA/ES256 | pyseto (PASETO v4.public) for internal-only tokens |
| Enterprise SSO | **Authlib** (OIDC/OAuth2) | python3-saml / pysaml2 (SAML), ldap3 (LDAP) |
| Bundled identity provider (optional) | **Keycloak** | ZITADEL |

**UserHarbor** isn't suitable yet: its authors say it isn't production-ready
(details in §3).

**For catalyst itself the answer is different** (§10): the catalyst CLI is
stdlib-only, so the libraries above don't drop into it. Users and groups move
out of the criterion to **Keycloak, used only through standard OIDC**, and
catalyst keeps its own role policy.

## 3. All-in-one user-management libraries

These promise accounts, roles and login in one package. They are the most
convenient option and the least flexible.

### UserHarbor

- **What:** A framework-agnostic user-management core. Separate packages
  connect it to SQLAlchemy, SMTP and FastAPI. MIT licence.
- **Pros:** Clean separation (no HTTP routes in the core; storage behind a
  contract-tested interface). It covers registration, email verification,
  login, sessions (log out one session or all of them), password reset,
  roles and permissions, and FastAPI guards (`require_role`,
  `require_permission`).
- **Cons:** The authors say it is in early development, its API may change
  often, and it is **not ready for production**. It has 19 stars and one
  follower. Groups aren't mentioned. The session-token format isn't
  documented (it uses a `SECRET_KEY`, so a symmetric signature is likely:
  every verifier would need the secret). The hashing algorithm isn't
  documented either.
- **Opinion:** A good design to watch, and possibly to contribute to.
  Don't build anything "very secure" on it yet. Check again once it reaches
  1.0 and has had an outside security review.

### fastapi-users

- **What:** Ready-made registration, login, verification, password reset and
  JWT or database-backed sessions for FastAPI.
- **Pros:** Widely used and well documented. It plugs into SQLAlchemy or
  Beanie, and has OAuth login.
- **Cons:** **In maintenance mode** (official README): security fixes only,
  no new features, and an unnamed successor toolkit is in progress. Tied to
  FastAPI. No roles or groups beyond an `is_superuser` flag.
- **Opinion:** Fine for an existing FastAPI app. Don't start something new
  on a library its own maintainers are replacing.

### Flask-Security-Too

- **What:** The maintained successor to Flask-Security: accounts, roles,
  2FA (TOTP, SMS, email), WebAuthn/passkeys, password policies and
  rate-limit hooks.
- **Pros:** Mature and actively maintained. Strong security defaults. The
  most complete all-in-one package in the Python ecosystem.
- **Cons:** Flask only. Roles are flat (no nested groups). Login is
  session-cookie based; tokens are its own format, not standard JWT/OIDC.
- **Opinion:** The best all-in-one choice **if** the product is a Flask app.
  Pair it with Casbin for groups.

### Django `contrib.auth` + django-allauth + django-guardian

- **What:** Django's built-in users, groups and permissions;
  `django-allauth` for social login, OIDC, SAML and MFA; `django-guardian`
  for per-object permissions.
- **Pros:** The most battle-tested stack in Python, with a large security
  track record and audited defaults (it supports Argon2 hashing).
- **Cons:** Django only. Built-in groups don't nest (a group can't contain
  another group). The token layer needs extra packages (e.g.
  `djangorestframework-simplejwt`).
- **Opinion:** The obvious choice if the product is Django. Otherwise it
  doesn't apply.

### "Auth" (auth.readthedocs.io)

- **What:** A self-described enterprise system: hierarchical users, roles and
  permissions, JWT, usable as a library or a REST API.
- **Pros:** Covers hierarchical roles, which most libraries don't.
- **Cons:** Effectively a one-maintainer project with little visible
  adoption, and it hasn't been audited.
- **Opinion:** Interesting to read for its model. Don't depend on it.

## 4. Password hashing

| Library | Pros | Cons | Opinion |
| --- | --- | --- | --- |
| **argon2-cffi** | The reference Argon2id binding (the 2015 Password Hashing Competition winner, recommended by OWASP); passlib's own docs recommend it as the Argon2 backend; actively maintained. | Argon2 only; you handle algorithm migration yourself. | **The base layer.** Always use it, directly or through pwdlib. |
| **pwdlib** | A modern, small wrapper (`PasswordHash.recommended()`), with Argon2 and bcrypt, and rehash-on-verify built in. Written by the fastapi-users author as passlib's replacement. | Deliberately not a full passlib replacement; there's no support for legacy hash formats. | **Pick.** The simplest correct API. |
| bcrypt | Mature and well understood. | Truncates passwords at 72 bytes; weaker against GPU attacks than Argon2id. | Only for compatibility with existing hashes. |
| ~~passlib~~ | Supported a very wide range of algorithms. | Unmaintained since 2020; reported broken from Python 3.13. | **Avoid.** |

## 5. Roles and groups (authorization)

This is where nested groups ("a group holds users, roles or other groups")
are decided. There are two families: **embedded engines** that run inside
the application (simple, standalone), and **authorization servers** (more
power, one more service to operate).

### PyCasbin (embedded) — recommended

- **What:** The Python port of Casbin (Apache project), a policy engine for
  ACL, RBAC, RBAC with domains (tenants), and ABAC. It's described in a
  small model file (the PERM metamodel: policy, effect, request, matchers).
  Latest release 2.8.0 (February 2026).
- **Pros:**
  - Role inheritance is native: `g, alice, editors`,
    `g, editors, staff`, `g, staff, reader` gives alice everything reader
    has. One mechanism covers **users in groups, groups in groups and roles
    in roles**, which is exactly need #3.
  - Domains give multi-tenancy (the same user can hold different roles per
    organization).
  - Storage adapters (SQLAlchemy 1.9.0, plus async variants) keep policies
    in the application's own database; a plain file works for small setups.
  - Pure Python, no extra service, so it runs standalone. Language-neutral
    policies (the same model works in Go, Java, Node.js), and a large user
    community (the main Casbin repository has about 19k stars).
- **Cons:**
  - It is only an engine: no users, passwords or login.
  - The model-file syntax takes an hour to learn, and a wrong matcher
    silently grants or denies access. **Test the policies.**
  - Policies are loaded into memory; very large per-object policy sets
    (millions of rows) need filtered loading or a different tool.
- **Opinion:** **Pick.** It's the simplest tool that models nested groups
  properly, and it needs no extra infrastructure. In an enterprise, map the
  identity provider's `groups` claim onto Casbin subjects.

### OpenFGA (authorization server, CNCF sandbox, from Okta/Auth0)

- **What:** A Zanzibar-style (Google's authorization system) server for
  relationship-based access control, with an official Python SDK.
- **Pros:** Built for nested groups and per-object sharing ("member of a
  team inside the department that owns this document"). It has a visual
  playground for testing models, scales to very large numbers of
  relationships, and Okta maintains the SDKs.
- **Cons:** One more service, with its own database, to run, secure and back
  up. Younger and less battle-tested than SpiceDB at very large scale.
  Overkill for "user has role X".
- **Opinion:** The upgrade path once the product needs sharing per document
  or per resource. Not where to start.

### SpiceDB (AuthZed)

- **What:** The most faithful Zanzibar implementation; Python client
  `authzed`.
- **Pros:** Strong consistency guarantees ("zookies"), a Watch API, mature
  at scale, with commercial backing.
- **Cons:** Heavier to run than OpenFGA, and has its own schema language.
- **Opinion:** Pick it over OpenFGA only if strict consistency is a hard
  requirement.

### Cerbos (policy decision point)

- **What:** A stateless policy-decision service with YAML policies and a
  Python SDK.
- **Pros:** Policies live in git, can be tested and reviewed; "derived
  roles" add attribute conditions on top of RBAC. Stateless, so easy to
  scale.
- **Cons:** It stores no group memberships. The caller passes the
  principal's roles in, so nesting has to be resolved elsewhere. Another
  service to run.
- **Opinion:** A good fit when roles come entirely from the enterprise
  identity provider and only the rules need to live in our code. Weaker
  than Casbin for standalone use.

### Oso

- **What:** The open-source Polar library, now deprecated (December 2023,
  security and critical fixes only). Oso Cloud is the hosted product.
- **Opinion:** **Avoid** the library (deprecated). Oso Cloud is a paid
  external dependency, which conflicts with "standalone".

### Permit.io / WorkOS FGA

- **What:** Hosted authorization services (Permit.io is built on OPA/OPAL)
  with Python SDKs and visual policy editors.
- **Opinion:** Quick to adopt, but each makes a vendor part of every access
  check. That rules both out for standalone and for most
  security-conscious enterprises.

### edx-rbac

- Django-only, reads roles from JWTs, and its releases date from around
  2019. **Not relevant.**

## 6. Signed tokens

**Algorithm rule:** sign with an **asymmetric** key (EdDSA/Ed25519 or
ES256). Services can then verify with the public key, which is published at
a JWKS endpoint (the standard URL listing public keys), and never hold the
secret. That is also what enterprise identity providers do, which keeps
both modes identical.

| Library | Pros | Cons | Opinion |
| --- | --- | --- | --- |
| **PyJWT** | The most widely used Python JWT library; FastAPI's docs moved to it from python-jose; simple API; `PyJWKClient` for JWKS. | Several 2026 advisories (key confusion, an algorithm allow-list bypass with `PyJWK` keys, `PyJWKClient` URL/redirect handling), fixed in 2.12.1–2.14.0 according to distro advisories. **I didn't confirm the exact boundaries from PyJWT's own release notes.** JWS only, no encryption (JWE). | **Pick**, pinned to the latest release, always passing `algorithms=[...]` explicitly and never using untrusted JWKS URLs. |
| **joserfc** | By the Authlib author; covers all the JOSE standards (JWS, JWE, JWK, JWT); strict typing; registry-based algorithm control. | Two 2026 CVEs (a low-severity padding issue fixed in 1.7.2, and an issuer-claim validation bypass fixed in 1.7.3). Smaller user base than PyJWT. | **Co-pick.** Prefer it if encrypted tokens are needed or Authlib is already in use. Pin ≥ 1.7.3. |
| **pyseto** (PASETO) | Removes the "algorithm agility" class of bugs: each version fixes its algorithms (v4.public = Ed25519). Passes the official PASETO test vectors; supports PASERK keys. | Enterprise identity providers, gateways and SIEMs don't speak PASETO. Smaller community. | Good for **internal** service-to-service tokens. Can't be the enterprise-facing format. |
| `itsdangerous` | Tiny, from the Flask team; ideal for signed links (password reset, email verification). | Symmetric (shared secret) and a non-standard format. | Use only for one-time links. |
| ~~python-jose~~ | — | Last release in 2021; known CVEs (e.g. CVE-2024-33663). | **Avoid.** Migrate using the joserfc migration guide. |

**Note for any choice:** the JWT libraries have had several security fixes
in 2026. Whatever is picked: pin the version, watch its advisories
(Dependabot or `pip-audit`), and keep token verification in **one** module
of our own with tests for the classic attacks (`alg: none`, HS/RS key
confusion, a missing `exp`, the wrong `aud`).

### Signing records, not just tokens

If "signature" also means *a person signs an approval*, a token isn't the
right tool, because tokens expire and prove who someone was at login, not
what they approved. Use **`cryptography`** (pyca) with **Ed25519**: give each
user (or their device) a key pair, sign a canonical hash of the record, and
store the signature, key ID and timestamp. For signatures that anyone must be
able to verify later, look at **Sigstore** (`sigstore-python`), which signs
with short-lived keys tied to an OIDC identity and records each signature in
a public transparency log.

## 7. Authentication and enterprise integration

| Library | Role | Pros | Cons | Opinion |
| --- | --- | --- | --- | --- |
| **Authlib** | OAuth2/OIDC client **and** server; framework integrations for Flask, Django, Starlette/FastAPI | One library covers "log in with the company identity provider" and "be our own OIDC issuer"; same author as joserfc; actively maintained. | Server-side features require careful configuration. | **Pick.** This is the enterprise connector. |
| python3-saml (OneLogin) / pysaml2 | SAML 2.0 service provider | Needed for older enterprise identity systems that only offer SAML. | XML signatures are a historic source of vulnerabilities; depends on the native xmlsec library. | Only if a customer requires SAML, and prefer letting a bundled identity provider handle SAML instead. |
| ldap3 | LDAP/Active Directory | Pure Python, mature. | Talking LDAP directly means handling passwords ourselves. | Prefer to federate through an identity provider instead. |
| pyotp, py_webauthn | TOTP second factor, passkeys | Small and standard. | We own the enrolment and recovery steps. | Use them if we run login ourselves. |

### Identity providers to bundle or connect to (not libraries, but the enterprise answer)

| Product | Pros | Cons | Opinion |
| --- | --- | --- | --- |
| **Keycloak** | The de facto open-source standard: OIDC, SAML, LDAP/AD federation, **nested groups**, fine-grained admin. In one October 2026 benchmark it was fast (about 72 ms of CPU per password login). | Java, heavy, and its configuration surface is large. | **Default** when we must ship our own identity provider. Client: `python-keycloak`. |
| ZITADEL | Multi-tenant by design (organizations), API- and Terraform-friendly, passkeys built in. | Weaker LDAP support; check with a proof of concept. | Good for multi-tenant SaaS. |
| Authentik | Python/Django core, visual flow editor, proxy authentication for apps that can't do OIDC. | The same benchmark measured about 1.2 s of CPU per password login, so it may need more CPU at scale. | Good for small and medium internal deployments. |
| Ory Kratos + Keto | Headless (API-first) identity plus Zanzibar-style permissions. | Two Go services; you build the UI yourself. | When full control of the login UI is a requirement. |

## 8. Recommended architecture

### Standalone mode

```text
login ─► pwdlib(argon2id) verify ─► issue access JWT (EdDSA, 5–15 min, kid)
                                    + rotating refresh token (stored server-side)
request ─► verify JWT (PyJWT/joserfc, pinned alg/iss/aud/exp)
        ─► Casbin.enforce(sub, domain, obj, act)   # nested groups resolved here
public keys ─► /.well-known/jwks.json
```

### Enterprise mode

```text
login ─► company IdP (Entra ID / Okta / Keycloak) via Authlib OIDC
request ─► verify IdP JWT against its JWKS (same verifier module)
        ─► map `groups` claim → Casbin subjects ─► Casbin.enforce(...)
```

The authorization code and the token verifier stay the same in both modes.
Only who issues tokens and where users live changes. Add OpenFGA later if
per-object sharing becomes a requirement.

## 9. Security baseline (whatever the libraries)

1. Hash with Argon2id; rehash on login when the parameters change.
2. Verify tokens with an explicit algorithm allow-list. Never accept
   `none`, and never let HS* (shared-secret) algorithms accept an
   asymmetric public key as the secret.
3. Always check `exp`, `nbf`, `iss` and `aud`; keep access tokens short-lived.
4. Put **group or role IDs** in tokens, never permission lists. Decide
   permissions on the server, so that revoking access takes effect
   immediately.
5. Rotate refresh tokens and detect reuse. Keep a server-side session
   record so a session can be revoked.
6. Rotate signing keys through `kid` and JWKS. Keep private keys in a
   KMS/HSM or Vault where available.
7. Rate-limit login, lock out repeated failures, and require MFA or
   passkeys for administrators.
8. Write an append-only audit log of every account, role and group change.
9. Run `pip-audit` (or Dependabot) on every build; the JWT libraries above
   all had advisories in 2026.

## 10. Decision for catalyst: take users and groups out of the criterion

*Proposed, not yet decided or implemented. Under catalyst's rules, the change
is a feature (a `REQ-`), because it changes how the user, role and gate rules
behave.*

### 10.1 What catalyst has today

- Each criterion holds its own user registry, `IAM/users/users.json`
  (`name`, `userid`, `git_username`, `roles`, `active`, `registered`,
  `notes`), and its role definitions, `IAM/roles/roles.json` (role →
  commands it grants, plus a reconciliation level).
- Changes go only through `catalyst user add|modify|remove|assign-role`,
  each one journaled. A user is never deleted, only deactivated, so old
  signatures stay resolvable (law L7).
- Authorization is already in catalyst. `scripts/catalyst/permissions.py`
  maps roles to commands. `scripts/catalyst/gates.py` lets an approval count
  only when its signer is active, holds the gate's role and didn't write the
  change.
- A workspace has its own criterion with its own users; its member projects
  inherit them, read-only.
- `catalyst serve` issues its own bearer tokens (`cst_…`) and stores only a
  SHA-256 hash of each, with the user ID it belongs to.
- A "signature" today is the signer's name or git username written into the
  journal and gate records. It isn't cryptographic.

### 10.2 The constraint that decides it

The catalyst CLI is **stdlib-only and ships as a single zipapp**
(`dist/catalyst.pyz`). The libraries recommended in §2 don't fit: PyJWT with
EdDSA/ES256 needs the compiled `cryptography` package, and PyCasbin brings its
own dependencies. Catalyst also doesn't need another authorization engine,
because it already has one (§10.1). What's missing is a **trusted source of
identity and group membership**. The simple fix is to take that work out of
catalyst, not to add libraries to it.

### 10.3 Choice: Keycloak, used only through OIDC

- **A ready-made product:** accounts, nested groups (subgroups inherit their
  parent's roles), roles, MFA and passkeys, an admin UI and an audit log,
  with no code of ours. Apache-2.0, a CNCF project.
- **Enterprise-ready:** it connects to LDAP/AD and to Entra ID or Okta.
  Because catalyst speaks only standard OIDC, a company that already runs
  Entra ID or Okta can skip Keycloak entirely.
- **Standalone:** one container, Postgres optional. It's the heaviest
  option (Java, roughly 0.5–1 GB of RAM), which is acceptable for a server;
  a solo user has the `local` fallback (§10.5).
- **Keeps the CLI stdlib-only:**
  - Login uses the OAuth 2.0 device flow (RFC 8628: open a URL, enter a
    code), which is plain HTTP through `urllib`.
  - Tokens are stored in the existing `~/.catalyst/credentials` file, with
    owner-only permissions.
  - `catalyst serve` checks a token through **token introspection**
    (RFC 7662) instead of verifying the signature locally. That needs no
    crypto library, and revoking access takes effect immediately.

### 10.4 What moves out and what stays

| Today in the criterion | After |
| --- | --- |
| `IAM/users/users.json` (people, `active`) | **Keycloak.** Deactivating a user there replaces `catalyst user remove`. |
| Who holds which role | **Keycloak groups**, sent as the `groups` claim of the token (full group paths). Workspace → project inheritance becomes a parent group with subgroups. |
| `IAM/roles/roles.json` (role → commands, reconciliation level) | **Stays.** It's governance policy, versioned, journaled and gated like any rule. Only who *holds* a role moves out. |
| Journal signer, gate `actor` | **Stays, as a permanent reference:** the identity provider's issuer (`iss`) plus the user's ID there (`sub`), with a display-name snapshot. |
| `serve.db` token table | Replaced by tokens that Keycloak (or the enterprise identity provider) issues. |

Files affected in the catalyst repository: `scripts/catalyst/admin.py`,
`gates.py`, `serve.py`, `workspace.py`, `criterion.py`, `init.py`, and the
documentation in `docs/users-registry.md`.

### 10.5 Risks and how to handle them

1. **Law L7 (users never deleted, signatures stay resolvable).** An
   enterprise identity provider *will* delete people. The criterion must
   never need a live lookup to resolve an old signature: every journal and
   gate entry snapshots `iss`, `sub` and the display name at signing time.
2. **Offline work.** Role checks use the groups in the cached token until it
   expires, then require a refresh. A deployment that should never depend on
   an identity provider uses a **`local` provider** behind the same
   interface: today's JSON registry, moved out of the criterion into its own
   small shared git repository (this `catalyst-users` repository is a
   candidate).
3. **Signatures aren't cryptographic yet.** If approvals must be verifiable
   later, sign the criterion's git commits with keys tied to the same
   identity: `gitsign` (Sigstore, keyless, uses the OIDC login), or SSH
   commit signing with an allowed-signers file generated from the identity
   provider. This is a separate decision, made after the move.
4. **Ties to one product.** Avoided by depending only on OIDC (device flow,
   introspection, the `groups` claim). Keycloak is the default, not a
   requirement.

### 10.6 Alternatives considered

| Option | Why it ranks lower |
| --- | --- |
| ZITADEL | Lighter, multi-tenant by design, but weaker LDAP support, which matters for enterprises. |
| Authentik | Easy to run, but one October 2026 benchmark measured about 1.2 s of CPU per password login. |
| Our own service (pwdlib + PyCasbin + PyJWT) | Full control, but we would own a login server's security, which is the opposite of "very simple". |
| Keep the registry in the criterion | Doesn't meet the goal; no enterprise single sign-on, MFA or central deactivation. |

### 10.7 Decision, 2026-10-23: a command-line facade to any provider

The owner decided that catalyst-users is a **command-line facade to any identity
provider**, not a Keycloak client. Keycloak is one provider among others.

- **Providers are registered by name.** The built-in ones are modules of
  `catalyst_users.providers` (`keycloak`; `static` for tests). An installed
  package adds its own through the entry-point group `catalyst_users.providers`,
  and never replaces a built-in one. Registering a module path directly in the
  pointer was rejected: the pointer would run whatever code it names.
- **catalyst-users holds the configuration.** `~/.catalyst-users/config.toml`
  names the provider and its settings (`--pointer FILE` overrides). A client,
  such as catalyst's VS Code extension, needs only the command to run.
- **The local system account is a machine identity, held by catalyst-users.**
  `catalyst-users token --system` signs it in through the provider. Keycloak's
  is the service account of the confidential client `catalyst-system` (client
  credentials grant). Its secret comes from a command in the provider's settings
  (the macOS keychain locally), so no client holds a credential. A person's
  password is never used: the realm's clients have the password grant off, and
  the OAuth 2.1 draft drops that grant.

## 11. What's left

- **Catalyst decision (§10):** the owner accepts or rejects it. If accepted:
  a design note and a `REQ-` covering the provider interface
  (`local` | `oidc`), the move of user records out of the criterion, the
  signer snapshot format, and migrating existing `users.json` records into
  Keycloak or the `local` repository.
- **Check the Keycloak specifics in a proof of concept:** the device flow, a
  group mapper sending full paths, introspection from `catalyst serve`, and
  the memory footprint.
- **Framework:** the final pick for accounts depends on whether the product
  is FastAPI, Flask, Django or framework-free. Flask → Flask-Security-Too;
  Django → contrib.auth + allauth; otherwise pwdlib plus a small account
  module of our own.
- **PyJWT advisory boundaries:** confirm the exact fixed versions from
  PyJWT's GitHub security advisories before pinning.
- **UserHarbor:** check again at 1.0, and see whether it adds groups and
  documents its token format and hashing algorithm.
- **fastapi-users successor:** check whether the announced toolkit has
  shipped.
- **Record signatures:** decide whether "signature" includes signing
  approvals (§6, last subsection). If so, design key custody (per-user keys
  vs. Sigstore).
- **Proof of concept:** a Casbin model for users → groups → groups → roles
  with domains, plus tests that grant and deny access through each level of
  nesting.

## Sources

- UserHarbor: [GitHub organization](https://github.com/userharbor), [DEV Community article](https://dev.to/aairom/decoupled-user-management-in-python-1f27)
- fastapi-users: [GitHub README (maintenance mode)](https://github.com/fastapi-users/fastapi-users)
- Auth: [documentation](https://auth.readthedocs.io/), [concepts](https://auth.readthedocs.io/en/latest/concepts.html)
- edx-rbac: [PyPI](https://pypi.org/project/edx-rbac/)
- Password hashing: [pwdlib on PyPI](https://pypi.org/project/pwdlib), [passlib install docs](https://passlib.readthedocs.io/en/stable/install.html), [Gentoo passlib package](https://packages-cdn-origin.gentoo.org/packages/dev-python/passlib), [FastAPI template discussion on passlib](https://gh.nn.ci/fastapi/full-stack-fastapi-template/discussions/1369)
- PyCasbin: [GitHub](https://github.com/apache/casbin-pycasbin), [PyPI](https://pypi.org/project/casbin/), [release 2.8.0 (mirror)](https://simple-repository.app.cern.ch/project/pycasbin), [SQLAlchemy adapter](https://pypi.org/project/casbin_sqlalchemy_adapter), [adapter 1.9.0 (mirror)](https://simple-repository.app.cern.ch/project/sqlalchemy_adapter)
- Oso: [0.27.1 changelog (deprecation)](https://osohq.com/docs/oss/project/changelogs/2023-12-18.html), [PyPI](https://pypi.org/project/oso/0.27.1)
- Comparisons: [Casbin vs Oso](https://stackshare.io/stackups/casbin-vs-oso), [Casbin vs Permit.io](https://stackshare.io/stackups/casbin-vs-permit-io), [Oso on Permit.io alternatives](https://www.osohq.com/learn/permitio-alternatives) (vendor)
- OpenFGA / SpiceDB: [OpenFGA vs Permify vs SpiceDB 2026](https://www.pkgpulse.com/guides/openfga-vs-permify-vs-spicedb-zanzibar-authorization-2026), [AuthZed vs OpenFGA](https://startwithidentity.com/compare/authzed-vs-openfga/), [OpenFGA overview](https://startwithidentity.com/vendors/authorization/openfga.md), [WorkOS SpiceDB migration](https://workos.com/docs/fga/migration-spicedb)
- Cerbos: [GitHub](https://github.com/cerbos/cerbos/)
- WorkOS: [RBAC for Python APIs](https://workos.com/blog/rbac-authorization-python-apis-workos)
- PyJWT advisories: [ALAS2023-2026-2051](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-2051.html), [ALAS2023-2026-1842](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-1842.html), [SUSE 2026:22238-1](https://linuxsecurity.com/advisories/suse/suse-2026-22238-1-python-pyjwt), [SUSE 2026:20839-1](https://linuxsecurity.com/advisories/suse/python-pyjwt-suse-2026-20839-1), [Ubuntu python3-jwt](https://www.ubuntuupdates.org/package/core/stonking/main/security/python3-jwt)
- joserfc / python-jose: [CVE-2026-62995 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2026-62995), [CVE-2026-75509 (OSV)](https://api.osv.dev/v1/vulns/CVE-2026-75509), [migrating from python-jose](https://jose.authlib.org/en/migrations/python-jose), [FastAPI discussion: why python-jose](https://github.com/tiangolo/fastapi/discussions/9587)
- PASETO: [pyseto docs](https://github.com/dajiaji/pyseto/blob/v1.7.0/docs/index.rst), [Alpine package](https://pkgs.alpinelinux.org/package/v3.23/community/s390x/py3-pyseto), [python-paseto](https://github.com/purificant/python-paseto)
- Identity providers: [Cerbos: best Keycloak alternatives](https://cerbos.dev/blog/best-keycloak-alternatives), [Authentik vs ZITADEL vs Keycloak](https://cloudzy.com/blog/authentik-vs-zitadel-vs-keycloak/), [Open-source authentication in 2026](https://skycloak.io/blog/open-source-authentication-comparison-2026/), [ComputingForGeeks benchmark](https://computingforgeeks.com/?p=173202)
