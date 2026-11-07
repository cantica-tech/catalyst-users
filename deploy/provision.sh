#!/usr/bin/env bash
# Provision a running Keycloak for catalyst, non-interactively: the steps of catalyst's beta/QUICKSTART.md §1
# that a person types, done by a container. Idempotent: a re-run signs in and adds what is missing.
#
# Inputs (environment): KC_URL (inside the network), KC_PUBLIC_URL (the issuer users see),
# KC_BOOTSTRAP_ADMIN_USERNAME, CATALYST_ADMIN, CATALYST_ADMIN_EMAIL, CATALYST_ADMIN_FIRST_NAME,
# CATALYST_ADMIN_LAST_NAME, CATALYST_CRITERIA (space-separated, may be empty).
# Secrets (files): /run/secrets/kc_admin_password, /run/secrets/catalyst_admin_password.
# Nothing read from a secret is printed; the password commands handed to catalyst-users read the files.
set -euo pipefail

: "${KC_URL:?}" "${KC_PUBLIC_URL:?}" "${CATALYST_ADMIN:?}" "${CATALYST_ADMIN_EMAIL:?}"
: "${CATALYST_ADMIN_FIRST_NAME:?}" "${CATALYST_ADMIN_LAST_NAME:?}"
KC_BOOTSTRAP_ADMIN_USERNAME="${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}"
REALM="${KC_REALM:-catalyst}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYCLOAK_DIR="${KEYCLOAK_DIR:-/opt/catalyst-users/keycloak}"
[ -d "$KEYCLOAK_DIR" ] || KEYCLOAK_DIR="$HERE/../keycloak"
KC_ADMIN_SECRET=/run/secrets/kc_admin_password
ADMIN_SECRET=/run/secrets/catalyst_admin_password
[ -r "$KC_ADMIN_SECRET" ] || { echo "provision: missing $KC_ADMIN_SECRET" >&2; exit 1; }
[ -r "$ADMIN_SECRET" ] || { echo "provision: missing $ADMIN_SECRET" >&2; exit 1; }

step() { printf '\n== %s\n' "$*"; }

step "waiting for Keycloak at $KC_URL"
for _ in $(seq 1 60); do
  if curl -sf "$KC_URL/realms/master" >/dev/null 2>&1 \
     || python3 -c "import urllib.request,sys; urllib.request.urlopen('$KC_URL/realms/master', timeout=3)" 2>/dev/null; then
    break
  fi
  sleep 3
done

criteria=()
for c in ${CATALYST_CRITERIA:-}; do criteria+=(--criterion "$c"); done

step "catalyst-users setup: the realm '$REALM' from its definition, the admin '$CATALYST_ADMIN', the criteria"
# The realm absent: created from the definition (no person, no secret in it), then the admin and the criteria.
# The realm present: signs the admin in, and nothing else. --force rewrites settings.json on a re-run.
catalyst-users setup --force --type keycloak \
  --provider "{\"url\": \"$KC_URL\", \"realm\": \"$REALM\", \"definition\": \"$KEYCLOAK_DIR/realm-catalyst.json\"}" \
  --username "$CATALYST_ADMIN" --password-command "cat $ADMIN_SECRET" \
  --server-admin "$KC_BOOTSTRAP_ADMIN_USERNAME" --server-admin-password-command "cat $KC_ADMIN_SECRET" \
  --email "$CATALYST_ADMIN_EMAIL" --first-name "$CATALYST_ADMIN_FIRST_NAME" --last-name "$CATALYST_ADMIN_LAST_NAME" \
  "${criteria[@]}"

step "criteria present on a re-run"
# setup adds criteria only when it creates the realm; `criteria add` is the catalyst-admin's and idempotent.
for c in ${CATALYST_CRITERIA:-}; do
  catalyst-users criteria add "$c" --admin "$CATALYST_ADMIN" || true
done

step "signing in as $CATALYST_ADMIN (password grant: no browser here)"
catalyst-users login --password --username "$CATALYST_ADMIN" < "$ADMIN_SECRET"

step "catalyst's roles and grants"
catalyst-users roles provision "$KEYCLOAK_DIR/catalyst-roles.json" \
  --login-client catalyst-cli --login-client catalyst-admin-cli

step "clients the definition declares and the realm lacks"
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat "$KC_ADMIN_SECRET")" \
  python3 "$KEYCLOAK_DIR/sync_clients.py" --server "$KC_URL"

step "what catalyst will see"
catalyst-users whoami --system

cat <<EOF

Done. Users point catalyst-users at this provider with:

  catalyst-users setup --type keycloak --provider '{"url": "$KC_PUBLIC_URL", "realm": "$REALM"}' \\
      --username <their username> --password-command <a command printing their password>

and a deployment at the issuer $KC_PUBLIC_URL/realms/$REALM (\`catalyst identity configure\`).
EOF
