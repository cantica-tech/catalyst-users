#!/usr/bin/env bash
# Write the three secret files compose.yaml mounts, 0600, each a generated password on one line.
# An existing file is kept. The catalyst admin's password is printed once, to be put in their password
# manager; the other two never leave the host.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p secrets && chmod 700 secrets

gen() { python3 -c 'import secrets; print(secrets.token_urlsafe(24))'; }

for name in kc_db_password kc_admin_password catalyst_admin_password; do
  f="secrets/${name}"
  if [ -e "${f}" ]; then
    echo "kept    ${f}"
  else
    (umask 077 && gen > "${f}")
    echo "written ${f}"
  fi
done

printf '\nThe catalyst admin signs in with (keep it in a password manager, then forget this output):\n  '
cat secrets/catalyst_admin_password
