"""Settings: which provider catalyst-users is a facade to, and its settings (id-PROVIDER-000005).

The provider is chosen by a pointer document (`pointer`): `--pointer FILE` or `CATALYST_USERS_POINTER`, else
`config.toml`'s `provider = "<name>"` with its `[<name>]` table, else the local dev Keycloak. The Keycloak settings
(`Settings`) keep their own precedence, lowest first: defaults, `config.toml`'s top-level keys, `CATALYST_USERS_*`
environment variables, explicit overrides; given explicitly, they win over the `[keycloak]` table.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from catalyst_users.errors import CatalystUsersError

ENV_PREFIX = "CATALYST_USERS_"


def home() -> Path:
    """Where credentials and `config.toml` live (`CATALYST_USERS_HOME`, else `~/.catalyst-users`)."""
    return Path(os.environ.get(f"{ENV_PREFIX}HOME") or Path.home() / ".catalyst-users")


@dataclass(frozen=True)
class Settings:
    server_url: str = "http://localhost:8080"
    realm: str = "catalyst"
    client_id: str = "catalyst-cli"
    api_client_id: str = "catalyst-api"
    api_client_secret: str | None = field(default=None, repr=False)
    timeout: float = 10.0
    catalyst_client: str = "catalyst"  # the client whose roles are catalyst grants (id-PROVIDER-000002)

    @property
    def issuer(self) -> str:
        return f"{self.server_url.rstrip('/')}/realms/{self.realm}"

    @property
    def admin_url(self) -> str:
        return f"{self.server_url.rstrip('/')}/admin/realms/{self.realm}"


_ENV = {
    "server_url": "SERVER",
    "realm": "REALM",
    "client_id": "CLIENT_ID",
    "api_client_id": "API_CLIENT_ID",
    "api_client_secret": "API_CLIENT_SECRET",
    "timeout": "TIMEOUT",
    "catalyst_client": "CATALYST_CLIENT",
}


def load(overrides: dict[str, Any] | None = None, config_file: Path | None = None) -> Settings:
    names = {f.name for f in fields(Settings)}
    values: dict[str, Any] = {}
    path = config_file or home() / "config.toml"
    if path.is_file():
        with path.open("rb") as fh:
            values.update({k: v for k, v in tomllib.load(fh).items() if k in names})
    for name, suffix in _ENV.items():
        if (value := os.environ.get(ENV_PREFIX + suffix)) is not None:
            values[name] = value
    values.update({k: v for k, v in (overrides or {}).items() if v is not None and k in names})
    if "timeout" in values:
        values["timeout"] = float(values["timeout"])
    return replace(Settings(), **values)


def _toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)


def pointer(
    overrides: dict[str, Any] | None = None, config_file: Path | None = None, pointer_file: str | None = None
) -> dict[str, Any]:
    """The pointer document naming the provider and its settings."""
    chosen = pointer_file or os.environ.get(f"{ENV_PREFIX}POINTER")
    if chosen:
        try:
            doc = json.loads(Path(chosen).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CatalystUsersError(f"cannot read the pointer {chosen}: {exc}") from None
        if not isinstance(doc, dict):
            raise CatalystUsersError(f"the pointer {chosen} is not a JSON object")
        return doc
    raw = _toml(config_file or home() / "config.toml")
    name = str(raw.get("provider") or "keycloak")
    table = raw.get(name) if isinstance(raw.get(name), dict) else {}
    doc: dict[str, Any] = {"provider": name, **table}
    if name != "keycloak":
        return doc
    settings = load(overrides, config_file)
    explicit = any(v is not None for k, v in (overrides or {}).items() if k in ("server_url", "realm", "client_id"))
    explicit = explicit or any(os.environ.get(ENV_PREFIX + s) for s in ("SERVER", "REALM", "CLIENT_ID"))
    legacy = {"issuer": settings.issuer, "client": settings.client_id}
    for key, value in legacy.items():
        if explicit or key not in doc:
            doc[key] = value
    doc.setdefault("catalyst_client", settings.catalyst_client)
    doc.setdefault("timeout", settings.timeout)
    return doc
