"""Settings: where the identity provider is and which clients to use.

Precedence, lowest first: defaults (the local dev Keycloak), `config.toml` in the
home directory, `CATALYST_USERS_*` environment variables, explicit overrides.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

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
