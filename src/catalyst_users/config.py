"""Settings: which provider catalyst-users is a facade to, and its settings (id-PROVIDER-000005, id-PROVIDER-000006).

The provider is chosen by a pointer document (`pointer`): `--pointer FILE` or `CATALYST_USERS_POINTER`, else
`IAM/settings.json` (written by `catalyst-users setup`), else `config.toml`'s `provider = "<name>"` with its
`[<name>]` table, else explicit Keycloak settings (flags or environment), which win over settings.json and config.toml:
when they name settings.json's own provider, its system account is kept (`system_pointer`). With none of them,
`NoSettingsError`: a terminal is asked to run setup. The Keycloak settings
(`Settings`) keep their own precedence, lowest first: defaults, `config.toml`'s top-level keys, `CATALYST_USERS_*`
environment variables, explicit overrides; given explicitly, they win over the `[keycloak]` table.
"""

from __future__ import annotations

import json
import os
import tomllib
import urllib.parse
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from catalyst_users.errors import CatalystUsersError
from catalyst_users.http import LOOPBACK

ENV_PREFIX = "CATALYST_USERS_"


def canonical_issuer(issuer: str) -> str:
    """An issuer as one provider is named, whatever its spelling: no trailing `/`, the scheme and host in lower case,
    and a loopback host (`localhost`, `127.0.0.1`, `::1`) spelled `localhost`, since all three reach this machine.
    For matching only: Keycloak mints a token's `iss` from the host it was called by, so calls keep their own URL."""
    parts = urllib.parse.urlsplit(str(issuer).strip().rstrip("/"))
    host = (parts.hostname or "").lower()
    if host in LOOPBACK:
        host = "localhost"
    elif ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:  # not a URL with a port: compared as written
        return str(issuer).strip().rstrip("/")
    netloc = host + (f":{port}" if port else "")
    return urllib.parse.urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))


def same_issuer(a: str | None, b: str | None) -> bool:
    """Whether two issuers name the same provider (`canonical_issuer`): `http://127.0.0.1:8080/realms/catalyst` and
    `http://localhost:8080/realms/catalyst/` do."""
    return bool(a) and bool(b) and canonical_issuer(str(a)) == canonical_issuer(str(b))


def home() -> Path:
    """Where the settings, `config.toml` and credentials live (id-PROVIDER-000009): `CATALYST_USERS_HOME`, else
    `users/` in catalyst's home (`$CATALYST_HOME/users`, else `~/.catalyst/users`). The default home adopts a
    `~/.catalyst-users` made before it, once; a home a variable names is never moved into."""
    explicit = os.environ.get(f"{ENV_PREFIX}HOME")
    if explicit:
        return Path(explicit)
    catalyst_home = os.environ.get("CATALYST_HOME")
    target = Path(catalyst_home or Path.home() / ".catalyst") / "users"
    if not catalyst_home:
        _adopt_legacy(target)
    return target


def _adopt_legacy(target: Path) -> None:
    import sys

    legacy = Path.home() / ".catalyst-users"
    if legacy.is_symlink() or not legacy.is_dir():  # adopted already (the link left behind), or none
        return
    if target.exists():
        print(f"catalyst-users: {legacy} is ignored: the settings are in {target}", file=sys.stderr)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    legacy.rename(target)
    legacy.symlink_to(target, target_is_directory=True)  # an earlier catalyst-users, vendored, still finds it
    print(f"catalyst-users: moved {legacy} to {target}, leaving a link (its home is in catalyst's)", file=sys.stderr)


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


class NoSettingsError(CatalystUsersError):
    """No provider is configured: `catalyst-users setup` writes IAM/settings.json."""

    def __init__(self) -> None:
        super().__init__(f"no IAM settings ({settings_file()}): run `catalyst-users setup`")


def settings_file() -> Path:
    return home() / "IAM" / "settings.json"


def read_settings() -> dict[str, Any] | None:
    path = settings_file()
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CatalystUsersError(f"cannot read {path}: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("type"), str):
        raise CatalystUsersError(f"{path} names no provider `type`")
    return doc


def write_settings(doc: dict[str, Any]) -> Path:
    """settings.json, owner-only: the directory `0700`, the file `0600`, written atomically."""
    path = settings_file()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    tmp.replace(path)
    return path


def settings_pointer(doc: dict[str, Any]) -> dict[str, Any]:
    """The pointer settings.json stands for: the provider's connection settings, its admin and password command."""
    pointer = {"provider": doc["type"], **(doc.get("provider") or {})}
    for key in ("username", "password_command"):
        if doc.get(key):
            pointer[key] = doc[key]
    return pointer


def system_pointer(issuer: str, client: str | None = None) -> dict[str, Any] | None:
    """settings.json's pointer, with its system account, for the provider at `issuer`; None when settings.json names
    another provider (or none, or no system account). The provider is reached as `issuer` spells it, so its tokens
    and their `iss` are that spelling's; `client`, given, replaces the login client (id-AUTH-000006)."""
    stored = read_settings()
    if stored is None or not stored.get("username") or not stored.get("password_command"):
        return None
    doc = settings_pointer(stored)
    from catalyst_users.provider import from_pointer  # the provider knows how its settings name its issuer

    try:
        stored_issuer = from_pointer(doc).issuer
    except CatalystUsersError:
        return None
    if not same_issuer(stored_issuer, issuer):
        return None
    if str(stored_issuer).rstrip("/") != str(issuer).rstrip("/"):
        doc["issuer"] = str(issuer).rstrip("/")
    if client:
        doc["client"] = client
    return doc


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
    explicit = any(v is not None for k, v in (overrides or {}).items() if k in ("server_url", "realm", "client_id"))
    explicit = explicit or any(os.environ.get(ENV_PREFIX + s) for s in ("SERVER", "REALM", "CLIENT_ID"))
    if explicit:  # settings.json's own provider, named explicitly, keeps its system account
        given = load(overrides, config_file)
        client = (overrides or {}).get("client_id") or os.environ.get(f"{ENV_PREFIX}CLIENT_ID")
        kept = system_pointer(given.issuer, client)
        if kept is not None:
            return kept
    stored = None if explicit else read_settings()
    if stored is not None:
        return settings_pointer(stored)
    path = config_file or home() / "config.toml"
    if not path.is_file() and not explicit:
        raise NoSettingsError
    raw = _toml(path)
    name = str(raw.get("provider") or "keycloak")
    section = raw.get(name)
    table: dict[str, Any] = section if isinstance(section, dict) else {}
    doc: dict[str, Any] = {"provider": name, **table}
    if name != "keycloak":
        return doc
    settings = load(overrides, config_file)
    legacy = {"issuer": settings.issuer, "client": settings.client_id}
    for key, value in legacy.items():
        if explicit or key not in doc:
            doc[key] = value
    doc.setdefault("catalyst_client", settings.catalyst_client)
    doc.setdefault("timeout", settings.timeout)
    return doc
