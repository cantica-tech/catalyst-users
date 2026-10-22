"""The logged-in person's tokens, owner-only on disk (id-AUTH-000002)."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
from pathlib import Path

from catalyst_users import config
from catalyst_users.oidc import Tokens

FILE_MODE = 0o600
DIR_MODE = 0o700


class CredentialStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or config.home() / "credentials.json"

    def save(self, issuer: str, client_id: str, tokens: Tokens) -> None:
        directory = self.path.parent
        directory.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        directory.chmod(DIR_MODE)
        data = json.dumps({"issuer": issuer, "client_id": client_id, "tokens": tokens.to_dict()}).encode()
        tmp = directory / f".{self.path.name}.{secrets.token_hex(4)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            tmp.replace(self.path)  # atomic: a reader sees the old file or the new one
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
            raise

    def load(self, issuer: str, client_id: str) -> Tokens | None:
        """The stored tokens for this issuer and client, or None."""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return None
        if data.get("issuer") != issuer or data.get("client_id") != client_id:
            return None
        try:
            return Tokens.from_dict(data["tokens"])
        except (KeyError, TypeError):
            return None

    def delete(self) -> bool:
        try:
            self.path.unlink()
        except FileNotFoundError:
            return False
        return True
