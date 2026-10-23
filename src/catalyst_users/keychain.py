"""The OS keychain, for a password typed at setup (id-PROVIDER-000006): stored there, never in a file, and read back
by a command that settings.json records. macOS `security`; elsewhere, libsecret's `secret-tool`."""

from __future__ import annotations

import platform
import shlex
import shutil
import subprocess

from catalyst_users.errors import CatalystUsersError

SERVICE = "catalyst-users"


def _quote(value: str) -> str:
    """Quoted for `security -i`'s own parser."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def store_command(account: str, secret: str) -> tuple[list[str], str]:
    """The program that stores `secret`, and what it reads on standard input: the secret never goes in argv."""
    if platform.system() == "Darwin":
        line = f"add-generic-password -U -s {_quote(SERVICE)} -a {_quote(account)} -w {_quote(secret)}\n"
        return ["security", "-i"], line
    if shutil.which("secret-tool"):
        return [
            "secret-tool",
            "store",
            "--label",
            f"{SERVICE} {account}",
            "service",
            SERVICE,
            "account",
            account,
        ], secret
    raise CatalystUsersError("no OS keychain here (macOS security or secret-tool): give a password command instead")


def read_command(account: str) -> str:
    """The command printing the stored secret, for settings.json."""
    if platform.system() == "Darwin":
        return shlex.join(["security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"])
    return shlex.join(["secret-tool", "lookup", "service", SERVICE, "account", account])


def store(account: str, secret: str) -> str:
    """Keep `secret` in the keychain under `account`; the command that reads it back."""
    argv, stdin = store_command(account, secret)
    done = subprocess.run(argv, input=stdin, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise CatalystUsersError(f"the keychain refused the password for {account}")
    return read_command(account)
