"""The password command is split by the platform's rules (BUG-000051, id-AUTH-000006): a Windows path keeps its
backslashes. Both splitters are tested on every OS; the run itself on the OS the tests run on."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys

import pytest

from catalyst_users.provider import ProviderError, secret_from_command, split_command

WINDOWS = [
    (r"C:\Tools\pw.exe", [r"C:\Tools\pw.exe"]),
    (r"C:\Tools\pw.exe --account owner", [r"C:\Tools\pw.exe", "--account", "owner"]),
    (r'"C:\Program Files\pw\pw.exe" -a owner', [r"C:\Program Files\pw\pw.exe", "-a", "owner"]),
    (r"py C:\scripts\pw.py \\server\share\x", ["py", r"C:\scripts\pw.py", r"\\server\share\x"]),
    (r'pw "C:\dir with space\\"', ["pw", "C:\\dir with space\\"]),
    (r'pw a\"b a\\\"b "c""d"', ["pw", 'a"b', 'a\\"b', 'c"d']),
    ('pw "" x', ["pw", "", "x"]),
    ('pw\t a   "b c', ["pw", "a", "b c"]),
    ("", []),
]

POSIX = [
    (
        "security find-generic-password -s catalyst-users -w",
        ["security", "find-generic-password", "-s", "catalyst-users", "-w"],
    ),
    ("/usr/bin/pw 'a b' \"c d\"", ["/usr/bin/pw", "a b", "c d"]),
    (r"pw a\ b", ["pw", "a b"]),
]


@pytest.mark.parametrize(("line", "argv"), WINDOWS)
def test_windows_rules_keep_backslashes(line, argv):
    assert split_command(line, windows=True) == argv


@pytest.mark.parametrize(("line", "argv"), POSIX)
def test_posix_rules_are_shlex_unchanged(line, argv):
    assert split_command(line, windows=False) == argv == shlex.split(line)


@pytest.mark.parametrize(
    "argv",
    [
        [r"C:\Program Files\Python\python.exe", "-c", "print('owner-pw')"],
        [r"C:\x.exe", 'say "hi"', "trailing\\", "", r"a\\b", "tab\there"],
    ],
)
def test_windows_rules_undo_what_subprocess_quotes(argv):
    """`subprocess.list2cmdline` is how Python quotes a list for Windows; the splitter gives the list back."""
    assert split_command(subprocess.list2cmdline(argv), windows=True) == argv


def test_the_platform_chooses_the_rules(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    assert split_command(r"C:\Tools\pw.exe") == [r"C:\Tools\pw.exe"]
    monkeypatch.setattr(os, "name", "posix")
    assert split_command(r"C:\Tools\pw.exe") == ["C:Toolspw.exe"]


def test_the_command_runs_split_by_this_platform_s_rules():
    line = subprocess.list2cmdline if os.name == "nt" else shlex.join
    assert secret_from_command(line([sys.executable, "-c", "print('pw')"]), "the command") == "pw"
    assert secret_from_command([sys.executable, "-c", "print('listed')"], "the command") == "listed"


def test_an_unsplittable_command_is_refused_without_a_secret():
    if os.name == "nt":
        pytest.skip("Windows closes an unterminated quote at the end of the line")
    with pytest.raises(ProviderError, match="cannot be split") as caught:
        secret_from_command("pw 'secret", "the command")
    assert "secret'" not in str(caught.value)


@pytest.mark.skipif(os.name != "nt", reason="a Windows path, unquoted, is only a path on Windows")
def test_an_unquoted_windows_path_runs_on_windows():
    if " " in sys.executable:
        pytest.skip("this interpreter's path has a space, so it is quoted anyway")
    assert secret_from_command(f"{sys.executable} -c \"print('win')\"", "the command") == "win"
