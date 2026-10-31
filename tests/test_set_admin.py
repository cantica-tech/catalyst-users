"""keycloak/set_admin.py makes the owner an admin, and removes the others only when asked (REQ-000016,
env-LOCAL-000002)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

KEYCLOAK = Path(__file__).resolve().parent.parent / "keycloak"
sys.path.insert(0, str(KEYCLOAK))  # the scripts import each other as siblings

import set_admin  # noqa: E402


class FakeAdmin:
    def __init__(self, settings, token) -> None:
        self.members_of = {set_admin.ADMINS: ["someone-else", "machine"]}
        self.removed: list[str] = []
        FakeAdmin.last = self

    def user(self, username):
        return SimpleNamespace(id="u-1", username=username)

    def _call(self, method, path, body=None):
        return None

    def add_member(self, path, username):
        self.members_of[path].append(username.lower())

    def members(self, path):
        return list(self.members_of[path])

    def remove_member(self, path, username):
        self.removed.append(username)


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setattr(set_admin, "keychain", lambda service: ("owner", "pw"))
    monkeypatch.setattr(set_admin, "bootstrap_token", lambda server, user, password: "boot")
    monkeypatch.setattr(set_admin, "KeycloakAdmin", FakeAdmin)


def test_the_other_admins_are_kept_and_listed_by_default(wired, capsys):
    assert set_admin.main(["--email", "o@example.com", "--first-name", "O", "--last-name", "W"]) == 0
    assert FakeAdmin.last.removed == []
    out = capsys.readouterr().out
    assert "kept; --sole-admin removes them" in out and "someone-else, machine" in out


def test_sole_admin_removes_every_other_member(wired, capsys):
    assert set_admin.main(["--email", "o@example.com", "--first-name", "O", "--last-name", "W", "--sole-admin"]) == 0
    assert FakeAdmin.last.removed == ["someone-else", "machine"]
    assert "now holds only them" in capsys.readouterr().out
