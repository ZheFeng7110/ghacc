"""Basic CLI behaviour end-to-end tests."""

from __future__ import annotations

from helpers import run_ghacc


def test_version(ghacc_bin):
    result = run_ghacc(ghacc_bin, ["version"])
    assert result.returncode == 0
    assert result.stdout.startswith("ghacc ")


def test_help_lists_commands(ghacc_bin):
    result = run_ghacc(ghacc_bin, ["help"])
    assert result.returncode == 0
    for command in ("run", "hosts", "ca", "test"):
        assert command in result.stdout


def test_unknown_command_fails(ghacc_bin):
    result = run_ghacc(ghacc_bin, ["definitely-not-a-command"])
    assert result.returncode == 2
