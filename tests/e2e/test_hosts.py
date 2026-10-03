"""Hosts takeover end-to-end tests (temp file, no system changes)."""

from __future__ import annotations

from helpers import run_ghacc


def test_apply_show_revert_roundtrip(ghacc_bin, tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    backup = tmp_path / "hosts.backup"

    applied = run_ghacc(
        ghacc_bin,
        ["hosts", "apply", "--path", str(hosts), "--backup", str(backup),
         "--ip", "127.0.0.1", "--provider", "github"],
    )
    assert applied.returncode == 0, applied.stderr
    text = hosts.read_text()
    assert "ghacc begin" in text
    assert "127.0.0.1\tgithub.com" in text
    assert "localhost" in text
    assert backup.is_file(), "apply must create a backup of the original file"

    shown = run_ghacc(ghacc_bin, ["hosts", "show", "--path", str(hosts)])
    assert shown.returncode == 0, shown.stderr
    assert "github.com" in shown.stdout

    reverted = run_ghacc(
        ghacc_bin,
        ["hosts", "revert", "--path", str(hosts), "--backup", str(backup)],
    )
    assert reverted.returncode == 0, reverted.stderr
    text = hosts.read_text()
    assert "ghacc" not in text
    assert "localhost" in text


def test_show_without_block(ghacc_bin, tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")

    result = run_ghacc(ghacc_bin, ["hosts", "show", "--path", str(hosts)])
    assert result.returncode == 0, result.stderr
    assert "no ghacc block" in result.stdout


def test_apply_is_idempotent(ghacc_bin, tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    backup = tmp_path / "hosts.backup"
    args = ["hosts", "apply", "--path", str(hosts), "--backup", str(backup),
            "--ip", "127.0.0.1", "--provider", "github"]

    assert run_ghacc(ghacc_bin, args).returncode == 0
    assert run_ghacc(ghacc_bin, args).returncode == 0

    text = hosts.read_text()
    assert text.count("ghacc begin") == 1
    assert text.count("ghacc end") == 1
