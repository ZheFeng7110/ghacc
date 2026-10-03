"""Certificate authority CLI end-to-end tests."""

from __future__ import annotations

from helpers import run_ghacc


def test_ca_path_and_export(ghacc_bin, tmp_path):
    ca_dir = tmp_path / "ca"

    path_result = run_ghacc(ghacc_bin, ["ca", "path", "--dir", str(ca_dir)])
    assert path_result.returncode == 0, path_result.stderr
    assert str(ca_dir / "ca.crt") in path_result.stdout

    exported = tmp_path / "exported.crt"
    export_result = run_ghacc(
        ghacc_bin,
        ["ca", "export", "--dir", str(ca_dir), "--path", str(exported)],
    )
    assert export_result.returncode == 0, export_result.stderr
    assert "BEGIN CERTIFICATE" in exported.read_text()


def test_ca_show_prints_pem(ghacc_bin, tmp_path):
    result = run_ghacc(ghacc_bin, ["ca", "show", "--dir", str(tmp_path / "ca")])
    assert result.returncode == 0, result.stderr
    assert "BEGIN CERTIFICATE" in result.stdout
