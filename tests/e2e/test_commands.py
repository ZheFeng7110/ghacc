"""End-to-end coverage for the M5 CLI surface."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import time

import pytest

from helpers import free_port, run_ghacc


def _run(ghacc_bin, args, env, **kwargs):
    return subprocess.run(
        [str(ghacc_bin), *args], env=env, capture_output=True, text=True, **kwargs
    )


def test_status_json_is_machine_readable(ghacc_bin, tmp_path):
    result = run_ghacc(ghacc_bin, ["status", "--json", "--dir", str(tmp_path / "ca")])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["version"]
    assert payload["mode"] in {"hosts", "system", "pac", "forward"}
    assert "github" in payload["available_providers"]
    assert payload["running"] is False
    assert payload["ca_present"] is False
    assert "hosts" in payload and "config" in payload


def test_status_text(ghacc_bin, tmp_path):
    result = run_ghacc(ghacc_bin, ["status", "--dir", str(tmp_path / "ca")])
    assert result.returncode == 0, result.stderr
    assert "mode:" in result.stdout
    assert "providers:" in result.stdout
    assert "github" in result.stdout


def test_provider_list_and_toggle(ghacc_bin, tmp_path):
    config = tmp_path / "config.toml"

    listed = run_ghacc(ghacc_bin, ["provider", "list", "--config", str(config)])
    assert listed.returncode == 0, listed.stderr
    assert "github" in listed.stdout
    assert "steam" in listed.stdout

    disabled = run_ghacc(
        ghacc_bin, ["provider", "disable", "steam", "--config", str(config)]
    )
    assert disabled.returncode == 0, disabled.stderr

    again = run_ghacc(ghacc_bin, ["provider", "list", "--config", str(config)])
    steam_line = next(line for line in again.stdout.splitlines() if "steam" in line)
    assert "[ ]" in steam_line

    bad = run_ghacc(
        ghacc_bin, ["provider", "enable", "does-not-exist", "--config", str(config)]
    )
    assert bad.returncode != 0


def test_config_path_get_set(ghacc_bin, tmp_path):
    config = tmp_path / "config.toml"

    path = run_ghacc(ghacc_bin, ["config", "path", "--config", str(config)])
    assert path.returncode == 0, path.stderr
    assert str(config) in path.stdout

    set_result = run_ghacc(
        ghacc_bin,
        ["config", "set", "listen.proxy_port", "12345", "--config", str(config)],
    )
    assert set_result.returncode == 0, set_result.stderr

    get_result = run_ghacc(
        ghacc_bin, ["config", "get", "listen.proxy_port", "--config", str(config)]
    )
    assert get_result.returncode == 0, get_result.stderr
    assert get_result.stdout.strip() == "12345"

    unknown = run_ghacc(ghacc_bin, ["config", "get", "nope", "--config", str(config)])
    assert unknown.returncode != 0


def test_completion_scripts(ghacc_bin):
    for shell in ("bash", "zsh", "fish"):
        result = run_ghacc(ghacc_bin, ["completion", shell])
        assert result.returncode == 0, result.stderr
        assert "ghacc" in result.stdout
        assert "run" in result.stdout

    bad = run_ghacc(ghacc_bin, ["completion", "elvish"])
    assert bad.returncode != 0


def test_help_mentions_new_commands(ghacc_bin):
    result = run_ghacc(ghacc_bin, ["help"])
    assert result.returncode == 0
    for command in ("run", "stop", "status", "provider", "ca", "hosts", "proxy", "test", "config"):
        assert command in result.stdout


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="daemon mode is not supported on Windows; run ghacc as a service",
)
def test_daemon_start_and_stop(ghacc_bin, tmp_path):
    env = os.environ.copy()
    env["XDG_STATE_HOME"] = str(tmp_path / "state")
    env["XDG_CONFIG_HOME"] = str(tmp_path / "config")
    config = tmp_path / "config" / "config.toml"
    ca_dir = tmp_path / "ca"
    port = free_port()

    assert (
        _run(
            ghacc_bin,
            ["config", "set", "listen.proxy_port", str(port), "--config", str(config)],
            env,
        ).returncode
        == 0
    )

    try:
        started = _run(
            ghacc_bin,
            ["run", "--mode", "forward", "--config", str(config), "--dir", str(ca_dir),
             "-d", "--force"],
            env,
        )
        assert started.returncode == 0, started.stderr

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with contextlib.suppress(OSError):
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            time.sleep(0.1)
        else:
            raise AssertionError(f"daemon never listened on {port}")

        status = _run(
            ghacc_bin,
            ["status", "--json", "--config", str(config), "--dir", str(ca_dir)],
            env,
        )
        assert status.returncode == 0, status.stderr
        payload = json.loads(status.stdout)
        assert payload["running"] is True
        assert payload["pid"] > 0
    finally:
        with contextlib.suppress(Exception):
            _run(ghacc_bin, ["stop", "--config", str(config), "--dir", str(ca_dir)], env)
        time.sleep(0.3)

    stopped = _run(
        ghacc_bin,
        ["status", "--json", "--config", str(config), "--dir", str(ca_dir)],
        env,
    )
    assert json.loads(stopped.stdout)["running"] is False
