"""pytest fixtures for the ghacc end-to-end suite."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from helpers import http_upstream, https_upstream

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def ghacc_bin() -> Path:
    """Path to the built ghacc executable.

    Uses ``$GHACC_BIN`` when set; otherwise builds the workspace with mcpp and
    picks the most recently built ``target/*/*/bin/ghacc/ghacc``.
    """
    override = os.environ.get("GHACC_BIN")
    if override:
        path = Path(override)
        assert path.is_file(), f"GHACC_BIN points at a missing file: {path}"
        return path

    try:
        subprocess.run(
            ["mcpp", "build"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError as error:  # pragma: no cover - environment issue
        raise RuntimeError("mcpp is not on PATH; set GHACC_BIN instead") from error
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"mcpp build failed:\n{error.stdout}\n{error.stderr}") from error

    candidates = sorted(
        REPO_ROOT.glob("target/*/*/bin/ghacc/ghacc"),
        key=lambda path: path.stat().st_mtime,
    )
    assert candidates, "ghacc binary not found under target/; run `mcpp build` first"
    return candidates[-1]


@pytest.fixture
def upstream_http():
    with http_upstream() as upstream:
        yield upstream


@pytest.fixture
def upstream_https(tmp_path: Path):
    with https_upstream(tmp_path) as upstream:
        yield upstream
