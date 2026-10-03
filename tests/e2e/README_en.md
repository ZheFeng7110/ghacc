# ghacc end-to-end tests

English | [简体中文](README.md)

Black-box tests that drive a real `ghacc` process over loopback sockets. They cover the forward
proxy (absolute-URI, CONNECT, PAC, TLS interception, Block), the hosts takeover block, the CA CLI,
and the M5 commands (`status`, `provider`, `config`, `completion`).

## Running

```sh
cd tests/e2e
uv run pytest
```

`uv` creates a local `.venv` and installs `pytest`. If the machine is offline, install `pytest`
beforehand or point `UV_INDEX_URL` at a mirror.

The suite builds the workspace itself (`mcpp build`) and picks the newest
`target/*/*/bin/ghacc/ghacc`. To use an existing binary instead:

```sh
GHACC_BIN=/path/to/ghacc uv run pytest
```

## Layout

| File | Coverage |
|---|---|
| `test_cli.py` | `version`, `help`, unknown command |
| `test_commands.py` | `status --json`, `provider list/enable/disable`, `config path/get/set`, `completion` |
| `test_forward_proxy.py` | forward proxy: absolute-URI, CONNECT tunnel, PAC, Block, TLS MITM |
| `test_hosts.py` | `hosts apply/show/revert` on a temporary file |
| `test_ca.py` | `ca path/show/export` |
| `helpers.py` | process/port/socket helpers and loopback upstream servers |
| `conftest.py` | `ghacc_bin` and upstream fixtures |

## Notes

- No test touches `/etc/hosts`, privileged ports or the real system proxy; everything runs on
  ephemeral ports and temporary directories.
- The TLS interception test generates a self-signed upstream certificate with `openssl` and trusts
  the CA written by `ghacc` under a temporary `--dir`.
- `mcpp` must be on `PATH` unless `GHACC_BIN` is set.
- The TUI needs a real terminal and is not part of the automated suite; the dashboard render is
  covered by a non-interactive unit test in `apps/ghacc/tests/tui_test.cpp`.
