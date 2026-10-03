# ghacc 端到端测试

[English](README_en.md) | 简体中文

这是一套黑盒测试：通过回环 socket 驱动真实的 `ghacc` 进程，覆盖正向代理（absolute-URI、
CONNECT、PAC、TLS 入侵、Block）、hosts 接管标记块、CA CLI，以及 M5 的 `status` / `provider` /
`config` / `completion` 等命令。

## 运行

```sh
cd tests/e2e
uv run pytest
```

`uv` 会创建本地 `.venv` 并安装 `pytest`。若机器离线，请事先安装 `pytest`，或把 `UV_INDEX_URL`
指向镜像。

测试套件默认会自行构建 workspace（`mcpp build`），并选用最新的
`target/*/*/bin/ghacc/ghacc`。若要直接使用已构建的二进制：

```sh
GHACC_BIN=/path/to/ghacc uv run pytest
```

## 目录说明

| 文件 | 覆盖范围 |
|---|---|
| `test_cli.py` | `version`、`help`、未知命令 |
| `test_commands.py` | `status --json`、`provider list/enable/disable`、`config path/get/set`、`completion` |
| `test_forward_proxy.py` | 正向代理：absolute-URI、CONNECT 隧道、PAC、Block、TLS MITM |
| `test_hosts.py` | 临时文件上的 `hosts apply/show/revert` |
| `test_ca.py` | `ca path/show/export` |
| `helpers.py` | 进程 / 端口 / socket 辅助函数与回环上游服务器 |
| `conftest.py` | `ghacc_bin` 与上游服务器 fixture |

## 说明

- 所有测试都不触碰 `/etc/hosts`、特权端口或真实系统代理，一切运行在临时端口与临时目录上。
- TLS 入侵测试用 `openssl` 生成自签名上游证书，并信任 `ghacc` 在临时 `--dir` 下写出的 CA。
- 除非设置了 `GHACC_BIN`，否则 `mcpp` 必须在 `PATH` 中。
- TUI 需要真实终端，未纳入自动化测试；仪表盘渲染由 `apps/ghacc/tests/tui_test.cpp` 做非交互单测。
