# ghacc

[English](README_en.md) | 简体中文

ghacc（GitHub / Steam Accelerator）是一个用 **C++23 模块**编写的网络加速工具。它把 SteamTools
（Watt Toolkit / Steam++）的「网络加速」能力提取重写为可在 **Linux / macOS / Windows** 上运行的
CLI + TUI 程序：

- 通过 **Hosts + 本地 MITM 反向代理**，或 **系统代理 / PAC 正向代理** 接管目标站点流量；
- 用 **DoH 解析 + TCP 测速择优** 选择更快的上游 IP；
- 内置 **GitHub** 与 **Steam** 两套加速规则，并支持通过配置文件扩展；
- 动态签发本地 CA 证书完成 TLS 解密转发（MITM），可一键安装/卸载信任。

> 本仓库是 SteamTools 网络加速部分的独立重写，不包含 Steam 客户端 JS 脚本注入、商业加速 SDK
> 与 Windows WinDivert 模式，但保留了脚本注入的扩展接口。

## 功能概览

| 能力 | 说明 |
|---|---|
| 代理模式 | `hosts`（Hosts + MITM 反向代理）、`system`（系统代理）、`pac`（PAC 文件）、`forward`（纯正向代理） |
| 加速目标 | 内置 `github`、`steam`；配置 `[[provider.custom]]` 可数据驱动扩展 |
| DNS | 自研 DoH（A/AAAA/CNAME）+ TTL 缓存 + 连接测速排序，失败回退系统解析 |
| TLS | 本地 CA 自签 + 按域名签发叶子证书；SNI 选证，ALPN 固定 `http/1.1` |
| 接管 | hosts 标记块（可回滚、有备份）、GNOME/KDE/macOS/Windows 系统代理 |
| 观测 | 5 秒窗口流量速率、请求日志、日志轮转、配置热重载 |
| 界面 | FTXUI 仪表盘 + 完整命令行 |

## 平台支持

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| hosts 路径 | `/etc/hosts` | `/etc/hosts` | `%SystemRoot%\System32\drivers\etc\hosts` |
| 绑定 80/443 | root 或 `setcap cap_net_bind_service=+eip <bin>` | root | 管理员 |
| CA 信任 | Debian: `update-ca-certificates`；RHEL: `update-ca-trust` | `security add-trusted-cert` | `certutil -addstore` |
| 系统代理 | GNOME `gsettings` / KDE `kwriteconfig` | `networksetup` | `reg` (WinINET) |
| 守护进程 | `fork`+`setsid` | `fork`+`setsid` | 暂不支持，请用服务 |

> 本机仅对 Linux 做了自动化验证；macOS/Windows 的平台代码按分支编写并给出明确的权限提示，
> 但未在对应系统上跑通端到端测试。

## 构建

依赖 [mcpp](https://github.com/mcpp-community/mcpp) 与已缓存的第三方包（asio / OpenSSL / FTXUI /
tomlplusplus / cmdline / boost.ut）。

```sh
mcpp build            # 构建 workspace（libs/accel + apps/ghacc）
mcpp test             # 运行单元测试（在 libs/accel 与 apps/ghacc 下）
mcpp run ghacc -- --help
```

首次构建会下载并静态构建 `compat.openssl`，耗时较长；构建成功后进入 mcpp 全局缓存。

## 快速开始

```sh
# 1. 启动仪表盘（无参数即进入 TUI）
ghacc

# 2. Hosts + MITM 模式：改写 hosts 并把 80/443 指向本地反向代理
sudo ghacc hosts apply --provider github,steam
sudo ghacc run --mode hosts
# ... 结束后还原
sudo ghacc hosts revert

# 3. 系统代理模式：把系统 HTTP/HTTPS 代理指向本地正向代理
ghacc run --mode system
# 另开终端设置（或让 ghacc 代劳）
ghacc proxy set

# 4. PAC 模式
ghacc run --mode pac
ghacc proxy set --pac

# 5. 纯正向代理：手动给客户端配置 http://127.0.0.1:26501
ghacc run --mode forward
curl -x http://127.0.0.1:26501 http://github.com

# 停止后台实例
ghacc stop
```

## 命令行参考

```
ghacc [tui]                               无参数或 tui 打开仪表盘
ghacc run   [--mode hosts|system|pac|forward]
            [--provider a,b] [--address IP]
            [--http-port N] [--https-port N] [--proxy-port N]
            [-d|--daemon] [--force]
ghacc stop
ghacc status [--json]
ghacc provider list
ghacc provider enable|disable <id>
ghacc ca path|show|export|install|uninstall [--path FILE]
ghacc hosts show|apply|revert [--ip IP] [--provider a,b]
            [--path FILE] [--backup FILE]
ghacc proxy set|clear [--pac] [--host HOST] [--port N]
ghacc test <domain> [--dns URL]...
ghacc config path|get|set|edit [key] [value]
ghacc completion bash|zsh|fish
ghacc version | help
```

通用选项 `--config FILE`（配置文件）与 `--dir DIR`（CA 目录）可放在子命令前后。

`status --json` 会输出稳定字段，便于脚本消费：

```json
{
  "version": "0.1.0",
  "running": false,
  "mode": "hosts",
  "address": "127.0.0.1",
  "proxy_port": 26501,
  "http_port": 80,
  "https_port": 443,
  "providers": ["github", "steam"],
  "available_providers": ["github", "steam"],
  "ca_present": true,
  "ca_trusted": false,
  "hosts": {"path": "/etc/hosts", "block_present": false, "writable": false, "entries": 0}
}
```

## TUI 仪表盘

无参数运行 `ghacc` 或 `ghacc tui` 进入全屏仪表盘：顶部状态栏、左侧 provider 开关、中部实时流量、
右侧请求日志、底部快捷键。

| 按键 | 作用 |
|---|---|
| `s` | 启动 / 停止引擎 |
| `p` | 暂停 / 恢复刷新 |
| `r` | 清空请求日志 |
| `m` | 循环切换模式并写入配置（监听需重启生效） |
| `c` | 安装并信任本地 CA |
| `h` | 应用 hosts 标记块 |
| `q` | 退出 |

## 配置文件

默认路径（可用 `--config` 覆盖）：

- Linux：`$XDG_CONFIG_HOME/ghacc/config.toml`（缺省 `~/.config/ghacc/config.toml`）
- macOS：`~/Library/Application Support/ghacc/config.toml`
- Windows：`%APPDATA%\ghacc\config.toml`

```toml
[general]
mode = "hosts"          # hosts | system | pac | forward
log_level = "info"      # debug | info | warn | error

[listen]
address = "127.0.0.1"
proxy_port = 26501
http_port = 80
https_port = 443
pac_path = "/pac"

[dns]
doh = ["https://doh.pub/dns-query", "https://1.1.1.1/dns-query"]
prefer_ipv6 = false
cache_ttl = 600

[providers]
enabled = ["github", "steam"]

# 数据驱动扩展：无需重新编译
[[provider.custom]]
id = "example"
name = "Example"
[[provider.custom.rules]]
pattern = "*.example.com"
```

`ghacc config get|set` 支持这些键：`mode`、`log_level`、`listen.address`、`listen.proxy_port`、
`listen.http_port`、`listen.https_port`、`listen.pac_path`、`dns.prefer_ipv6`、`dns.cache_ttl`、
`dns.doh`、`providers.enabled`。

运行中会监听配置文件 mtime，自动热重载 **provider 规则** 与 **日志级别**；监听地址/端口/模式
变化需要重启。

## 数据与日志路径

| 用途 | Linux | macOS | Windows |
|---|---|---|---|
| CA 证书/私钥 | `~/.config/ghacc/ca/` | `~/Library/Application Support/ghacc/ca/` | `%APPDATA%\ghacc\ca\` |
| 叶子证书缓存 | `~/.local/share/ghacc/certs/` | `~/Library/Application Support/ghacc/certs/` | `%LOCALAPPDATA%\ghacc\certs\` |
| PID / hosts 备份 | `~/.local/state/ghacc/` | `~/Library/Application Support/ghacc/` | `%LOCALAPPDATA%\ghacc\` |
| 日志（轮转） | `~/.local/state/ghacc/ghacc.log` | `~/Library/Logs/ghacc/ghacc.log` | `%LOCALAPPDATA%\ghacc\logs\ghacc.log` |

日志按大小轮转（默认 4 MiB，保留 3 份 `.1`/`.2`/`.3`）。

## CA 信任

```sh
ghacc ca path          # 打印 ca.crt 路径
ghacc ca show          # 打印 PEM
ghacc ca export --path ./ghacc-ca.crt
sudo ghacc ca install  # 安装到系统信任库
sudo ghacc ca uninstall
```

无权限时会返回带 `sudo` / 管理员提示的错误。

## 测试

```sh
# 单元测试（boost.ut）
cd libs/accel && mcpp test
cd apps/ghacc && mcpp test

# 端到端（Python + pytest，黑盒驱动真实进程）
cd tests/e2e && uv run pytest
```

端到端套件不触碰 80/443、真实 `/etc/hosts` 或系统代理；详见
[`tests/e2e/README.md`](tests/e2e/README.md)。

## 持续集成

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) 在 GitHub Actions 上运行：

- **三平台构建验证**（`ubuntu-24.04` / `macos-14` / `windows-latest`）：安装 mcpp、构建
  workspace、运行 `libs/accel` 与 `apps/ghacc` 的单元测试，并做 CLI 冒烟测试。
- **端到端测试**（Linux）：构建后运行 `tests/e2e` 的 pytest 套件。
- **打包**（Linux）：`mcpp pack --mode self-contained`，产物作为 CI artifact 上传。

第三方依赖（OpenSSL / FTXUI 等）编译结果按 `mcpp.lock` 哈希缓存到 `~/.mcpp`。

## 打包

```sh
mcpp pack                      # 默认 vendored 产物
mcpp pack --mode self-contained  # 携带运行库，便于分发
```

产物位于 `apps/ghacc/target/dist/`。

## 扩展 provider

内置 provider 之外的加速目标可通过配置文件数据驱动添加，或以 C++ 模块实现并注册。接口说明见
[`docs/provider-api.md`](docs/provider-api.md)。

## 已知限制

- 只做 HTTP/1.1：本地 ALPN 仅通告 `http/1.1`，上游也走 1.1。
- hosts 文件不支持通配域名：`*.github.com` 只能落到基名 `github.com`，子域由 MITM / 正向代理覆盖。
- 暂不做 Steam JS 脚本注入（保留 `IScriptInjector` 接口）。
- 不做 Windows WinDivert DNS 拦截与商业加速 SDK。
- macOS/Windows 的接管流程未在对应平台做自动化验证。

## 许可

MIT
