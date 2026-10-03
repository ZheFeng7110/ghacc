# 2026-10-03 M5 + M6：完整 CLI、FTXUI 仪表盘与打磨

## 目标

在 M0–M4（规则/config/log/flow、DoH、CA+MITM、接管层+正向代理）基础上完成 **M5** 与 **M6**：

- **M5**：用 `mcpplibs.cmdline` 重写命令行解析，补齐计划 §6 的全部子命令；FTXUI 仪表盘；
  CA 安装/卸载、hosts/系统代理交互与权限提示；`status --json`。
- **M6**：Steam 规则补全、日志轮转、配置热重载、错误处理、`mcpp pack`、中英双语 README 与
  `docs/provider-api.md`（默认中文，英文 `_en.md`）。

## 依赖

- 命令行解析：`mcpplibs.cmdline`（workspace 已声明），`import mcpplibs::cmdline;`。
  解析交给库，子命令分发与执行仍由 `apps/ghacc/src/cli.cpp` 负责。
- TUI：`compat.ftxui`（`features = ["modules"]`），`import ftxui;`。

## 库新增/变更

| 模块 | 变更 |
|---|---|
| `config` | 新增 XDG/平台目录：`default_data_dir/state_dir/log_dir/ca_dir/pid_path/log_path` |
| `log` | 新增文件输出 + 按大小轮转；保留内存环形缓冲供 TUI |
| `takeover.ca_trust` | 新增：按平台规划并执行 CA 信任/取消信任（Debian/RHEL/macOS/Windows） |
| `engine` | `Pipeline.rules` 改为 `shared_ptr<const RuleSet>` 快照；新增 `ProxyEngine::update_rules()` 支持配置热重载 |
| `provider.github` / `provider.steam` | 扩充域名覆盖 |

## 应用结构（`apps/ghacc`）

```
src/
├── main.cpp         # 无参数 → TUI；有参数 → cmdline
├── app.cppm/.cpp    # Runtime：路径、配置装载、规则构建、PID 文件、状态、CA 目录
├── cli.cppm/.cpp    # mcpplibs.cmdline App + 全部子命令实现
└── tui.cppm/.cpp    # FTXUI 仪表盘（可渲染函数 + 交互循环）
```

- `main`：`argc == 1` → `run_tui()`；否则 `cli::run(argc, argv)`。
- 库根不导出 app 内部；app 通过 `import ghacc.accel;` 使用引擎。

### 子命令

```
ghacc [tui]                      无参数或 tui → 仪盘表
ghacc run   [--mode ...] [--provider a,b] [--address IP] [--http/--https/--proxy-port] [-d/--daemon]
ghacc stop                       读 PID 文件，发送 SIGTERM / TerminateProcess
ghacc status [--json]            模式、监听、provider、CA 信任、hosts 块、运行状态
ghacc provider list
ghacc provider enable|disable <id>
ghacc ca path|show|export [--path]
ghacc ca install|uninstall       信任/取消信任本地 CA
ghacc hosts show|apply|revert [--ip] [--provider] [--path] [--backup]
ghacc proxy set|clear [--pac]
ghacc test <domain> [--dns URL]...
ghacc config path|get|set|edit
ghacc completion <shell>
```

全局选项 `--config FILE`、`--dir DIR`（CA 目录）在根 App 上声明为 `global`，子命令前后均可。

## 配置热重载

`run` 在前台运行时于 io_context 上挂一个 2s 周期 `steady_timer`，检查 `config.toml` 的
mtime；变化时只热更新 **provider 列表（规则快照）** 与 **日志级别**。监听地址/端口/模式
变化需要重启，日志中给出提示。`ProxyEngine::update_rules` 通过 `asio::post` 在 io 线程
替换 `shared_ptr`，在途连接持有旧快照，新连接使用新规则。

## CA 信任（平台）

| 平台 | 安装 | 卸载 |
|---|---|---|
| Linux Debian | 复制 PEM 到 `/usr/local/share/ca-certificates/ghacc.crt` + `update-ca-certificates` | 删除 + `update-ca-certificates --fresh` |
| Linux RHEL | 复制到 `/etc/pki/ca-trust/source/anchors/ghacc.crt` + `update-ca-trust extract` | 删除 + `update-ca-trust` |
| macOS | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain` | `security remove-trusted-cert -d` |
| Windows | `certutil -addstore -f ROOT` | `certutil -delstore ROOT "ghacc Root CA"` |

命令规划为纯函数（可单测），执行走可注入 Runner；无权限时返回带 `sudo`/管理员提示的错误。

## daemon

`-d`：POSIX 下 `fork()` + `setsid()`，stdio 重定向到日志文件，子进程写 `<state>/ghacc.pid`；
Windows 暂不支持（明确报错，建议用服务）。`stop` 读 PID 并 `kill(SIGTERM)`。

## TUI

单窗口多面板：顶部状态栏；左侧 provider 列表（取消/启用）；中部流量速率与累计；右侧请求
日志表格；底部快捷键。后台线程 `io.run()`，主线程 `ScreenInteractive::Loop`，通过 `Log`/
`FlowAnalyzer`/`RequestLog` 的线程安全快照拉取数据；定时 `PostEvent(Event::Custom)` 刷新。
渲染主体抽成纯函数 `render_dashboard(const DashboardState&) -> Element`，用 ftxui 的
`Screen::Create` + `Render` 做非交互单测。

## 验证

- 库单测：config 平台目录、log 轮转、ca_trust 命令规划、rule 覆盖（Steam/GitHub 域名）。
- 应用单测：`render_dashboard` 输出包含关键文本。
- e2e（pytest）：`status --json`、`provider list`、`config path`、`completion`、`test`、
  `ca install`（用临时 runner？改为仅断言命令规划不可行时跳过，避免动系统）。
- `mcpp pack`：产出可分发归档。
- README / docs 双语：`README.md`（中文）+ `README_en.md`，`docs/provider-api.md` +
  `docs/provider-api_en.md`，`tests/e2e/README.md` + `tests/e2e/README_en.md`。
