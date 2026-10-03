# 2026-10-02 网络加速（GitHub / Steam）提取重写设计

## 1. 背景与目标

将 `/tmp/SteamTools`（Watt Toolkit / Steam++）中 `BD.WTTS.Client.Plugins.Accelerator.ReverseProxy`
的「网络加速」引擎提取出来，用 **C++23 + C++ 模块** 重写为跨平台 CLI/TUI 程序 `ghacc`，
构建系统使用 [**mcpp**](https://github.com/mcpp-community/mcpp)。

- 内置加速目标：**GitHub**、**Steam**
- 预留 provider 扩展接口，后续可添加更多加速目标
- 代理模式：**Hosts+MITM** 与 **System/PAC 正向代理** 都要
- 平台：Linux / macOS / Windows
- 本次**不做** Steam JS 脚本注入（仅预留接口）

## 2. 源机制速览

引擎源自 FastGithub 2.1.4 + YARP：

```
Hosts/System/PAC 接管
  → 本地代理服务（80/443 反向代理 或 26501 正向代理）
  → 探测 TLS；命中规则的域名做 MITM（本地 CA 动态签发证书）
  → DomainPattern 匹配规则 → DoH 解析目标 IP 并择优连接
  → HTTP/1.1 转发 / CONNECT 隧道透传
  → 流量统计 + 请求日志
```

域名规则在源项目中来自服务端 `AccelerateProjectDTO`；本重写改为
**内置 provider 规则 + 用户配置文件扩展**，不依赖服务端。

## 3. 技术选型

| 用途 | 选型 | 来源 |
|---|---|---|
| 构建 | mcpp workspace | 本机 |
| 异步 I/O | `chriskohlhoff.asio@1.38.1`（`features=["ssl"]`） | mcpp-index / gitcode CN 镜像 |
| TLS/加密 | `compat.openssl@3.5.1` | mcpp-index / gitcode CN 镜像（源码静态构建） |
| TUI | `compat.ftxui@7.0.3`（`features=["modules"]` → `import ftxui;`） | mcpp-index |
| 单元测试 | `boost-ext.ut@2.3.1`（`import boost.ut;`） | mcpp-index |
| CLI | `mcpplibs.cmdline` | mcpp-index / gitcode CN 镜像 |
| 配置 | `marzer.tomlplusplus@3.4.0`（`import tomlplusplus;`） | mcpp-index / gitcode CN 镜像 |

只用 HTTP/1.1：本地 TLS 只对客户端通告 ALPN `http/1.1`，上游同样 1.1，规避 HTTP/2 复杂度。

## 4. 依赖与网络约束（重要）

所有第三方依赖一律在 mcpp.toml 中声明（索引依赖，不再 vendor 到仓库）：

| 依赖 | 声明位置 | 版本 / feature |
|---|---|---|
| asio | `[workspace.dependencies.chriskohlhoff]` | `1.38.1`, `features=["ssl"]` |
| openssl | `[workspace.dependencies.compat]` | `3.5.1` |
| ftxui | `[workspace.dependencies.compat]` | `7.0.3`, `features=["modules"]` |
| boost.ut | `[workspace.dependencies.boost-ext]` | `2.3.1` |
| toml++ | `[workspace.dependencies]` | `3.4.0` |

本机网络状况（2026-10-02 实测）：

- **GitHub 不可达**（curl 超时；xlings 曾卡在 `20.205.243.166:443` 零字节）。
- `compat.ftxui@7.0.3`、`boost-ext.ut@2.3.1` 在 gitcode **无 CN 镜像**。
- asio / openssl / tomlplusplus / cmdline 有 gitcode CN 镜像，可正常拉取。

因此**依赖的拉取与首次构建由用户手动完成**（在修好网络或手动放置产物后）。
构建时若 OpenSSL 因网络失败，应停止并请用户手动处理（用户明确要求）。

另外，`~/.mcpp/registry/data/xim-pkgindex/.xlings-index-cache.json` 曾因记录
`/tmp/opencode/mcpp-pinned/...` 的陈旧路径导致 `xim:* not found`，已删除（备份
`/tmp/opencode/xim-index-cache.bak.json`）。

## 5. 目录结构

```
ghacc/
├── mcpp.toml                  # 虚拟 workspace + workspace.dependencies
├── .agents/docs/              # 设计文档（本文件）
├── libs/accel/                # 核心引擎包 ghacc.accel
│   ├── mcpp.toml
│   ├── src/*.cppm / *.cpp
│   └── tests/*.cpp
└── apps/ghacc/                # CLI/TUI 程序包 ghacc.ghacc
    ├── mcpp.toml
    └── src/{main.cpp,cli.*,tui.*}
```

## 6. 核心模块划分（`ghacc.accel.*`）

| 模块 | 职责 |
|---|---|
| `ghacc.accel` | 库根，聚合 re-export |
| `ghacc.accel.rule` | `DomainRule` / `RuleSet`，通配+正则匹配，PAC 用 pattern 列表 |
| `ghacc.accel.config` | 配置模型 + TOML 读写（tomlplusplus） |
| `ghacc.accel.log` | 文件日志 + 内存环形缓冲（TUI 读取） |
| `ghacc.accel.flow` | 5s 窗口读写速率 + 累计字节 |
| `ghacc.accel.net.dns` | DoH 报文编解码、缓存、RTT 择优；系统解析兜底 |
| `ghacc.accel.net.socket` | asio 封装、超时、候选 IP 竞速连接 |
| `ghacc.accel.net.tls` | `SSL_CTX` 管理、SNI 回调、证书缓存 |
| `ghacc.accel.http.*` | HTTP/1.1 报文模型 / 增量解析 / 序列化转发 |
| `ghacc.accel.ca.authority` | 根 CA 生成/加载/导出、按域名签发叶子（OpenSSL） |
| `ghacc.accel.engine` | 引擎总控：监听、连接管线（MITM + Forward） |
| `ghacc.accel.takeover.hosts` | 带标记块的 hosts 增删 + 备份 + 权限检测 |
| `ghacc.accel.takeover.system_proxy` | 系统代理/PAC 设置（三平台分派） |
| `ghacc.accel.provider` | `IAccelerationProvider` + `ProviderRegistry` |
| `ghacc.accel.provider.github` | GitHub 内置规则 |
| `ghacc.accel.provider.steam` | Steam 内置规则 |

### Provider 扩展接口（预留）

```cpp
export module ghacc.accel.provider;

export namespace ghacc::accel {

struct ProviderMeta { std::string id, display_name, description, homepage; bool default_enabled; };

// 本次不实现，仅预留脚本注入能力
class IScriptInjector {
public:
    virtual ~IScriptInjector() = default;
    virtual bool matches(std::string_view url) const = 0;
    virtual std::string script_for(std::string_view url) const = 0;
};

class IAccelerationProvider {
public:
    virtual ~IAccelerationProvider() = default;
    virtual ProviderMeta meta() const = 0;
    virtual std::vector<DomainRule> rules() const = 0;
    virtual void on_register(class ProviderContext&) {}
    virtual void on_start(class ProviderContext&) {}
    virtual void on_stop(class ProviderContext&) {}
    virtual std::shared_ptr<IScriptInjector> script_injector() const { return nullptr; }
};

class ProviderRegistry {
public:
    void add(std::unique_ptr<IAccelerationProvider>);
    IAccelerationProvider* find(std::string_view id) const;
    std::vector<IAccelerationProvider*> all() const;
    RuleSet build_rules(const std::vector<std::string>& enabled) const;
};

}
```

扩展方式：
1. 编译期：新增 `ghacc.accel.provider.<x>` 模块并注册（复杂逻辑）。
2. 运行期：配置 `[[provider.custom]]` 直接给域名规则，由 `ConfigProvider` 实现（无需重新编译）。

## 7. CLI / TUI

CLI 子命令：`run` / `stop` / `status` / `provider` / `ca` / `hosts` / `proxy` / `test` / `config`。
无参数进入 FTXUI 仪表盘：provider 开关、模式切换、实时流量、请求日志、CA/hosts 操作提示。

## 8. 平台适配

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| hosts | `/etc/hosts`（root） | `/etc/hosts`（root） | `System32\drivers\etc\hosts`（管理员） |
| 绑定 80/443 | root 或 `setcap cap_net_bind_service=+eip` | root | 管理员 |
| CA 信任 | `update-ca-certificates` / `update-ca-trust` | `security add-trusted-cert` | `certutil -addstore -f ROOT` |
| 系统代理 | GNOME gsettings / KDE / 环境变量 | `networksetup` | WinINET 注册表 |

## 9. 实施里程碑

- **M0 骨架**：workspace + 索引依赖打通（asio/openssl/ftxui/boost.ut/tomlplusplus/cmdline），hello 构建
- **M1 基础模块**：rule / config / log / flow / provider + boost.ut 单测
- **M2 网络与 DNS**：asio 封装、DoH 编解码 + 缓存 + 择优，`ghacc test <domain>`
- **M3 CA + MITM**：CA 签发、HTTP/1.1 编解码、反向代理；集成测试
- **M4 接管层 + 正向代理**：hosts、CONNECT/absolute-URI、PAC、系统代理
- **M5 CLI 完整 + TUI**
- **M6 三平台打磨 + 打包**

## 10. 验证

- `mcpp test`（boost.ut）覆盖纯逻辑单元。
- 非特权高端口做集成测试，避免触碰真实 80/443 与 `/etc/hosts`。
- 手工：三平台上 GitHub / Steam 的 hosts+MITM、系统代理/PAC。

## 11. 进展与已知问题

### 11.1 mcpp workspace 依赖不继承 `features`（重要）

`mcpp` 的 `merge_workspace_deps`（`src/project.cppm`）在成员使用 `dep.workspace = true`
时只复制 `version/path/git`，**不复制 `features`**。后果：

- `compat.ftxui` 以 `{ workspace = true }` 引入时 `modules` feature 丢失，
  包会以 `features: []` 构建，`source_globs` 排除 `*.cppm`，于是没有 `ftxui` 模块，
  `import ftxui;` 报 `failed to read compiled module: gcm.cache/ftxui.gcm`。
- 同理 `chriskohlhoff.asio` 的 `ssl` feature 也会丢失，`asio::ssl` 整个命名空间消失。

**约定**：凡带 `features` 的依赖，feature 必须写在成员自己的依赖边上：

```toml
# apps/ghacc/mcpp.toml
[dependencies.compat]
ftxui = { workspace = true, features = ["modules"] }

# libs/accel/mcpp.toml
[dependencies.chriskohlhoff]
asio = { version = "1.38.1", features = ["ssl"] }
```

（`{ workspace = true, features = [...] }` 合法：`features` 解析在 `workspace` 之前。）

### 11.2 其他环境备注

- `~/.mcpp/registry/data/xim-pkgindex/.xlings-index-cache.json` 曾记录
  `/tmp/opencode/mcpp-pinned/...` 的陈旧路径，导致 `xim:make/perl/glibc/linux-headers`
  解析失败；删除该缓存（备份 `/tmp/opencode/xim-index-cache.bak.json`）后恢复。
- `compat.openssl` 安装曾卡在 GitHub（`20.205.243.166:443` 零字节）；网络恢复后构建成功并缓存。
- asio 模块未导出 `asio::streambuf` / `read_until`，也未导出 `verify_mode` 的无作用域枚举值；
  DoH 客户端因此手动读取 HTTP 响应，TLS 校验后续直接用 OpenSSL API 设置。

### 11.3 已完成

- M0：workspace + 索引依赖（asio/openssl/ftxui/boost.ut/toml++/cmdline）
- M1：`rule` / `flow` / `log` / `provider`（github/steam）/ `config`，单测全绿
- M2（部分）：`net.dns`（DNS 报文编解码，含 CNAME 压缩解析）+
  `net.resolver`（DoH POST、TTL 缓存、系统解析兜底、TCP RTT 择优）；
  CLI `ghacc test <domain>` 实机验证通过（github.com → 20.205.243.166，111ms）
- M3（部分）：`ca.authority`（OpenSSL 自签根 CA，落盘 `ca.crt`/`ca.key` 0600；
  按域名签发叶子证书，SAN/扩展齐全，含大小写不敏感缓存）
- M3（完成）：`http.message`/`http.parser`/`http.writer`（HTTP/1.1 报文模型、增量解析、
  Content-Length/Chunked 分帧、`ChunkedScanner`）；`net.tls`（服务端 `SSL_CTX` +
  SNI 选证 + ALPN `http/1.1`、系统 CA 加载）；`engine`（http/https 监听、TLS MITM、
  上游 DoH 择优连接、流式反向转发、`Block`/`fixed-ip`/`forward_destination`/`user_agent`、
  `FlowAnalyzer` 统计与 `RequestLog` 请求日志）。详见
  `.agents/docs/2026-10-03-m3-ca-mitm-engine.md`。

测试：`mcpp test`（accel 10 个 + ghacc 1 个）全绿，其中 `http_test` 覆盖报文编解码与分块，
`engine_test` 用回环明文/TLS 上游验证反向代理、403 拦截、TLS MITM 证书链与请求日志。

### 11.4 M4（完成）

- `takeover.hosts`：标记块增删、首次备份、幂等、权限检测与提示、原子写。
- `engine.types` / `engine.detail`：抽出反向/正向代理共用的 `EngineOptions`、`Pipeline`、
  流工具、`connect_best`、`run_exchange`、`proxy_request`、`run_tunnel`。
- `engine.forward`：正向代理端口——`CONNECT` 纯隧道、`CONNECT` + TLS 入侵、
  absolute-URI 明文转发、proxy 端口首字节 sniffing（TLS 直连按 SNI 匹配）。
- `engine.pac`：PAC 生成与请求识别，由正向代理监听在 `pac_path` 提供。
- `takeover.system_proxy`：GNOME / KDE / macOS / Windows 四后端命令规划与执行，
  可注入 Runner 便于测试。
- 最小 CLI：`ghacc run --mode ...`、`ghacc hosts show|apply|revert`、`ghacc ca path|show|export`。
- 测试新增：`hosts_test`、`pac_test`、`system_proxy_test`、`forward_test`（回环集成：
  absolute-URI、CONNECT 隧道、CONNECT+TLS 入侵、403、PAC），`rule_test` 增补 `hostnames()`。
- 端到端：`ghacc run --mode forward` + `curl -x` 经本地正向代理成功；hosts 模式在
  无 root 时给出明确提权提示。

### 11.5 下一步

- M5：用 `mcpplibs.cmdline` 重写完整 CLI（含 `proxy set/clear`、`status --json`）+
  FTXUI 仪表盘；替换当前手写解析。
- hosts 模式的 root 端到端（绑定 80/443 + 写入 `/etc/hosts`）需在具备权限的机器手工验证。
- 已知：反向代理的 `Tunnel` 规则仍按反向代理处理；“正向代理端口首字节 sniffing” 已在
  M4 落地。

## 12. 已知限制

- 只支持 HTTP/1.1。
- 暂不支持 Steam 脚本注入。
- Windows 不做 WinDivert DNS 拦截，统一用 Hosts 模式。
