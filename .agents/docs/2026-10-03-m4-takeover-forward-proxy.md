# 2026-10-03 M4：接管层 + 正向代理设计

## 目标

在 M1–M3（rule/config/log/flow/provider、DoH 解析、CA + MITM 反向代理）基础上完成 **M4**：

- `ghacc.accel.takeover.hosts`：带标记块的 hosts 增删、备份、幂等、权限检测。
- `ghacc.accel.engine.forward`：正向代理——CONNECT 隧道、CONNECT+TLS 入侵、absolute-URI 转发、PAC 服务。
- `ghacc.accel.engine.pac`：PAC 脚本生成与请求识别。
- `ghacc.accel.takeover.system_proxy`：三平台系统代理/PAC 设置（GNOME / KDE / macOS networksetup / Windows reg）。
- 端到端验证：正向代理模式 `curl -x` 成功；hosts 模式（需提权）访问 `github.com`。

为支撑 CLI 验证，本里程碑在 `apps/ghacc` 里加入**最小可运行 CLI**（`run` / `hosts` / `ca export`）。
完整的 `cmdline` 子命令与 FTXUI 仪表盘仍属于 M5，届时替换现在的手写解析。

## 模块与数据流

### 正向代理连接管线（proxy_port）

```
accept（proxy 端口，明文 TCP）
  → peek 2 字节（message_peek，不消费）
      ├─ 0x16 0x03（TLS）→ TLS 握手(SNI 选证) → 命中 ReverseProxy 规则 ? 转发 : 关闭
      └─ 明文
          ├─ CONNECT host:port
          │     ├─ 命中 ReverseProxy + tls_sni → 200 + TLS 入侵 → 解出 HTTP 请求 → 转发
          │     ├─ Block → 403
          │     └─ 其它 → 200 + 纯 TCP 隧道（双向 copy + 空闲超时）
          ├─ absolute-URI 明文请求
          │     ├─ 命中 Block → 403
          │     ├─ 指向本地代理的 /pac → 返回 PAC
          │     └─ 其它 → 转发（命中规则 accelerated=true，未命中直接转发）
          └─ origin-form（非 /pac）→ 400
```

### 反向代理复用

M3 的 `engine.cpp` 内联了大量可复用的协程工具。M4 抽出：

- `ghacc.accel.engine.types`：`EngineOptions`、`Pipeline`、`ExchangeMeta`（公共类型，从 `engine` 再导出，保持 API 兼容）。
- `ghacc.accel.engine.detail`：报文/内存/流工具、`connect_best`、`prepare_upstream_tls`、`run_exchange`、`proxy_request`、`run_tunnel`。
  反向代理与正向代理都调用 `proxy_request`，转发逻辑只有一份。
- `ghacc.accel.engine`：只保留 `ProxyEngine` 的监听/装配与反向代理入口。

`EngineOptions` 新增 `enable_forward` / `enable_pac` / `pac_path` / `tunnel_idle_timeout`。
`ProxyEngine::start()` 绑定 forward 监听后，把 `options.proxy_port` 回填为实际端口（支持测试用 0）。

`engine_options_from_config(const Config&)` 按模式映射监听：

| mode | http/https (80/443) | forward (proxy_port) | PAC |
|---|---|---|---|
| Hosts | ✅ | — | — |
| System | — | ✅ | — |
| Pac | — | ✅ | ✅ |
| ForwardOnly | — | ✅ | — |

## 关键接口

### takeover.hosts

```cpp
struct HostEntry { std::string ip, host; };

class HostsManager {
public:
    explicit HostsManager(std::filesystem::path path = default_path(),
                          std::filesystem::path backup = default_backup_path());
    static std::filesystem::path default_path();
    static std::filesystem::path default_backup_path();

    bool is_writable() const;
    std::string permission_hint() const;
    bool contains_our_block() const;
    std::vector<HostEntry> current_block() const;

    std::expected<void, std::string> apply(std::span<const HostEntry>);
    std::expected<void, std::string> revert();
};
```

- 标记块：`# >>> ghacc begin ... >>>` / `# <<< ghacc end <<<`，只替换自己写的块，其余内容逐字保留。
- 备份：首次改动前把原文件复制到 `backup`（已存在则不覆盖），保证 `revert` 之外还可人工恢复。
- 原子写：同目录临时文件 + rename（Windows 用 `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`）。
- `RuleSet::hostnames()` 提供可写入 hosts 的具体域名（精确模式 + `*.suffix` 的通配基名；正则与中间通配跳过）。

### engine.pac

```cpp
struct PacOptions { std::string proxy_host; uint16_t proxy_port; std::string pac_path; };
std::vector<std::string> pac_patterns(const RuleSet&);   // 跳过正则
std::string generate_pac(const RuleSet&, const PacOptions&);
bool is_pac_request(std::string_view target, const PacOptions&);
```

生成 `FindProxyForURL`：命中 `shExpMatch(host, pattern)` 列表则返回 `PROXY host:port`，否则 `DIRECT`。

### engine.forward

```cpp
class ForwardProxy {
public:
    explicit ForwardProxy(const TlsServerContext&);
    asio::awaitable<void> serve(asio::ip::tcp::socket, Pipeline&);
};
```

### takeover.system_proxy

```cpp
enum class SystemProxyKind { None, Gnome, Kde, MacOs, Windows };
struct SystemProxyBackend { SystemProxyKind kind; std::string tool, service; };

std::vector<std::vector<std::string>> plan_http_proxy(const SystemProxyBackend&, bool, std::string_view host, uint16_t port);
std::vector<std::vector<std::string>> plan_pac(const SystemProxyBackend&, bool, std::string_view url);

class SystemProxyManager {
public:
    static SystemProxyManager detect();
    std::expected<void, std::string> set_http(bool, std::string_view, uint16_t);
    std::expected<void, std::string> set_pac(bool, std::string_view);
    std::expected<void, std::string> clear();
    // 注入式 Runner 便于测试；run_process 为默认实现（popen / _popen）。
};
```

命令规划与执行分离：`plan_*` 是纯函数，单测直接断言 argv；`set_*` 顺序执行。

- GNOME：`gsettings set org.gnome.system.proxy ...`
- KDE：`kwriteconfig5/6 --file kioslaverc --group "Proxy Settings" ...`
- macOS：`networksetup -setwebproxy/-setsecurewebproxy/-setautoproxyurl <service> ...`
- Windows：`reg add HKCU\...\Internet Settings ...`（不链接 WinINET，刷新由系统策略/下次登录完成）

## 配置扩展

`config.toml` 增加（可选）：

```toml
[listen]
pac_path = "/pac"
```

`config.cpp` 解析/序列化该字段；`EngineOptions` 默认为 `/pac`。

## 验证

- `hosts_test`：临时文件上 apply/幂等/revert/备份/权限错误路径。
- `rule_test` 增补 `hostnames()`：精确、通配基名、正则跳过、去重。
- `pac_test`：生成内容含 shExpMatch 与 PROXY；`is_pac_request` 处理 origin/absolute/查询串；正则被跳过。
- `system_proxy_test`：四个后端 `plan_http_proxy` / `plan_pac` / disable 的 argv 断言。
- `forward_test`（回环集成，全部临时端口）：
  1. absolute-URI 明文转发：代理 → 回环明文上游，验证 200 与 body。
  2. CONNECT 纯隧道：CONNECT 到回环上游后走明文 HTTP，验证 body。
  3. CONNECT + TLS 入侵：规则 `test.local` 固定 IP，客户端用 CA 校验叶子证书，验证转发与请求日志。
  4. Block 规则 absolute-URI 返回 403。
  5. `/pac` 返回 `application/x-ns-proxy-autoconfig` 且端口为实际绑定端口。
- 手工：`ghacc run --mode forward` 后 `curl -x http://127.0.0.1:26501 http://...`；
  hosts 模式需 root，绑定 80/443 并写入 `/etc/hosts`。

所有自动化测试不触碰 80/443、`/etc/hosts` 或系统代理。

## 已知限制

- 只做 HTTP/1.1。
- hosts 文件不支持通配域名：`*.github.com` 只能落到基名 `github.com`，子域仍需 MITM/正向代理模式覆盖。
- Windows/macOS 的系统代理与 CA 信任路径未在 CI 验证（无对应平台），代码按平台分派并给出明确错误。
- 正向代理 CONNECT 的 MITM 默认上游按 TLS 处理（端口 443 语义）。
- `DnsResolver` 的 DoH 请求仍使用阻塞 I/O，超时依赖底层 TCP 超时；网络极差时解析可能长时间阻塞
  引擎的 io 线程（M2 遗留，后续可改为全异步 + 定时器）。
- hosts 模式的 root 端到端（80/443 + `/etc/hosts`）未在无特权环境自动验证，仅验证了临时文件上的
  标记块增删与无权限时的报错提示。
