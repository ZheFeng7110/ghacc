# 2026-10-03 M3：CA + MITM 引擎设计

## 目标

在 M1/M2 的基础上完成 **M3（CA + MITM 引擎）**：

- `ghacc.accel.ca.authority`：已完成（自签根 CA、按域名签发叶子证书、缓存、导出）。
- `ghacc.accel.http.*`：HTTP/1.1 报文模型、增量解析、序列化。
- `ghacc.accel.net.tls`：服务端 `SSL_CTX` 封装（SNI 选证、ALPN `http/1.1`）与系统 CA 加载。
- `ghacc.accel.engine`：反向代理引擎（80/443 监听、TLS MITM、上游择优连接、流式转发、统计与请求日志）。
- 集成测试：本机回环上游 HTTP/TLS 服务，经 MITM 环路验证证书链与转发。

## 模块与数据流

```
accept（http / https 监听）
  ├─ https：TLS 握手（net.tls 的 SNI 回调按域名取 CA 叶子证书，ALPN=http/1.1）
  └─ http ：明文
        ↓
  read_head → http::parse_request_head
        ↓
  Host → RuleSet::match（取 action / forward_destination / ip / user_agent / timeout）
        ↓
  DnsResolver::resolve_ranked(upstream_host, port) → connect_best（按 RTT 顺序、带超时）
        ↓
  上游为 TLS 时（客户端 TLS 或 absolute-form https）用 asio::ssl 客户端，SNI=host
        ↓
  run_exchange：转发请求头/体（Content-Length / Chunked 流式）→ 读响应头/体 → 回写客户端
        ↓
  FlowAnalyzer 统计字节；RequestLog 记录一条请求
```

设计取舍：

- **Hosts 模式下 http 与 https 使用独立监听**，因此 M3 不做首字节 sniffing（sniffing 留给
  M4 的正向代理端口，那里 CONNECT 与 TLS 共用一个端口）。
- 每条连接只处理**一个请求**并强制 `Connection: close`，避免 keep-alive 复用与响应
  分帧歧义；功能正确、实现简单，后续可加连接池。
- 请求体 / 响应体**边读边转发**，使用 `ChunkedScanner` 识别分块结束，不整体缓冲大文件。
- 上游端口默认 80/443，`EngineOptions` 暴露 `upstream_http_port` / `upstream_https_port`
  与 `upstream_tls_verify`，便于测试与自定义。
- 规则 `Block` 返回 403；`Tunnel`/`StaticResponse` 在 M3 暂按反向代理处理（Tunnel 语义属于
  正向代理，M4 落地）。

## 接口摘要

### http.message

```cpp
class Headers { set/add/remove/get/get_all/contains/fields ... };  // 大小写不敏感、保序
struct Request  { std::string method, target, version; Headers headers; };
struct Response { std::string version, reason; int status; Headers headers; };
```

### http.parser

```cpp
std::expected<Request,  std::string> parse_request_head (std::string_view);
std::expected<Response, std::string> parse_response_head(std::string_view);
enum class BodyFraming { None, ContentLength, Chunked, UntilClose };
std::expected<BodyInfo,   std::string> request_body_info (const Request&);
std::expected<BodyInfo,   std::string> response_body_info(const Request&, const Response&);
class ChunkedScanner { std::size_t consume(std::string_view); bool done(); bool failed(); };
```

### http.writer

```cpp
std::string serialize_request (const Request&);
std::string serialize_response(const Response&);
std::string status_reason(int status);
```

### net.tls

```cpp
class TlsServerContext {
public:
    explicit TlsServerContext(const CertificateAuthority&);
    asio::ssl::context& context() noexcept;   // 已装 SNI 回调与 ALPN
};
void load_system_ca(asio::ssl::context&);     // 供上游客户端验证使用
```

### engine

```cpp
struct EngineOptions {
    ProxyMode mode; std::string listen_address = "127.0.0.1";
    std::uint16_t http_port = 80, https_port = 443, proxy_port = 26501;
    std::uint16_t upstream_http_port = 80, upstream_https_port = 443;
    bool enable_http = true, enable_https = true, upstream_tls_verify = true;
    DnsConfig dns;
};
class ProxyEngine {
    ProxyEngine(asio::io_context&, EngineOptions, RuleSet, CertificateAuthority&,
                FlowAnalyzer&, RequestLog&);
    void start();                          // 绑定监听，抛 std::system_error
    asio::awaitable<void> run();           // start() + 等待 request_stop
    void request_stop();                   // 线程安全（post 到 io 线程取消）
    std::vector<std::uint16_t> listening_ports() const;
};
```

`RequestLog` 与 `RequestRecord` 并入 `ghacc.accel.flow`，供 M5 TUI 表格使用。

## 验证

- `http_test`：请求/响应解析、Content-Length/Chunked 分帧、ChunkedScanner（含跨块与 trailer）、
  序列化往返。
- `engine_test`：
  1. 明文反向代理：引擎 http 监听 → 回环明文上游，验证请求体/响应体透传与 `RequestLog`。
  2. TLS MITM：客户端以 SNI `github.com` 连接引擎 https 监听，用 CA 校验引擎动态签发的叶子
     证书；引擎再以 TLS 连接回环上游（`upstream_tls_verify=false`），验证证书链与转发。
  3. `Block` 规则返回 403。
- 所有测试使用临时端口（bind 0）与临时目录，不触碰 80/443 与 `/etc/hosts`。
