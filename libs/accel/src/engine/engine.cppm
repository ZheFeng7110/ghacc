export module ghacc.accel.engine;

import std;
import asio;
import ghacc.accel.config;
import ghacc.accel.flow;
import ghacc.accel.rule;
import ghacc.accel.ca.authority;

export namespace ghacc::accel {

/// Runtime options for the local proxy engine.
struct EngineOptions {
    ProxyMode mode = ProxyMode::Hosts;
    std::string listen_address = "127.0.0.1";
    /// Ports the engine listens on for the Hosts/MITM reverse proxy.
    std::uint16_t http_port = 80;
    std::uint16_t https_port = 443;
    /// Forward-proxy port (System/PAC/ForwardOnly; used from M4 on).
    std::uint16_t proxy_port = 26501;
    /// Upstream ports used when the reverse proxy connects out.
    std::uint16_t upstream_http_port = 80;
    std::uint16_t upstream_https_port = 443;
    bool enable_http = true;
    bool enable_https = true;
    /// Verify upstream certificates. Tests may disable this for self-signed hosts.
    bool upstream_tls_verify = true;
    DnsConfig dns;
};

/// Local reverse-proxy / MITM engine.
///
/// The engine binds its listeners in `start()` and accepts connections until
/// `request_stop()` is called. Each accepted connection is handled on the
/// supplied `asio::io_context`; the engine does not run the context itself.
class ProxyEngine {
public:
    ProxyEngine(asio::io_context& io, EngineOptions options, RuleSet rules,
                CertificateAuthority& ca, FlowAnalyzer& flow, RequestLog& requests);
    ~ProxyEngine();

    ProxyEngine(const ProxyEngine&) = delete;
    ProxyEngine& operator=(const ProxyEngine&) = delete;
    ProxyEngine(ProxyEngine&&) noexcept;
    ProxyEngine& operator=(ProxyEngine&&) noexcept;

    /// Bind the configured listeners and begin accepting.
    /// Throws `std::system_error` (e.g. a privileged port without permission).
    void start();

    /// Bind (if needed) and run until `request_stop()`.
    asio::awaitable<void> run();

    /// Ask the engine to stop accepting; safe to call from any thread.
    void request_stop();

    [[nodiscard]] bool running() const noexcept;

    /// Actual bound ports, in listener order (useful with port 0 in tests).
    [[nodiscard]] std::vector<std::uint16_t> listening_ports() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ghacc::accel
