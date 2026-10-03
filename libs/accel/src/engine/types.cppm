export module ghacc.accel.engine.types;

import std;
import asio;
import ghacc.accel.config;
import ghacc.accel.flow;
import ghacc.accel.rule;
import ghacc.accel.net.resolver;

export namespace ghacc::accel {

/// Runtime options for the local proxy engine.
///
/// The same struct drives both capture modes: the Hosts/MITM reverse proxy
/// (`enable_http` / `enable_https`) and the forward proxy (`enable_forward`,
/// optionally serving a PAC file when `enable_pac` is set).
struct EngineOptions {
    ProxyMode mode = ProxyMode::Hosts;
    std::string listen_address = "127.0.0.1";
    /// Ports the engine listens on for the Hosts/MITM reverse proxy.
    std::uint16_t http_port = 80;
    std::uint16_t https_port = 443;
    /// Forward-proxy port (System / PAC / ForwardOnly).
    std::uint16_t proxy_port = 26501;
    /// Upstream ports used when the reverse proxy connects out.
    std::uint16_t upstream_http_port = 80;
    std::uint16_t upstream_https_port = 443;
    bool enable_http = true;
    bool enable_https = true;
    /// Bind the forward-proxy listener (CONNECT / absolute-URI).
    bool enable_forward = false;
    /// Serve a PAC file from the forward-proxy listener.
    bool enable_pac = false;
    /// Path the PAC file is served from.
    std::string pac_path = "/pac";
    /// Verify upstream certificates. Tests may disable this for self-signed hosts.
    bool upstream_tls_verify = true;
    /// Close idle CONNECT tunnels after this long.
    std::chrono::seconds tunnel_idle_timeout{600};
    DnsConfig dns;
};

/// Shared state handed to the per-connection serving coroutines.
///
/// `rules` is a snapshot shared with the engine; replacing the engine's rules
/// leaves in-flight connections on the old set while new connections pick up
/// the new one.
struct Pipeline {
    std::shared_ptr<const RuleSet> rules;
    DnsResolver& resolver;
    FlowAnalyzer& flow;
    RequestLog& requests;
    asio::ssl::context& upstream_tls;
    const EngineOptions& options;
};

/// Bookkeeping passed to `run_exchange` so a `RequestRecord` can be emitted.
struct ExchangeMeta {
    std::string host;
    std::string upstream_ip;
    bool accelerated = false;
    std::chrono::steady_clock::time_point started;
};

} // namespace ghacc::accel
