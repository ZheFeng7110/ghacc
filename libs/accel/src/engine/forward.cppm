export module ghacc.accel.engine.forward;

import std;
import asio;
import ghacc.accel.engine.types;
import ghacc.accel.net.tls;

export namespace ghacc::accel {

/// Forward-proxy connection handler.
///
/// Serves the listener bound on `EngineOptions::proxy_port`:
///   - `CONNECT host:port`            plain tunnel, or TLS interception when a
///                                    `ReverseProxy` rule with `tls_sni` matches;
///   - absolute-URI HTTP requests     forwarded (accelerated when a rule matches);
///   - the PAC file at `EngineOptions::pac_path` when `enable_pac` is set.
///
/// A TLS ClientHello sent directly to the proxy port is intercepted when its
/// SNI matches a rule; otherwise the connection is dropped.
class ForwardProxy {
public:
    explicit ForwardProxy(TlsServerContext& tls) noexcept : tls_(&tls) {}

    asio::awaitable<void> serve(asio::ip::tcp::socket socket, Pipeline& pipeline);

private:
    TlsServerContext* tls_;
};

} // namespace ghacc::accel
