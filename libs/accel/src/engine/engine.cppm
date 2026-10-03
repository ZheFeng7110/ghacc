export module ghacc.accel.engine;

import std;
import asio;
import ghacc.accel.config;
import ghacc.accel.flow;
import ghacc.accel.rule;
import ghacc.accel.ca.authority;

// EngineOptions / Pipeline / ExchangeMeta live in a shared module so the
// reverse- and forward-proxy implementations can both depend on them.
export import ghacc.accel.engine.types;

export namespace ghacc::accel {

/// Map a user `Config` onto engine listening options (mode -> listeners).
[[nodiscard]] EngineOptions engine_options_from_config(const Config& config);

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
