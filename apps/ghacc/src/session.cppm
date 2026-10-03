export module ghacc.session;

import std;
import ghacc.accel;
import ghacc.app;

export namespace ghacc::app {

/// Owns the io_context, the `ProxyEngine` and (optionally) a background watcher
/// that hot-reloads providers and the log level from `config.toml`.
///
/// `start()` binds the listeners and runs the io_context on a worker thread;
/// `stop()` (or destruction) shuts the engine down and joins it.
class EngineSession {
public:
    EngineSession(Config config, RuntimePaths paths, CertificateAuthority& ca,
                  FlowAnalyzer& flow, RequestLog& requests, const ProviderRegistry& registry);
    ~EngineSession();

    EngineSession(const EngineSession&) = delete;
    EngineSession& operator=(const EngineSession&) = delete;

    /// Bind listeners and start serving. Returns a message on failure.
    std::expected<void, std::string> start();

    /// Ask the engine to stop and join the worker thread.
    void stop();

    [[nodiscard]] bool running() const;
    [[nodiscard]] std::vector<std::uint16_t> ports() const;

    /// Replace the live rule set (new connections only).
    void update_rules(RuleSet rules);

    /// Watch `<config>` for mtime changes and hot-reload providers/log level.
    void start_config_watch();

    /// Install SIGINT/SIGTERM handlers that stop the engine (CLI foreground).
    void handle_signals();

    /// Block until the worker thread finishes (after a stop or signal).
    void wait();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ghacc::app
