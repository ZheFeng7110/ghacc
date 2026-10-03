module;

#include <chrono>
#include <csignal>

module ghacc.session;

import std;
import asio;
import ghacc.accel;
import ghacc.app;

namespace ghacc::app {

namespace fs = std::filesystem;

struct EngineSession::Impl {
    Config config;
    RuntimePaths paths;
    CertificateAuthority* ca;
    FlowAnalyzer* flow;
    RequestLog* requests;
    const ProviderRegistry* registry;

    asio::io_context io;
    asio::signal_set signals{io};
    std::optional<ProxyEngine> engine;
    std::thread worker;
    std::jthread watcher;
    std::atomic<bool> stopping{false};

    Impl(Config cfg, RuntimePaths p, CertificateAuthority& authority, FlowAnalyzer& analyzer,
         RequestLog& log, const ProviderRegistry& reg)
        : config(std::move(cfg)),
          paths(std::move(p)),
          ca(&authority),
          flow(&analyzer),
          requests(&log),
          registry(&reg) {}

    RuleSet rules_from(const Config& cfg) const { return build_rules(cfg, *registry); }

    std::expected<void, std::string> start() {
        if (engine) return {};
        stopping.store(false);
        io.restart();
        EngineOptions options = engine_options_from_config(config);
        try {
            engine.emplace(io, options, rules_from(config), *ca, *flow, *requests);
            engine->start();
        } catch (const std::exception& error) {
            engine.reset();
            return std::unexpected(std::string(error.what()));
        }
        worker = std::thread([this] {
            try {
                io.run();
            } catch (const std::exception& error) {
                log_error("session", std::string("io_context stopped: ") + error.what());
            }
        });
        return {};
    }

    void stop() {
        if (stopping.exchange(true)) return;
        if (watcher.joinable()) watcher.request_stop();
        std::error_code ignored;
        try {
            signals.cancel(ignored);
        } catch (const std::exception&) {
            // asio signal_set is not supported on every platform.
        }
        if (engine) engine->request_stop();
        io.stop();
        if (worker.joinable()) worker.join();
        engine.reset();
    }

    void handle_signals() {
        try {
            signals.add(SIGINT);
            signals.add(SIGTERM);
            signals.async_wait([this](const std::error_code& ec, int) {
                if (ec) return;
                log_info("session", "stop requested");
                if (engine) engine->request_stop();
            });
        } catch (const std::exception& error) {
            // asio signal_set is not available on every platform (e.g. Windows);
            // the CLI simply cannot be interrupted with Ctrl-C there.
            log_debug("session", std::string("signal handling unavailable: ") + error.what());
        }
    }

    void wait() {
        if (worker.joinable()) worker.join();
        engine.reset();
    }

    void update_rules(RuleSet rules) {
        if (engine) engine->update_rules(std::move(rules));
    }

    void start_config_watch() {
        watcher = std::jthread([this](std::stop_token token) {
            std::error_code ec;
            auto last = fs::last_write_time(paths.config, ec);
            while (!token.stop_requested() && !stopping.load()) {
                for (int i = 0; i < 20 && !token.stop_requested(); ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                if (token.stop_requested()) break;
                std::error_code watch_ec;
                const auto current = fs::last_write_time(paths.config, watch_ec);
                if (watch_ec || current == last) continue;
                last = current;

                auto loaded = load_config(paths.config);
                if (!loaded) {
                    log_warn("reload", "config reload failed: " + loaded.error());
                    continue;
                }
                config = *loaded;
                Log::instance().set_level(config.log_level);
                update_rules(rules_from(config));
                log_info("reload", "reloaded providers and log level from " +
                                       paths.config.string());
            }
        });
    }
};

EngineSession::EngineSession(Config config, RuntimePaths paths, CertificateAuthority& ca,
                             FlowAnalyzer& flow, RequestLog& requests,
                             const ProviderRegistry& registry)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(paths), ca, flow, requests,
                                   registry)) {}

EngineSession::~EngineSession() { stop(); }

std::expected<void, std::string> EngineSession::start() { return impl_->start(); }

void EngineSession::stop() { impl_->stop(); }

bool EngineSession::running() const { return impl_->engine && impl_->engine->running(); }

std::vector<std::uint16_t> EngineSession::ports() const {
    if (!impl_->engine) return {};
    return impl_->engine->listening_ports();
}

void EngineSession::update_rules(RuleSet rules) { impl_->update_rules(std::move(rules)); }

void EngineSession::start_config_watch() { impl_->start_config_watch(); }

void EngineSession::handle_signals() { impl_->handle_signals(); }

void EngineSession::wait() { impl_->wait(); }

} // namespace ghacc::app
