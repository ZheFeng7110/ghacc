module;

#include <openssl/ssl.h>

module ghacc.accel.engine;

import std;
import asio;
import ghacc.accel.config;
import ghacc.accel.flow;
import ghacc.accel.log;
import ghacc.accel.rule;
import ghacc.accel.ca.authority;
import ghacc.accel.engine.types;
import ghacc.accel.engine.detail;
import ghacc.accel.engine.forward;
import ghacc.accel.net.resolver;
import ghacc.accel.net.tls;
import ghacc.accel.http.message;
import ghacc.accel.http.parser;
import ghacc.accel.http.writer;

namespace ghacc::accel {

namespace {

using http::Request;

/// Serve one request on an established reverse-proxy client stream.
template <class ClientStream>
asio::awaitable<void> serve_reverse(Pipeline& p, ClientStream& client, bool client_tls,
                                    std::string sni) {
    const auto started = std::chrono::steady_clock::now();
    std::string client_buffer;
    auto head = co_await read_head(client, client_buffer);
    if (!head) co_return;

    auto parsed = http::parse_request_head(*head);
    if (!parsed) {
        co_await send_error(client, 400, "Bad Request");
        co_return;
    }
    Request request = std::move(*parsed);

    bool target_https = false;
    request.target = to_origin_form(request.target, target_https);
    if (request.target.empty() || request.target.front() != '/') request.target = "/";

    const auto host_header = request.headers.get("host");
    const std::string authority = host_header ? std::string(*host_header) : sni;
    const std::string host = http::lower_ascii(host_only(authority));
    if (host.empty()) {
        co_await send_error(client, 400, "Missing Host");
        co_return;
    }

    const auto rule = p.rules->match(host);
    if (rule && rule->action == RuleAction::Block) {
        log_info("engine", "blocked " + host);
        co_await send_error(client, 403, "Forbidden");
        co_return;
    }

    const bool upstream_tls = client_tls || target_https;
    const std::uint16_t default_port =
        upstream_tls ? p.options.upstream_https_port : p.options.upstream_http_port;
    const std::uint16_t upstream_port = port_from_authority(authority, default_port);
    const std::string upstream_host =
        (rule && !rule->forward_destination.empty()) ? rule->forward_destination : host;

    co_await proxy_request(p, client, client_buffer, request, host, authority, rule, upstream_host,
                           upstream_port, upstream_tls, started);
}

} // namespace

struct ProxyEngine::Impl {
    asio::io_context& io;
    EngineOptions options;
    std::shared_ptr<RuleSet> rules;
    CertificateAuthority* ca;
    FlowAnalyzer* flow;
    RequestLog* requests;
    std::unique_ptr<TlsServerContext> tls_server;
    std::unique_ptr<ForwardProxy> forward_proxy;
    asio::ssl::context upstream_tls{asio::ssl::context::tls_client};
    DnsResolver resolver;
    std::vector<std::unique_ptr<asio::ip::tcp::acceptor>> acceptors;
    std::vector<std::uint16_t> ports;
    std::optional<asio::steady_timer> stop_timer;
    std::atomic<bool> stopping{false};
    std::atomic<bool> started{false};

    Impl(asio::io_context& context, EngineOptions opts, RuleSet rule_set,
         CertificateAuthority& authority, FlowAnalyzer& analyzer, RequestLog& log)
        : io(context),
          options(std::move(opts)),
          rules(std::make_shared<RuleSet>(std::move(rule_set))),
          ca(&authority),
          flow(&analyzer),
          requests(&log),
          resolver(options.dns) {
        load_system_ca(upstream_tls);
        tls_server = std::make_unique<TlsServerContext>(*ca);
        forward_proxy = std::make_unique<ForwardProxy>(*tls_server);
    }

    Pipeline pipeline() noexcept {
        return Pipeline{rules, resolver, *flow, *requests, upstream_tls, options};
    }

    asio::awaitable<void> accept_loop(asio::ip::tcp::acceptor& acceptor, bool tls) {
        for (;;) {
            std::error_code ec;
            auto socket =
                co_await acceptor.async_accept(asio::redirect_error(asio::use_awaitable, ec));
            if (ec) {
                if (stopping.load() || ec == asio::error::operation_aborted) co_return;
                continue;
            }
            if (stopping.load()) {
                std::error_code ignored;
                socket.close(ignored);
                co_return;
            }
            if (tls) {
                asio::co_spawn(io, handle_tls(std::move(socket)), asio::detached);
            } else {
                asio::co_spawn(io, handle_http(std::move(socket)), asio::detached);
            }
        }
    }

    asio::awaitable<void> forward_accept_loop(asio::ip::tcp::acceptor& acceptor) {
        for (;;) {
            std::error_code ec;
            auto socket =
                co_await acceptor.async_accept(asio::redirect_error(asio::use_awaitable, ec));
            if (ec) {
                if (stopping.load() || ec == asio::error::operation_aborted) co_return;
                continue;
            }
            if (stopping.load()) {
                std::error_code ignored;
                socket.close(ignored);
                co_return;
            }
            asio::co_spawn(io, handle_forward(std::move(socket)), asio::detached);
        }
    }

    asio::awaitable<void> handle_http(asio::ip::tcp::socket socket) {
        auto p = pipeline();
        try {
            co_await serve_reverse(p, socket, false, "");
        } catch (const std::exception& e) {
            log_debug("engine", std::string("http connection error: ") + e.what());
        }
    }

    asio::awaitable<void> handle_tls(asio::ip::tcp::socket socket) {
        auto p = pipeline();
        try {
            asio::ssl::stream<asio::ip::tcp::socket> stream(std::move(socket),
                                                            tls_server->context());
            std::error_code ec;
            co_await stream.async_handshake(asio::ssl::stream_base::server,
                                            asio::redirect_error(asio::use_awaitable, ec));
            if (ec) co_return;
            const char* name = SSL_get_servername(stream.native_handle(), TLSEXT_NAMETYPE_host_name);
            std::string sni = name != nullptr ? name : "";
            co_await serve_reverse(p, stream, true, std::move(sni));
            std::error_code shutdown_ec;
            co_await stream.async_shutdown(asio::redirect_error(asio::use_awaitable, shutdown_ec));
        } catch (const std::exception& e) {
            log_debug("engine", std::string("tls connection error: ") + e.what());
        }
    }

    asio::awaitable<void> handle_forward(asio::ip::tcp::socket socket) {
        auto p = pipeline();
        try {
            co_await forward_proxy->serve(std::move(socket), p);
        } catch (const std::exception& e) {
            log_debug("engine", std::string("forward connection error: ") + e.what());
        }
    }
};

EngineOptions engine_options_from_config(const Config& config) {
    EngineOptions options;
    options.mode = config.mode;
    options.listen_address = config.listen.address;
    options.http_port = config.listen.http_port;
    options.https_port = config.listen.https_port;
    options.proxy_port = config.listen.proxy_port;
    options.pac_path = config.listen.pac_path;
    options.dns = config.dns;

    switch (config.mode) {
        case ProxyMode::Hosts:
            options.enable_http = true;
            options.enable_https = true;
            options.enable_forward = false;
            options.enable_pac = false;
            break;
        case ProxyMode::System:
            options.enable_http = false;
            options.enable_https = false;
            options.enable_forward = true;
            options.enable_pac = false;
            break;
        case ProxyMode::Pac:
            options.enable_http = false;
            options.enable_https = false;
            options.enable_forward = true;
            options.enable_pac = true;
            break;
        case ProxyMode::ForwardOnly:
            options.enable_http = false;
            options.enable_https = false;
            options.enable_forward = true;
            options.enable_pac = false;
            break;
    }
    return options;
}

ProxyEngine::ProxyEngine(asio::io_context& io, EngineOptions options, RuleSet rules,
                         CertificateAuthority& ca, FlowAnalyzer& flow, RequestLog& requests)
    : impl_(std::make_unique<Impl>(io, std::move(options), std::move(rules), ca, flow, requests)) {}

ProxyEngine::ProxyEngine(ProxyEngine&&) noexcept = default;
ProxyEngine& ProxyEngine::operator=(ProxyEngine&&) noexcept = default;
ProxyEngine::~ProxyEngine() = default;

void ProxyEngine::start() {
    if (impl_->started.exchange(true)) return;
    const asio::ip::address address = asio::ip::make_address(impl_->options.listen_address);

    const auto open_listener = [&](std::uint16_t port, bool tls) {
        auto acceptor = std::make_unique<asio::ip::tcp::acceptor>(impl_->io);
        const asio::ip::tcp::endpoint endpoint(address, port);
        std::error_code ec;
        acceptor->open(endpoint.protocol(), ec);
        if (ec) throw std::system_error(ec, "open listener on port " + std::to_string(port));
        acceptor->set_option(asio::socket_base::reuse_address(true), ec);
        acceptor->bind(endpoint, ec);
        if (ec) throw std::system_error(ec, "bind listener on port " + std::to_string(port));
        acceptor->listen(asio::socket_base::max_listen_connections, ec);
        if (ec) throw std::system_error(ec, "listen on port " + std::to_string(port));
        impl_->ports.push_back(acceptor->local_endpoint().port());
        asio::ip::tcp::acceptor* handle = acceptor.get();
        impl_->acceptors.push_back(std::move(acceptor));
        asio::co_spawn(impl_->io, impl_->accept_loop(*handle, tls), asio::detached);
        log_info("engine", std::string(tls ? "https" : "http") + " listener on " +
                              impl_->options.listen_address + ":" +
                              std::to_string(impl_->ports.back()));
        return impl_->ports.back();
    };

    const auto open_forward_listener = [&](std::uint16_t port) {
        auto acceptor = std::make_unique<asio::ip::tcp::acceptor>(impl_->io);
        const asio::ip::tcp::endpoint endpoint(address, port);
        std::error_code ec;
        acceptor->open(endpoint.protocol(), ec);
        if (ec) throw std::system_error(ec, "open forward listener on port " + std::to_string(port));
        acceptor->set_option(asio::socket_base::reuse_address(true), ec);
        acceptor->bind(endpoint, ec);
        if (ec) throw std::system_error(ec, "bind forward listener on port " + std::to_string(port));
        acceptor->listen(asio::socket_base::max_listen_connections, ec);
        if (ec) throw std::system_error(ec, "listen on forward port " + std::to_string(port));
        const std::uint16_t actual = acceptor->local_endpoint().port();
        impl_->options.proxy_port = actual;
        impl_->ports.push_back(actual);
        asio::ip::tcp::acceptor* handle = acceptor.get();
        impl_->acceptors.push_back(std::move(acceptor));
        asio::co_spawn(impl_->io, impl_->forward_accept_loop(*handle), asio::detached);
        log_info("engine", "forward proxy listener on " + impl_->options.listen_address + ":" +
                              std::to_string(actual));
    };

    if (impl_->options.enable_http) {
        impl_->options.http_port = open_listener(impl_->options.http_port, false);
    }
    if (impl_->options.enable_https) {
        impl_->options.https_port = open_listener(impl_->options.https_port, true);
    }
    if (impl_->options.enable_forward) open_forward_listener(impl_->options.proxy_port);
}

asio::awaitable<void> ProxyEngine::run() {
    try {
        start();
    } catch (const std::exception& e) {
        log_error("engine", std::string("cannot start: ") + e.what());
        co_return;
    }
    impl_->stop_timer.emplace(co_await asio::this_coro::executor);
    impl_->stop_timer->expires_at(std::chrono::steady_clock::time_point::max());
    std::error_code ec;
    co_await impl_->stop_timer->async_wait(asio::redirect_error(asio::use_awaitable, ec));
}

void ProxyEngine::request_stop() {
    if (impl_->stopping.exchange(true)) return;
    auto* impl = impl_.get();
    asio::post(impl->io, [impl] {
        for (auto& acceptor : impl->acceptors) {
            std::error_code ec;
            acceptor->cancel(ec);
        }
        if (impl->stop_timer) impl->stop_timer->cancel();
    });
}

void ProxyEngine::update_rules(RuleSet rules) {
    auto* impl = impl_.get();
    auto snapshot = std::make_shared<RuleSet>(std::move(rules));
    asio::post(impl->io,
               [impl, snapshot = std::move(snapshot)]() mutable { impl->rules = std::move(snapshot); });
}

bool ProxyEngine::running() const noexcept {
    return impl_->started.load() && !impl_->stopping.load();
}

std::vector<std::uint16_t> ProxyEngine::listening_ports() const { return impl_->ports; }

} // namespace ghacc::accel
