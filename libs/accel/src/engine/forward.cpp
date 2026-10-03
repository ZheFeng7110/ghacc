module;

#include <openssl/ssl.h>

module ghacc.accel.engine.forward;

import std;
import asio;
import ghacc.accel.config;
import ghacc.accel.flow;
import ghacc.accel.log;
import ghacc.accel.rule;
import ghacc.accel.engine.types;
import ghacc.accel.engine.detail;
import ghacc.accel.engine.pac;
import ghacc.accel.net.resolver;
import ghacc.accel.net.tls;
import ghacc.accel.http.message;
import ghacc.accel.http.parser;
import ghacc.accel.http.writer;

namespace ghacc::accel {

namespace {

using http::Request;
using tcp = asio::ip::tcp;

std::string lower_copy(std::string_view text) { return http::lower_ascii(text); }

PacOptions pac_options(const Pipeline& p) {
    PacOptions options;
    options.proxy_host = p.options.listen_address;
    options.proxy_port = p.options.proxy_port;
    options.pac_path = p.options.pac_path;
    return options;
}

asio::awaitable<void> serve_pac(tcp::socket& socket, Pipeline& p) {
    const std::string body = generate_pac(p.rules, pac_options(p));
    http::Response response;
    response.status = 200;
    response.reason = "OK";
    response.headers.set("Content-Type", "application/x-ns-proxy-autoconfig");
    response.headers.set("Content-Length", std::to_string(body.size()));
    response.headers.set("Connection", "close");
    const std::string head = http::serialize_response(response);
    co_await write_all(socket, head);
    p.flow.on_flow(Direction::Write, head.size());
    co_await write_all(socket, body);
    p.flow.on_flow(Direction::Write, body.size());
}

/// Resolve and connect to `host:port`, honouring a fixed-IP rule.
asio::awaitable<std::optional<tcp::socket>> connect_upstream(Pipeline& p,
                                                             const std::optional<DomainRule>& rule,
                                                             std::string_view host,
                                                             std::uint16_t port,
                                                             std::string& chosen_ip) {
    std::vector<RankedAddress> ranked;
    if (rule && rule->ip) {
        std::error_code ec;
        auto address = asio::ip::make_address(*rule->ip, ec);
        if (ec) co_return std::nullopt;
        RankedAddress entry;
        entry.address = address;
        entry.reachable = true;
        ranked.push_back(entry);
    } else {
        ranked = p.resolver.resolve_ranked(host, port);
    }
    if (ranked.empty()) co_return std::nullopt;
    const auto timeout = rule ? rule->timeout : std::chrono::milliseconds{10000};
    co_return co_await connect_best(ranked, port, timeout, chosen_ip);
}

/// `CONNECT host:port`: plain tunnel or TLS interception.
asio::awaitable<void> handle_connect(Pipeline& p, tcp::socket socket, std::string buffer,
                                     const Request& request, TlsServerContext& tls_context) {
    const std::string authority = request.target;
    const std::string host = lower_copy(host_only(authority));
    const std::uint16_t port = port_from_authority(authority, 443);
    if (host.empty()) {
        co_await send_error(socket, 400, "Bad Request");
        co_return;
    }

    auto rule = p.rules.match(host);
    if (rule && rule->action == RuleAction::Block) {
        log_info("forward", "blocked CONNECT " + authority);
        co_await send_error(socket, 403, "Forbidden");
        co_return;
    }

    const bool mitm = rule && rule->action == RuleAction::ReverseProxy && rule->tls_sni;

    if (!mitm) {
        std::string upstream_ip;
        auto upstream = co_await connect_upstream(p, rule, host, port, upstream_ip);
        if (!upstream) {
            log_warn("forward", "cannot connect tunnel upstream " + authority);
            co_await send_error(socket, 502, "Bad Gateway");
            co_return;
        }
        static constexpr std::string_view established =
            "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (!co_await write_all(socket, established)) co_return;
        p.flow.on_flow(Direction::Write, established.size());
        log_info("forward", "CONNECT tunnel " + authority + " -> " + upstream_ip);
        co_await run_tunnel(std::move(socket), std::move(*upstream), p.flow,
                            p.options.tunnel_idle_timeout);
        co_return;
    }

    static constexpr std::string_view established =
        "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (!co_await write_all(socket, established)) co_return;
    p.flow.on_flow(Direction::Write, established.size());

    asio::ssl::stream<tcp::socket> client_tls(std::move(socket), tls_context.context());
    std::error_code ec;
    co_await client_tls.async_handshake(asio::ssl::stream_base::server,
                                        asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        log_debug("forward", "client TLS handshake failed for " + authority + ": " + ec.message());
        co_return;
    }
    const char* sni_raw =
        SSL_get_servername(client_tls.native_handle(), TLSEXT_NAMETYPE_host_name);
    const std::string sni = sni_raw != nullptr ? lower_copy(sni_raw) : host;

    std::string client_buffer;
    auto head = co_await read_head(client_tls, client_buffer);
    if (!head) co_return;
    auto parsed = http::parse_request_head(*head);
    if (!parsed) {
        co_await send_error(client_tls, 400, "Bad Request");
        co_return;
    }
    Request decrypted = std::move(*parsed);
    bool ignored_https = false;
    decrypted.target = to_origin_form(decrypted.target, ignored_https);
    if (decrypted.target.empty() || decrypted.target.front() != '/') decrypted.target = "/";

    const auto host_header = decrypted.headers.get("host");
    const std::string request_authority =
        host_header ? std::string(*host_header) : (sni.empty() ? host : sni);
    const std::string upstream_host =
        !rule->forward_destination.empty() ? rule->forward_destination : host;

    log_info("forward", "CONNECT MITM " + authority + " (sni " + sni + ")");
    co_await proxy_request(p, client_tls, client_buffer, decrypted, host, request_authority, rule,
                           upstream_host, port, true, std::chrono::steady_clock::now());
    std::error_code shutdown_ec;
    co_await client_tls.async_shutdown(asio::redirect_error(asio::use_awaitable, shutdown_ec));
}

/// Absolute-URI plain HTTP forwarded through the proxy (and PAC serving).
asio::awaitable<void> handle_http(Pipeline& p, tcp::socket socket, std::string buffer,
                                  Request request) {
    const std::string_view target = request.target;

    if (target.starts_with("/")) {
        if (p.options.enable_pac && is_pac_request(target, pac_options(p))) {
            co_await serve_pac(socket, p);
            co_return;
        }
        co_await send_error(socket, 400, "Bad Request");
        co_return;
    }

    const std::string authority = authority_from_target(target);
    if (authority.empty()) {
        co_await send_error(socket, 400, "Bad Request");
        co_return;
    }
    const std::string host = lower_copy(host_only(authority));
    if (host.empty()) {
        co_await send_error(socket, 400, "Bad Request");
        co_return;
    }

    if (p.options.enable_pac && is_pac_request(target, pac_options(p)) &&
        (host == "127.0.0.1" || host == "localhost" || host == "::1")) {
        co_await serve_pac(socket, p);
        co_return;
    }

    bool target_https = false;
    request.target = to_origin_form(target, target_https);
    request.headers.set("Host", authority);

    auto rule = p.rules.match(host);
    if (rule && rule->action == RuleAction::Block) {
        log_info("forward", "blocked " + host);
        co_await send_error(socket, 403, "Forbidden");
        co_return;
    }

    const std::uint16_t port = port_from_authority(authority, target_https ? 443 : 80);
    const std::string upstream_host =
        (rule && !rule->forward_destination.empty()) ? rule->forward_destination : host;
    co_await proxy_request(p, socket, buffer, request, host, authority, rule, upstream_host, port,
                           target_https, std::chrono::steady_clock::now());
}

/// TLS ClientHello sent straight to the proxy port: intercept only if SNI matches.
asio::awaitable<void> handle_direct_tls(Pipeline& p, tcp::socket socket,
                                        TlsServerContext& tls_context) {
    asio::ssl::stream<tcp::socket> client_tls(std::move(socket), tls_context.context());
    std::error_code ec;
    co_await client_tls.async_handshake(asio::ssl::stream_base::server,
                                        asio::redirect_error(asio::use_awaitable, ec));
    if (ec) co_return;

    const char* sni_raw =
        SSL_get_servername(client_tls.native_handle(), TLSEXT_NAMETYPE_host_name);
    const std::string sni = sni_raw != nullptr ? lower_copy(sni_raw) : "";
    if (sni.empty()) co_return;

    auto rule = p.rules.match(sni);
    if (!rule || rule->action != RuleAction::ReverseProxy || !rule->tls_sni) {
        log_debug("forward", "unmatched direct TLS SNI " + sni);
        co_return;
    }

    std::string buffer;
    auto head = co_await read_head(client_tls, buffer);
    if (!head) co_return;
    auto parsed = http::parse_request_head(*head);
    if (!parsed) {
        co_await send_error(client_tls, 400, "Bad Request");
        co_return;
    }
    Request request = std::move(*parsed);
    bool ignored_https = false;
    request.target = to_origin_form(request.target, ignored_https);
    if (request.target.empty() || request.target.front() != '/') request.target = "/";

    const auto host_header = request.headers.get("host");
    const std::string authority =
        host_header ? std::string(*host_header) : (sni + ":" + std::to_string(p.options.upstream_https_port));
    const std::string host = lower_copy(host_only(authority));
    if (host.empty()) {
        co_await send_error(client_tls, 400, "Bad Request");
        co_return;
    }
    const std::uint16_t port =
        port_from_authority(authority, p.options.upstream_https_port);
    const std::string upstream_host =
        !rule->forward_destination.empty() ? rule->forward_destination : host;

    co_await proxy_request(p, client_tls, buffer, request, host, authority, rule, upstream_host,
                           port, true, std::chrono::steady_clock::now());
    std::error_code shutdown_ec;
    co_await client_tls.async_shutdown(asio::redirect_error(asio::use_awaitable, shutdown_ec));
}

} // namespace

asio::awaitable<void> ForwardProxy::serve(tcp::socket socket, Pipeline& pipeline) {
    // Peek without consuming so a TLS ClientHello reaches the handshake intact.
    std::array<unsigned char, 2> peek{};
    std::error_code ec;
    const std::size_t n = co_await socket.async_receive(
        asio::buffer(peek), asio::socket_base::message_peek,
        asio::redirect_error(asio::use_awaitable, ec));
    if (ec || n == 0) co_return;

    const bool is_tls = n >= 2 && peek[0] == 0x16 && peek[1] == 0x03;
    if (is_tls) {
        co_await handle_direct_tls(pipeline, std::move(socket), *tls_);
        co_return;
    }

    std::string buffer;
    auto head = co_await read_head(socket, buffer);
    if (!head) co_return;
    auto parsed = http::parse_request_head(*head);
    if (!parsed) {
        co_await send_error(socket, 400, "Bad Request");
        co_return;
    }
    Request request = std::move(*parsed);

    if (request.method == "CONNECT") {
        co_await handle_connect(pipeline, std::move(socket), std::move(buffer), request, *tls_);
        co_return;
    }
    co_await handle_http(pipeline, std::move(socket), std::move(buffer), std::move(request));
}

} // namespace ghacc::accel
