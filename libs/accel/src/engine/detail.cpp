module;

#include <openssl/ssl.h>

module ghacc.accel.engine.detail;

import std;
import asio;
import ghacc.accel.flow;
import ghacc.accel.log;

namespace ghacc::accel {

namespace {

/// Idle-aware bidirectional TCP tunnel state.
///
/// All access happens on the single engine executor, so no locking is needed.
struct TunnelState {
    explicit TunnelState(asio::any_io_executor executor, std::chrono::seconds timeout)
        : timer(std::move(executor)), timeout(timeout) {}

    asio::steady_timer timer;
    std::chrono::seconds timeout;
    asio::ip::tcp::socket* sockets[2]{nullptr, nullptr};
    bool closed = false;
    int finished = 0;

    void close_all() {
        if (closed) return;
        closed = true;
        std::error_code ec;
        for (auto* socket : sockets) {
            if (socket != nullptr) socket->close(ec);
        }
        timer.cancel();
    }

    /// Half-close `to`'s send side so its peer observes EOF, then tear the
    /// tunnel down once both directions have drained.
    ///
    /// The sockets are *not* closed as soon as one direction ends: closing a
    /// socket while the opposite direction still has a read pending makes
    /// Windows abort the connection (RST) instead of sending a FIN, which the
    /// peer sees as `ConnectionResetError` / `ECONNRESET`.
    void finish_direction(asio::ip::tcp::socket& to) {
        if (closed) return;
        std::error_code ec;
        to.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        if (++finished >= 2) close_all();
    }

    /// Cancel the pending idle wait so the supervisor re-arms a fresh timeout.
    void touch() {
        if (closed) return;
        timer.expires_after(timeout);
    }
};

asio::awaitable<void> relay_direction(asio::ip::tcp::socket& from, asio::ip::tcp::socket& to,
                                      FlowAnalyzer& flow, std::shared_ptr<TunnelState> state) {
    std::array<char, kReadChunk> chunk{};
    std::error_code read_ec;
    for (;;) {
        std::error_code ec;
        const std::size_t n = co_await from.async_read_some(
            asio::buffer(chunk), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0) {
            read_ec = ec;
            break;
        }
        flow.on_flow(Direction::Read, n);
        state->touch();
        co_await asio::async_write(to, asio::buffer(chunk.data(), n),
                                   asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            read_ec = ec;
            break;
        }
        flow.on_flow(Direction::Write, n);
    }
    // A clean EOF (the peer half-closed) lets the other direction keep
    // draining; any real error tears the whole tunnel down immediately.
    if (!read_ec || read_ec == asio::error::eof) {
        state->finish_direction(to);
    } else {
        state->close_all();
    }
}

} // namespace

std::uint16_t parse_port(std::string_view text, std::uint16_t fallback) {
    std::uint32_t value = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size() || value == 0 || value > 65535) {
        return fallback;
    }
    return static_cast<std::uint16_t>(value);
}

std::string host_only(std::string_view value) {
    if (!value.empty() && value.front() == '[') {
        const auto end = value.find(']');
        if (end != std::string_view::npos) return std::string(value.substr(1, end - 1));
    }
    const auto first = value.find(':');
    if (first != std::string_view::npos && value.find(':', first + 1) == std::string_view::npos) {
        value = value.substr(0, first);
    }
    return std::string(value);
}

std::uint16_t port_from_authority(std::string_view value, std::uint16_t fallback) {
    if (value.empty()) return fallback;
    if (value.front() == '[') {
        const auto end = value.find(']');
        if (end != std::string_view::npos && end + 1 < value.size() && value[end + 1] == ':') {
            return parse_port(value.substr(end + 2), fallback);
        }
        return fallback;
    }
    const auto colon = value.rfind(':');
    if (colon != std::string_view::npos && value.find(':') == colon) {
        return parse_port(value.substr(colon + 1), fallback);
    }
    return fallback;
}

std::string to_origin_form(std::string_view target, bool& scheme_https) {
    const auto scheme = target.find("://");
    if (scheme == std::string_view::npos) return std::string(target);
    scheme_https = http::iequals(target.substr(0, scheme), "https");
    const auto path = target.find('/', scheme + 3);
    return path == std::string_view::npos ? std::string("/") : std::string(target.substr(path));
}

std::string authority_from_target(std::string_view target) {
    const auto scheme = target.find("://");
    if (scheme == std::string_view::npos) return {};
    std::string_view rest = target.substr(scheme + 3);
    const auto end = rest.find_first_of("/?#");
    if (end != std::string_view::npos) rest = rest.substr(0, end);
    return std::string(rest);
}

asio::awaitable<std::optional<asio::ip::tcp::socket>> connect_best(
    const std::vector<RankedAddress>& ranked, std::uint16_t port,
    std::chrono::milliseconds timeout, std::string& chosen_ip) {
    const auto executor = co_await asio::this_coro::executor;
    for (const auto& entry : ranked) {
        asio::ip::tcp::socket socket(executor);
        asio::steady_timer timer(executor);
        bool timed_out = false;
        timer.expires_after(timeout);
        timer.async_wait([&](const std::error_code& ec) {
            if (!ec) {
                timed_out = true;
                std::error_code ignored;
                socket.close(ignored);
            }
        });

        std::error_code ec;
        co_await socket.async_connect(asio::ip::tcp::endpoint(entry.address, port),
                                      asio::redirect_error(asio::use_awaitable, ec));
        timer.cancel();
        if (!timed_out && !ec) {
            chosen_ip = entry.address.to_string();
            co_return socket;
        }
    }
    co_return std::nullopt;
}

void prepare_upstream_tls(asio::ssl::stream<asio::ip::tcp::socket>& upstream,
                          std::string_view host, bool verify_name) {
    SSL* handle = upstream.native_handle();
    const std::string host_str(host);
    SSL_set_tlsext_host_name(handle, host_str.c_str());
    static constexpr unsigned char alpn_http11[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    SSL_set_alpn_protos(handle, alpn_http11, sizeof(alpn_http11));
    if (verify_name) {
        upstream.set_verify_callback(asio::ssl::host_name_verification(host_str));
    } else {
        SSL_set_verify(handle, SSL_VERIFY_NONE, nullptr);
    }
}

asio::awaitable<void> run_tunnel(asio::ip::tcp::socket client, asio::ip::tcp::socket upstream,
                                 FlowAnalyzer& flow, std::chrono::seconds idle_timeout) {
    const auto executor = co_await asio::this_coro::executor;
    auto state = std::make_shared<TunnelState>(executor, idle_timeout);
    state->sockets[0] = &client;
    state->sockets[1] = &upstream;

    asio::co_spawn(executor, relay_direction(client, upstream, flow, state), asio::detached);
    asio::co_spawn(executor, relay_direction(upstream, client, flow, state), asio::detached);

    for (;;) {
        state->timer.expires_after(state->timeout);
        std::error_code ec;
        co_await state->timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        if (state->closed) co_return;
        if (!ec) {
            log_debug("engine", "tunnel idle timeout");
            state->close_all();
            co_return;
        }
    }
}

} // namespace ghacc::accel
