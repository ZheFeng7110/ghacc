export module ghacc.accel.engine.detail;

import std;
import asio;
import ghacc.accel.config;
import ghacc.accel.flow;
import ghacc.accel.log;
import ghacc.accel.rule;
import ghacc.accel.engine.types;
import ghacc.accel.net.resolver;
import ghacc.accel.http.message;
import ghacc.accel.http.parser;
import ghacc.accel.http.writer;

export namespace ghacc::accel {

/// Read buffer size used by the streaming relays.
inline constexpr std::size_t kReadChunk = 64 * 1024;
/// Maximum size of an HTTP head accepted before giving up.
inline constexpr std::size_t kMaxHead = 64 * 1024;

// --- request/authority helpers -------------------------------------------

/// Parse a decimal port, returning `fallback` on failure or out-of-range.
[[nodiscard]] std::uint16_t parse_port(std::string_view text, std::uint16_t fallback);

/// Host part of a `Host` header / authority, without port and without brackets.
[[nodiscard]] std::string host_only(std::string_view value);

/// Port from a `host:port` / `[v6]:port` authority, or `fallback`.
[[nodiscard]] std::uint16_t port_from_authority(std::string_view value, std::uint16_t fallback);

/// Reduce an absolute-form request target to origin-form; sets `scheme_https`.
[[nodiscard]] std::string to_origin_form(std::string_view target, bool& scheme_https);

/// Authority (`host[:port]`) of an absolute-form request target.
[[nodiscard]] std::string authority_from_target(std::string_view target);

// --- stream helpers -------------------------------------------------------

template <class Stream>
asio::awaitable<bool> write_all(Stream& stream, std::string_view data) {
    if (data.empty()) co_return true;
    std::error_code ec;
    co_await asio::async_write(stream, asio::buffer(data.data(), data.size()),
                               asio::redirect_error(asio::use_awaitable, ec));
    co_return !ec;
}

/// Read until the CRLFCRLF that terminates a head; returns the head (without the
/// delimiter) and leaves any body bytes already read in `buffer`.
template <class Stream>
asio::awaitable<std::optional<std::string>> read_head(Stream& stream, std::string& buffer) {
    std::array<char, 16 * 1024> chunk{};
    for (;;) {
        const auto end = buffer.find("\r\n\r\n");
        if (end != std::string::npos) {
            std::string head = buffer.substr(0, end);
            buffer.erase(0, end + 4);
            co_return head;
        }
        if (buffer.size() > kMaxHead) co_return std::nullopt;
        std::error_code ec;
        const std::size_t n = co_await stream.async_read_some(
            asio::buffer(chunk), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0) co_return std::nullopt;
        buffer.append(chunk.data(), n);
    }
}

template <class Stream>
asio::awaitable<void> send_error(Stream& stream, int status, std::string_view reason) {
    http::Response response;
    response.status = status;
    response.reason = std::string(reason);
    response.headers.set("Content-Length", "0");
    response.headers.set("Connection", "close");
    co_await write_all(stream, http::serialize_response(response));
}

/// Forward exactly `length` bytes from `from` to `to`; `pending` holds body bytes
/// already read from `from` alongside the request/response head.
template <class From, class To>
asio::awaitable<bool> relay_exact(From& from, To& to, std::string& pending, std::uint64_t length,
                                  FlowAnalyzer& flow) {
    std::array<char, kReadChunk> chunk{};
    while (length > 0) {
        if (!pending.empty()) {
            const auto take =
                static_cast<std::size_t>(std::min<std::uint64_t>(pending.size(), length));
            if (!co_await write_all(to, std::string_view(pending).substr(0, take))) co_return false;
            flow.on_flow(Direction::Write, take);
            pending.erase(0, take);
            length -= take;
            continue;
        }
        std::error_code ec;
        const std::size_t n = co_await from.async_read_some(
            asio::buffer(chunk), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0) co_return false;
        flow.on_flow(Direction::Read, n);
        const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(n, length));
        if (!co_await write_all(to, std::string_view(chunk.data(), take))) co_return false;
        flow.on_flow(Direction::Write, take);
        if (take < n) pending.assign(chunk.data() + take, n - take);
        length -= take;
    }
    co_return true;
}

template <class From, class To>
asio::awaitable<void> relay_until_close(From& from, To& to, std::string& pending,
                                        FlowAnalyzer& flow) {
    if (!pending.empty()) {
        if (!co_await write_all(to, pending)) co_return;
        flow.on_flow(Direction::Write, pending.size());
        pending.clear();
    }
    std::array<char, kReadChunk> chunk{};
    for (;;) {
        std::error_code ec;
        const std::size_t n = co_await from.async_read_some(
            asio::buffer(chunk), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0) co_return;
        flow.on_flow(Direction::Read, n);
        if (!co_await write_all(to, std::string_view(chunk.data(), n))) co_return;
        flow.on_flow(Direction::Write, n);
    }
}

/// Relay a chunked body verbatim, stopping when the terminating chunk is seen.
template <class From, class To>
asio::awaitable<bool> relay_chunked(From& from, To& to, std::string& pending,
                                    FlowAnalyzer& flow) {
    http::ChunkedScanner scanner;
    auto forward = [&](std::string_view data) -> std::optional<std::size_t> {
        const std::size_t consumed = scanner.consume(data);
        if (scanner.failed()) return std::nullopt;
        return consumed;
    };

    if (!pending.empty()) {
        const auto consumed = forward(pending);
        if (!consumed) co_return false;
        if (!co_await write_all(to, std::string_view(pending).substr(0, *consumed))) co_return false;
        flow.on_flow(Direction::Write, *consumed);
        pending.erase(0, *consumed);
        if (scanner.done()) co_return true;
    }

    std::array<char, kReadChunk> chunk{};
    for (;;) {
        std::error_code ec;
        const std::size_t n = co_await from.async_read_some(
            asio::buffer(chunk), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0) co_return false;
        flow.on_flow(Direction::Read, n);
        const auto consumed = forward(std::string_view(chunk.data(), n));
        if (!consumed) co_return false;
        if (!co_await write_all(to, std::string_view(chunk.data(), *consumed))) co_return false;
        flow.on_flow(Direction::Write, *consumed);
        if (*consumed < n) pending.assign(chunk.data() + *consumed, n - *consumed);
        if (scanner.done()) co_return true;
    }
}

// --- upstream connection --------------------------------------------------

/// Try ranked upstream addresses in order with a per-address timeout.
asio::awaitable<std::optional<asio::ip::tcp::socket>> connect_best(
    const std::vector<RankedAddress>& ranked, std::uint16_t port,
    std::chrono::milliseconds timeout, std::string& chosen_ip);

/// Configure SNI, ALPN `http/1.1` and verification for an upstream TLS stream.
/// Implemented in the module's implementation unit (uses OpenSSL directly).
void prepare_upstream_tls(asio::ssl::stream<asio::ip::tcp::socket>& upstream,
                          std::string_view host, bool verify_name);

// --- exchange -------------------------------------------------------------

/// Forward one request/response pair between an established client stream and
/// an established upstream stream, streaming bodies and emitting a record.
template <class ClientStream, class UpstreamStream>
asio::awaitable<void> run_exchange(Pipeline& p, ClientStream& client, UpstreamStream& upstream,
                                   std::string& client_buffer, const http::Request& request,
                                   const http::BodyInfo& req_body, std::string out_head,
                                   ExchangeMeta meta) {
    if (!co_await write_all(upstream, out_head)) co_return;
    p.flow.on_flow(Direction::Write, out_head.size());

    switch (req_body.framing) {
        case http::BodyFraming::ContentLength:
            if (!co_await relay_exact(client, upstream, client_buffer, req_body.length, p.flow)) {
                co_return;
            }
            break;
        case http::BodyFraming::Chunked:
            if (!co_await relay_chunked(client, upstream, client_buffer, p.flow)) co_return;
            break;
        case http::BodyFraming::None:
        case http::BodyFraming::UntilClose:
            break;
    }

    std::string upstream_buffer;
    auto resp_head = co_await read_head(upstream, upstream_buffer);
    if (!resp_head) co_return;
    auto response = http::parse_response_head(*resp_head);
    if (!response) {
        co_await send_error(client, 502, "Bad Gateway");
        co_return;
    }

    response->headers.remove("Connection");
    response->headers.remove("Keep-Alive");
    response->headers.remove("Proxy-Connection");
    response->headers.set("Connection", "close");
    const std::string resp_out = http::serialize_response(*response);
    if (!co_await write_all(client, resp_out)) co_return;
    p.flow.on_flow(Direction::Write, resp_out.size());

    if (auto resp_body = http::response_body_info(request, *response)) {
        switch (resp_body->framing) {
            case http::BodyFraming::ContentLength:
                co_await relay_exact(upstream, client, upstream_buffer, resp_body->length, p.flow);
                break;
            case http::BodyFraming::Chunked:
                co_await relay_chunked(upstream, client, upstream_buffer, p.flow);
                break;
            case http::BodyFraming::UntilClose:
                co_await relay_until_close(upstream, client, upstream_buffer, p.flow);
                break;
            case http::BodyFraming::None:
                break;
        }
    }

    RequestRecord record;
    record.time = std::chrono::system_clock::now();
    record.method = request.method;
    record.host = meta.host;
    record.path = request.target;
    record.status = response->status;
    record.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - meta.started);
    record.upstream = meta.upstream_ip;
    record.accelerated = meta.accelerated;
    p.requests.add(std::move(record));

    log_info("engine", request.method + " " + meta.host + request.target + " -> " +
                          std::to_string(response->status));
}

/// Resolve, connect, optionally TLS-handshake and run one exchange.
///
/// Shared by the reverse proxy and the forward proxy. `rule` may be null for a
/// plain (non-accelerated) forward-proxy request.
template <class ClientStream>
asio::awaitable<void> proxy_request(Pipeline& p, ClientStream& client, std::string& client_buffer,
                                    const http::Request& request, std::string host,
                                    std::string authority, std::optional<DomainRule> rule,
                                    std::string upstream_host, std::uint16_t upstream_port,
                                    bool upstream_tls,
                                    std::chrono::steady_clock::time_point started) {
    auto body = http::request_body_info(request);
    if (!body) {
        co_await send_error(client, 400, "Bad Request");
        co_return;
    }

    std::vector<RankedAddress> ranked;
    if (rule && rule->ip) {
        std::error_code ec;
        auto address = asio::ip::make_address(*rule->ip, ec);
        if (ec) {
            co_await send_error(client, 502, "Bad Gateway");
            co_return;
        }
        RankedAddress entry;
        entry.address = address;
        entry.reachable = true;
        ranked.push_back(entry);
    } else {
        ranked = p.resolver.resolve_ranked(upstream_host, upstream_port);
    }
    if (ranked.empty()) {
        log_warn("engine", "no upstream address for " + upstream_host);
        co_await send_error(client, 502, "Bad Gateway");
        co_return;
    }

    const auto timeout = rule ? rule->timeout : std::chrono::milliseconds{10000};
    std::string upstream_ip;
    auto socket = co_await connect_best(ranked, upstream_port, timeout, upstream_ip);
    if (!socket) {
        log_warn("engine", "cannot connect upstream " + upstream_host);
        co_await send_error(client, 502, "Bad Gateway");
        co_return;
    }

    http::Request outgoing = request;
    outgoing.headers.set("Connection", "close");
    outgoing.headers.remove("Proxy-Connection");
    outgoing.headers.remove("Keep-Alive");
    if (!outgoing.headers.contains("Host")) outgoing.headers.set("Host", authority);
    if (rule && rule->user_agent) outgoing.headers.set("User-Agent", *rule->user_agent);
    outgoing.version = "HTTP/1.1";
    const std::string out_head = http::serialize_request(outgoing);

    ExchangeMeta meta;
    meta.host = std::move(host);
    meta.upstream_ip = upstream_ip;
    meta.accelerated = rule.has_value();
    meta.started = started;

    try {
        if (upstream_tls) {
            asio::ssl::stream<asio::ip::tcp::socket> upstream(std::move(*socket), p.upstream_tls);
            const bool verify =
                p.options.upstream_tls_verify && !(rule && rule->tls_ignore_name_mismatch);
            prepare_upstream_tls(upstream, upstream_host, verify);

            std::error_code ec;
            co_await upstream.async_handshake(asio::ssl::stream_base::client,
                                              asio::redirect_error(asio::use_awaitable, ec));
            if (ec) {
                log_warn("engine",
                         "upstream TLS handshake failed for " + upstream_host + ": " + ec.message());
                co_await send_error(client, 502, "Bad Gateway");
                co_return;
            }
            co_await run_exchange(p, client, upstream, client_buffer, request, *body,
                                  std::move(out_head), meta);
            std::error_code shutdown_ec;
            co_await upstream.async_shutdown(asio::redirect_error(asio::use_awaitable, shutdown_ec));
        } else {
            asio::ip::tcp::socket upstream = std::move(*socket);
            co_await run_exchange(p, client, upstream, client_buffer, request, *body,
                                  std::move(out_head), meta);
        }
    } catch (const std::exception& e) {
        log_debug("engine", std::string("connection error: ") + e.what());
    }
}

/// Bidirectional TCP tunnel between `client` and `upstream` until either side
/// closes or the idle timeout elapses.
asio::awaitable<void> run_tunnel(asio::ip::tcp::socket client, asio::ip::tcp::socket upstream,
                                 FlowAnalyzer& flow, std::chrono::seconds idle_timeout);

} // namespace ghacc::accel
