module;
#include <openssl/ssl.h>

module ghacc.accel.net.resolver;

import std;
import asio;
import ghacc.accel.config;
import ghacc.accel.net.dns;

namespace ghacc::accel {

namespace {

using namespace std::chrono_literals;

struct DohEndpoint {
    std::string host;
    std::uint16_t port = 443;
    std::string path = "/dns-query";
};

std::optional<DohEndpoint> parse_endpoint(std::string_view url) {
    constexpr std::string_view https = "https://";
    if (!url.starts_with(https)) return std::nullopt;
    url.remove_prefix(https.size());

    DohEndpoint endpoint;
    auto slash = url.find('/');
    std::string_view authority = url.substr(0, slash);
    endpoint.path = slash == std::string_view::npos ? "/dns-query" : std::string(url.substr(slash));

    auto colon = authority.rfind(':');
    if (colon != std::string_view::npos) {
        endpoint.host = std::string(authority.substr(0, colon));
        try {
            endpoint.port = static_cast<std::uint16_t>(std::stoi(std::string(authority.substr(colon + 1))));
        } catch (...) {
            return std::nullopt;
        }
    } else {
        endpoint.host = std::string(authority);
    }
    if (endpoint.host.empty()) return std::nullopt;
    return endpoint;
}

void load_system_ca(asio::ssl::context& context) {
    std::error_code ec;
#if defined(__APPLE__)
    const char* candidates[] = {"/etc/ssl/cert.pem"};
#elif defined(_WIN32)
    const char* candidates[] = {nullptr};
#else
    const char* candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
    };
#endif
    for (const char* candidate : candidates) {
        if (candidate == nullptr) break;
        if (!std::filesystem::exists(candidate, ec)) continue;
        context.load_verify_file(candidate, ec);
        if (!ec) return;
    }
    context.set_default_verify_paths(ec);
}

std::optional<asio::ip::address> to_address(const dns::Answer& answer) {
    if (!answer.address) return std::nullopt;
    const auto& raw = *answer.address;
    if (answer.address_length == 4) {
        asio::ip::address_v4::bytes_type bytes{};
        std::copy_n(raw.begin(), 4, bytes.begin());
        return asio::ip::make_address_v4(bytes);
    }
    if (answer.address_length == 16) {
        asio::ip::address_v6::bytes_type bytes{};
        std::copy_n(raw.begin(), 16, bytes.begin());
        return asio::ip::make_address_v6(bytes);
    }
    return std::nullopt;
}

std::string lower_copy(std::string_view text);

/// POST a DNS wire query to a DoH endpoint and return the response body.
std::optional<std::vector<std::byte>> doh_request(const DohEndpoint& endpoint,
                                                  std::span<const std::byte> query,
                                                  std::chrono::milliseconds timeout) {
    asio::io_context io;
    std::error_code ec;

    asio::ip::tcp::resolver resolver(io);
    auto results = resolver.resolve(endpoint.host, std::to_string(endpoint.port), ec);
    if (ec || results.empty()) return std::nullopt;

    asio::ssl::context ssl_context(asio::ssl::context::tls_client);
    load_system_ca(ssl_context);

    asio::ssl::stream<asio::ip::tcp::socket> stream(io, ssl_context);
    if (!SSL_set_tlsext_host_name(stream.native_handle(), endpoint.host.c_str())) {
        return std::nullopt;
    }
    stream.set_verify_callback(asio::ssl::host_name_verification(endpoint.host));

    // Bounded connect + handshake via an async timer that closes the socket.
    bool timed_out = false;
    asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const std::error_code& e) {
        if (!e) {
            timed_out = true;
            stream.next_layer().close(ec);
        }
    });

    asio::connect(stream.next_layer(), results, ec);
    if (ec || timed_out) return std::nullopt;
    stream.handshake(asio::ssl::stream_base::client, ec);
    if (ec || timed_out) return std::nullopt;

    std::string request = "POST " + endpoint.path + " HTTP/1.1\r\n";
    request += "Host: " + endpoint.host + "\r\n";
    request += "Accept: application/dns-message\r\n";
    request += "Content-Type: application/dns-message\r\n";
    request += "Content-Length: " + std::to_string(query.size()) + "\r\n";
    request += "Connection: close\r\n\r\n";

    asio::write(stream, asio::buffer(request), ec);
    if (ec) return std::nullopt;
    asio::write(stream, asio::buffer(query.data(), query.size()), ec);
    if (ec) return std::nullopt;

    // Read until the end of the header block (asio's `streambuf`/`read_until`
    // are not part of the exported asio module surface).
    std::string raw;
    std::array<char, 8192> chunk{};
    std::size_t header_end = std::string::npos;
    while (header_end == std::string::npos) {
        const std::size_t n = stream.read_some(asio::buffer(chunk), ec);
        if (n > 0) raw.append(chunk.data(), n);
        header_end = raw.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
        if ((ec && n == 0) || raw.size() > (1u << 20)) return std::nullopt;
    }

    const auto line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return std::nullopt;
    if (raw.substr(0, line_end).find(" 200 ") == std::string::npos) return std::nullopt;

    std::size_t content_length = 0;
    for (std::size_t pos = line_end + 2; pos < header_end;) {
        const auto end = raw.find("\r\n", pos);
        if (end == std::string::npos || end > header_end) break;
        const std::string header = raw.substr(pos, end - pos);
        if (lower_copy(header).starts_with("content-length:")) {
            try {
                content_length = std::stoul(header.substr(header.find(':') + 1));
            } catch (...) {
                content_length = 0;
            }
        }
        pos = end + 2;
    }

    std::string body = raw.substr(header_end + 4);
    if (body.size() < content_length) {
        std::string tail(content_length - body.size(), '\0');
        std::size_t got = 0;
        while (got < tail.size()) {
            const std::size_t n = stream.read_some(asio::buffer(tail.data() + got, tail.size() - got), ec);
            if (n == 0) break;
            got += n;
        }
        tail.resize(got);
        body += tail;
    } else if (content_length > 0) {
        body.resize(content_length);
    }
    if (body.empty()) return std::nullopt;

    std::vector<std::byte> out(body.size());
    std::memcpy(out.data(), body.data(), body.size());
    return out;
}

std::optional<std::chrono::milliseconds> connect_rtt(const asio::ip::address& address,
                                                     std::uint16_t port,
                                                     std::chrono::milliseconds timeout) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    const auto endpoint = asio::ip::tcp::endpoint(address, port);

    std::error_code ec;
    bool completed = false;
    const auto start = std::chrono::steady_clock::now();
    socket.async_connect(endpoint, [&](const std::error_code& e) {
        ec = e;
        completed = true;
    });
    io.run_for(timeout);
    if (!completed) {
        socket.close(ec);
        return std::nullopt;
    }
    if (ec) return std::nullopt;
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
}

std::string lower_copy(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // namespace

DnsResolver::DnsResolver(DnsConfig config) : config_(std::move(config)) {}

std::vector<asio::ip::address> DnsResolver::resolve_uncached(std::string_view host) {
    std::vector<asio::ip::address> addresses;

    // A literal address needs no DNS (and DoH cannot resolve an IP anyway).
    if (std::error_code literal_ec; true) {
        auto literal = asio::ip::make_address(std::string(host), literal_ec);
        if (!literal_ec) return {literal};
    }

    for (const auto& url : config_.doh) {
        auto endpoint = parse_endpoint(url);
        if (!endpoint) continue;

        const auto collect = [&](dns::RecordType type) {
            auto query = dns::encode_query(host, type);
            auto response = doh_request(*endpoint, query, 5s);
            if (!response) return;
            auto parsed = dns::parse_message(*response);
            if (!parsed || parsed->rcode != dns::Rcode::NoError) return;
            for (const auto& answer : parsed->answers) {
                if (auto address = to_address(answer)) addresses.push_back(*address);
            }
        };

        if (config_.prefer_ipv6) collect(dns::RecordType::AAAA);
        collect(dns::RecordType::A);
        if (!addresses.empty()) break;
    }

    if (addresses.empty()) {
        // Fallback: system resolver.
        asio::io_context io;
        std::error_code ec;
        asio::ip::tcp::resolver resolver(io);
        auto results = resolver.resolve(std::string(host), "443", ec);
        if (!ec) {
            for (const auto& entry : results) addresses.push_back(entry.endpoint().address());
        }
    }

    std::ranges::sort(addresses, {}, [](const asio::ip::address& a) { return a.to_string(); });
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
    return addresses;
}

std::vector<asio::ip::address> DnsResolver::resolve(std::string_view host) {
    const std::string key = lower_copy(host);
    {
        std::lock_guard lock(mutex_);
        if (auto it = cache_.find(key); it != cache_.end()) {
            if (std::chrono::steady_clock::now() < it->second.expires) {
                return it->second.addresses;
            }
        }
    }

    auto addresses = resolve_uncached(host);

    {
        std::lock_guard lock(mutex_);
        CacheEntry entry;
        entry.addresses = addresses;
        entry.negative = addresses.empty();
        const auto ttl = entry.negative ? std::chrono::seconds{30}
                                        : std::chrono::seconds{config_.cache_ttl_seconds};
        entry.expires = std::chrono::steady_clock::now() + ttl;
        cache_[key] = std::move(entry);
    }
    return addresses;
}

std::vector<RankedAddress> DnsResolver::resolve_ranked(std::string_view host, std::uint16_t port) {
    std::vector<RankedAddress> ranked;
    for (const auto& address : resolve(host)) {
        RankedAddress entry;
        entry.address = address;
        if (auto rtt = connect_rtt(address, port, 3s)) {
            entry.reachable = true;
            entry.rtt = *rtt;
        } else {
            entry.rtt = 3000ms;
        }
        ranked.push_back(entry);
    }

    std::ranges::sort(ranked, [](const RankedAddress& a, const RankedAddress& b) {
        if (a.reachable != b.reachable) return a.reachable > b.reachable;
        if (a.rtt != b.rtt) return a.rtt < b.rtt;
        return a.address.to_string() < b.address.to_string();
    });
    return ranked;
}

void DnsResolver::clear_cache() {
    std::lock_guard lock(mutex_);
    cache_.clear();
}

} // namespace ghacc::accel
