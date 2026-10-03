export module ghacc.accel.net.resolver;

import std;
import asio;
import ghacc.accel.config;

export namespace ghacc::accel {

/// A resolved address with the measured TCP round-trip time to it.
struct RankedAddress {
    asio::ip::address address;
    std::chrono::milliseconds rtt{0};
    bool reachable = false;
};

/// Resolves host names through DNS-over-HTTPS with a system-resolver fallback.
///
/// All methods are blocking and safe to call from a worker thread; results are
/// cached for the configured TTL.
class DnsResolver {
public:
    explicit DnsResolver(DnsConfig config);

    /// All A/AAAA addresses for `host` (DoH first, system resolver on failure).
    [[nodiscard]] std::vector<asio::ip::address> resolve(std::string_view host);

    /// Addresses for `host` with reachability/RTT measured against `port`,
    /// fastest (reachable) first.
    [[nodiscard]] std::vector<RankedAddress> resolve_ranked(std::string_view host,
                                                            std::uint16_t port);

    void clear_cache();

    [[nodiscard]] const DnsConfig& config() const noexcept { return config_; }

private:
    enum class CacheState : std::uint8_t { Fresh, Negative, Expired };

    struct CacheEntry {
        std::vector<asio::ip::address> addresses;
        std::chrono::steady_clock::time_point expires;
        bool negative = false;
    };

    [[nodiscard]] std::vector<asio::ip::address> resolve_uncached(std::string_view host);

    DnsConfig config_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
};

} // namespace ghacc::accel
