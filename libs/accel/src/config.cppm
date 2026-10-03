export module ghacc.accel.config;

import std;
import ghacc.accel.log;
import ghacc.accel.rule;

export namespace ghacc::accel {

/// How traffic is captured and steered into the engine.
enum class ProxyMode : std::uint8_t {
    /// Rewrite the hosts file and run a local 80/443 MITM reverse proxy.
    Hosts,
    /// Configure the operating system HTTP/HTTPS proxy.
    System,
    /// Serve a PAC file and point the system at it.
    Pac,
    /// Run only the forward proxy; the user configures clients manually.
    ForwardOnly,
};

[[nodiscard]] std::string_view to_string(ProxyMode mode) noexcept;
[[nodiscard]] std::optional<ProxyMode> proxy_mode_from(std::string_view text) noexcept;

struct ListenConfig {
    std::string address = "127.0.0.1";
    std::uint16_t proxy_port = 26501;  // forward proxy (System / PAC / ForwardOnly)
    std::uint16_t http_port = 80;      // reverse proxy (Hosts)
    std::uint16_t https_port = 443;    // MITM reverse proxy (Hosts)
    std::string pac_path = "/pac";     // PAC path served by the forward proxy
};

struct DnsConfig {
    std::vector<std::string> doh = {
        "https://doh.pub/dns-query",
        "https://1.1.1.1/dns-query",
    };
    bool prefer_ipv6 = false;
    std::uint32_t cache_ttl_seconds = 600;
};

/// A user-defined acceleration target described purely by configuration.
struct CustomProviderConfig {
    std::string id;
    std::string name;
    std::vector<DomainRule> rules;
};

struct Config {
    ProxyMode mode = ProxyMode::Hosts;
    LogLevel log_level = LogLevel::Info;
    ListenConfig listen;
    DnsConfig dns;
    std::vector<std::string> enabled_providers = {"github", "steam"};
    std::vector<CustomProviderConfig> custom_providers;
};

[[nodiscard]] Config default_config();

/// Parse configuration from TOML text. Missing keys keep their defaults.
[[nodiscard]] std::expected<Config, std::string> parse_config(std::string_view toml_text);

/// Serialize configuration to TOML text.
[[nodiscard]] std::string to_toml(const Config& config);

[[nodiscard]] std::expected<Config, std::string> load_config(const std::filesystem::path& path);

/// Write configuration atomically (write to a temporary then rename).
[[nodiscard]] std::expected<void, std::string> save_config(const std::filesystem::path& path,
                                                           const Config& config);

/// Platform default path: `<config_dir>/ghacc/config.toml`.
[[nodiscard]] std::filesystem::path default_config_path();

/// Platform data directory (leaf certificate cache, ...).
[[nodiscard]] std::filesystem::path default_data_dir();

/// Platform state directory (PID file, hosts backup, ...).
[[nodiscard]] std::filesystem::path default_state_dir();

/// Platform log directory.
[[nodiscard]] std::filesystem::path default_log_dir();

/// Default CA directory: the config directory with a `ca/` child.
[[nodiscard]] std::filesystem::path default_ca_dir();

/// Default daemon PID file: `<state_dir>/ghacc.pid`.
[[nodiscard]] std::filesystem::path default_pid_path();

/// Default log file: `<log_dir>/ghacc.log`.
[[nodiscard]] std::filesystem::path default_log_path();

/// Default leaf-certificate cache: `<data_dir>/certs`.
[[nodiscard]] std::filesystem::path default_cert_cache_dir();

} // namespace ghacc::accel
