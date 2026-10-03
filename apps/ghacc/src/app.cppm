export module ghacc.app;

import std;
import ghacc.accel;

export namespace ghacc::app {

using namespace ghacc::accel;

/// User-supplied overrides for the platform defaults.
struct RuntimeOptions {
    std::optional<std::filesystem::path> config_path;
    std::optional<std::filesystem::path> ca_dir;
    std::optional<std::filesystem::path> hosts_path;
    std::optional<std::filesystem::path> hosts_backup;
};

/// Every path the application reads or writes.
struct RuntimePaths {
    std::filesystem::path config;
    std::filesystem::path ca;
    std::filesystem::path hosts;
    std::filesystem::path hosts_backup;
    std::filesystem::path pid;
    std::filesystem::path log;
    std::filesystem::path data;
    std::filesystem::path state;
};

[[nodiscard]] RuntimePaths resolve_paths(const RuntimeOptions& options = {});

/// Load configuration; a missing file yields defaults. On parse failure the
/// warning is filled in and defaults are returned.
[[nodiscard]] Config load_effective_config(const RuntimePaths& paths, std::string& warning);

/// Registry with the built-in GitHub and Steam providers.
[[nodiscard]] ProviderRegistry make_registry();

/// Compile the enabled providers plus any `[[provider.custom]]` rules.
[[nodiscard]] RuleSet build_rules(const Config& config, const ProviderRegistry& registry);

[[nodiscard]] std::vector<std::string> split(std::string_view text, char separator);
[[nodiscard]] std::string join(const std::vector<std::string>& values, std::string_view separator);
[[nodiscard]] std::optional<std::uint16_t> parse_port(std::string_view text);

/// Point the process logger at `<log_dir>/ghacc.log` with rotation.
void configure_logging(const RuntimePaths& paths, LogLevel level, bool to_file = true);

// --- status ---------------------------------------------------------------

struct HostsStatus {
    bool block_present = false;
    bool writable = false;
    std::size_t entries = 0;
    std::string path;
};

struct StatusInfo {
    bool running = false;
    int pid = 0;
    std::string mode;
    std::string address;
    std::uint16_t proxy_port = 0;
    std::uint16_t http_port = 0;
    std::uint16_t https_port = 0;
    std::vector<std::string> providers;
    std::vector<std::string> available_providers;
    bool ca_present = false;
    bool ca_trusted = false;
    HostsStatus hosts;
    std::string config_path;
    std::string log_path;
    std::string version;
};

[[nodiscard]] StatusInfo gather_status(const RuntimePaths& paths, const Config& config,
                                       const ProviderRegistry& registry);
[[nodiscard]] std::string to_json(const StatusInfo& status);
[[nodiscard]] std::string to_text(const StatusInfo& status);

// --- shell completion -----------------------------------------------------

[[nodiscard]] std::string completion_script(std::string_view shell);

// --- daemon / pid file ----------------------------------------------------

[[nodiscard]] std::optional<int> read_pid_file(const std::filesystem::path& path);
[[nodiscard]] bool process_alive(int pid);
[[nodiscard]] std::expected<void, std::string> write_pid_file(const std::filesystem::path& path,
                                                              bool force);
void remove_pid_file(const std::filesystem::path& path);
[[nodiscard]] std::expected<void, std::string> stop_process(const std::filesystem::path& pid_path,
                                                            std::chrono::milliseconds timeout);

/// Detach from the controlling terminal (POSIX). On Windows this is
/// unsupported and returns an error. Never returns in the parent process.
[[nodiscard]] std::expected<void, std::string> daemonize(const std::filesystem::path& log_path);

} // namespace ghacc::app
