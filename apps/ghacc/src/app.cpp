module;

#include <cerrno>
#if defined(_WIN32)
#include <windows.h>
#else
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#endif
#include <cstdio>

module ghacc.app;

import std;
import ghacc.accel;

namespace ghacc::app {

namespace fs = std::filesystem;

RuntimePaths resolve_paths(const RuntimeOptions& options) {
    RuntimePaths paths;
    paths.config = options.config_path ? *options.config_path : default_config_path();
    paths.ca = options.ca_dir ? *options.ca_dir : paths.config.parent_path() / "ca";
    paths.hosts = options.hosts_path ? *options.hosts_path : HostsManager::default_path();
    paths.hosts_backup =
        options.hosts_backup ? *options.hosts_backup : HostsManager::default_backup_path();
    paths.pid = default_pid_path();
    paths.log = default_log_path();
    paths.data = default_data_dir();
    paths.state = default_state_dir();
    return paths;
}

Config load_effective_config(const RuntimePaths& paths, std::string& warning) {
    warning.clear();
    auto loaded = load_config(paths.config);
    if (!loaded) {
        warning = loaded.error();
        return default_config();
    }
    return *loaded;
}

ProviderRegistry make_registry() {
    ProviderRegistry registry;
    registry.add(std::make_unique<GitHubProvider>());
    registry.add(std::make_unique<SteamProvider>());
    return registry;
}

RuleSet build_rules(const Config& config, const ProviderRegistry& registry) {
    RuleSet rules = registry.build_rules(config.enabled_providers);
    for (const auto& custom : config.custom_providers) {
        for (auto rule : custom.rules) {
            if (rule.provider_id.empty()) rule.provider_id = custom.id;
            rules.add(std::move(rule));
        }
    }
    return rules;
}

std::vector<std::string> split(std::string_view text, char separator) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto end = text.find(separator, start);
        const auto part = text.substr(
            start, end == std::string_view::npos ? std::string_view::npos : end - start);
        if (!part.empty()) out.emplace_back(part);
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return out;
}

std::string join(const std::vector<std::string>& values, std::string_view separator) {
    std::string out;
    for (const auto& value : values) {
        if (!out.empty()) out.append(separator);
        out += value;
    }
    return out;
}

std::optional<std::uint16_t> parse_port(std::string_view text) {
    unsigned parsed = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (ec != std::errc{} || ptr != text.data() + text.size() || parsed > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(parsed);
}

void configure_logging(const RuntimePaths& paths, LogLevel level, bool to_file) {
    Log::instance().set_level(level);
    if (to_file) Log::instance().set_file(paths.log);
}

// --- status ---------------------------------------------------------------

namespace {

std::string escape_json(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out += std::format("\\u{:04x}", static_cast<unsigned>(c));
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

std::string json_string(std::string_view value) { return "\"" + escape_json(value) + "\""; }

std::string json_string_array(const std::vector<std::string>& values) {
    std::string out = "[";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) out += ",";
        out += json_string(values[i]);
    }
    out += "]";
    return out;
}

} // namespace

StatusInfo gather_status(const RuntimePaths& paths, const Config& config,
                         const ProviderRegistry& registry) {
    StatusInfo status;
    status.version = std::string(version);
    status.config_path = paths.config.string();
    status.log_path = paths.log.string();
    status.mode = std::string(to_string(config.mode));
    status.address = config.listen.address;
    status.proxy_port = config.listen.proxy_port;
    status.http_port = config.listen.http_port;
    status.https_port = config.listen.https_port;
    status.providers = config.enabled_providers;
    for (const auto& meta : registry.metas()) status.available_providers.push_back(meta.id);

    if (auto pid = read_pid_file(paths.pid); pid && process_alive(*pid)) {
        status.running = true;
        status.pid = *pid;
    }

    const fs::path ca_cert = paths.ca / "ca.crt";
    std::error_code ec;
    status.ca_present = fs::exists(ca_cert, ec) && !ec;
    if (status.ca_present) {
        CaTrustManager manager(plan_ca_trust(ca_cert, detect_ca_trust_platform()));
        if (auto trusted = manager.is_trusted(); trusted) status.ca_trusted = *trusted;
    }

    HostsManager hosts(paths.hosts, paths.hosts_backup);
    status.hosts.path = paths.hosts.string();
    status.hosts.writable = hosts.is_writable();
    status.hosts.block_present = hosts.contains_our_block();
    if (status.hosts.block_present) status.hosts.entries = hosts.current_block().size();
    return status;
}

std::string to_json(const StatusInfo& status) {
    std::string out = "{";
    out += "\"version\":" + json_string(status.version);
    out += ",\"running\":" + std::string(status.running ? "true" : "false");
    out += ",\"pid\":" + std::to_string(status.pid);
    out += ",\"mode\":" + json_string(status.mode);
    out += ",\"address\":" + json_string(status.address);
    out += ",\"proxy_port\":" + std::to_string(status.proxy_port);
    out += ",\"http_port\":" + std::to_string(status.http_port);
    out += ",\"https_port\":" + std::to_string(status.https_port);
    out += ",\"providers\":" + json_string_array(status.providers);
    out += ",\"available_providers\":" + json_string_array(status.available_providers);
    out += ",\"ca_present\":" + std::string(status.ca_present ? "true" : "false");
    out += ",\"ca_trusted\":" + std::string(status.ca_trusted ? "true" : "false");
    out += ",\"hosts\":{";
    out += "\"path\":" + json_string(status.hosts.path);
    out += ",\"block_present\":" + std::string(status.hosts.block_present ? "true" : "false");
    out += ",\"writable\":" + std::string(status.hosts.writable ? "true" : "false");
    out += ",\"entries\":" + std::to_string(status.hosts.entries);
    out += "}";
    out += ",\"config\":" + json_string(status.config_path);
    out += ",\"log\":" + json_string(status.log_path);
    out += "}";
    return out;
}

std::string to_text(const StatusInfo& status) {
    std::string out;
    out += "ghacc " + status.version + "\n";
    out += "  running:   " + std::string(status.running ? "yes" : "no");
    if (status.running) out += " (pid " + std::to_string(status.pid) + ")";
    out += "\n";
    out += "  mode:      " + status.mode + "\n";
    out += "  listen:    " + status.address + " http=" + std::to_string(status.http_port) +
           " https=" + std::to_string(status.https_port) +
           " proxy=" + std::to_string(status.proxy_port) + "\n";
    out += "  providers: " + (status.providers.empty() ? std::string("(none)")
                                                      : join(status.providers, ",")) +
           "\n";
    out += "  ca:        " + std::string(status.ca_present ? "present" : "missing") +
           std::string(status.ca_trusted ? ", trusted" : ", not trusted") + "\n";
    out += "  hosts:     " + status.hosts.path +
           std::string(status.hosts.block_present ? ", block applied" : ", no block") +
           " (" + std::to_string(status.hosts.entries) + " entries)\n";
    out += "  config:    " + status.config_path + "\n";
    out += "  log:       " + status.log_path + "\n";
    return out;
}

// --- shell completion -----------------------------------------------------

std::string completion_script(std::string_view shell) {
    constexpr std::string_view commands =
        "run stop status provider ca hosts proxy test config completion help version";
    if (shell == "bash") {
        return std::format(
            "# bash completion for ghacc\n"
            "_ghacc() {{\n"
            "  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n"
            "  if [ \"$COMP_CWORD\" -eq 1 ]; then\n"
            "    COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") )\n"
            "  fi\n"
            "}}\n"
            "complete -F _ghacc ghacc\n",
            commands);
    }
    if (shell == "zsh") {
        return std::format(
            "#compdef ghacc\n"
            "_ghacc() {{\n"
            "  local -a commands\n"
            "  commands=({})\n"
            "  _describe 'command' commands\n"
            "}}\n"
            "compdef _ghacc ghacc\n",
            commands);
    }
    if (shell == "fish") {
        std::string out;
        for (const auto& command : split(commands, ' ')) {
            out += "complete -c ghacc -n '__fish_use_subcommand' -a '" + command + "'\n";
        }
        return out;
    }
    return {};
}

// --- daemon / pid file ----------------------------------------------------

std::optional<int> read_pid_file(const fs::path& path) {
    std::ifstream stream(path);
    if (!stream) return std::nullopt;
    int pid = 0;
    stream >> pid;
    if (!stream || pid <= 0) return std::nullopt;
    return pid;
}

bool process_alive(int pid) {
    if (pid <= 0) return false;
#if defined(_WIN32)
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                static_cast<DWORD>(pid));
    if (handle == nullptr) return false;
    DWORD code = 0;
    const bool alive = GetExitCodeProcess(handle, &code) != 0 && code == STILL_ACTIVE;
    CloseHandle(handle);
    return alive;
#else
    if (::kill(pid, 0) == 0) return true;
    return errno == EPERM;
#endif
}

std::expected<void, std::string> write_pid_file(const fs::path& path, bool force) {
    if (auto existing = read_pid_file(path)) {
        if (!force && process_alive(*existing)) {
            return std::unexpected("ghacc is already running (pid " + std::to_string(*existing) +
                                   "); use --force to replace " + path.string());
        }
    }
    std::error_code ec;
    if (const auto parent = path.parent_path(); !parent.empty()) fs::create_directories(parent, ec);
    std::ofstream stream(path, std::ios::trunc);
    if (!stream) return std::unexpected("cannot write pid file: " + path.string());
#if defined(_WIN32)
    stream << static_cast<long long>(GetCurrentProcessId());
#else
    stream << static_cast<long long>(::getpid());
#endif
    return {};
}

void remove_pid_file(const fs::path& path) {
    std::error_code ec;
    fs::remove(path, ec);
}

std::expected<void, std::string> stop_process(const fs::path& pid_path,
                                              std::chrono::milliseconds timeout) {
    auto pid = read_pid_file(pid_path);
    if (!pid) return std::unexpected("no running ghacc found (" + pid_path.string() + ")");
    if (!process_alive(*pid)) {
        remove_pid_file(pid_path);
        return std::unexpected("stale pid file removed; process " + std::to_string(*pid) +
                               " is not running");
    }
#if defined(_WIN32)
    HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(*pid));
    if (handle == nullptr) return std::unexpected("cannot open process " + std::to_string(*pid));
    const bool ok = TerminateProcess(handle, 0) != 0;
    CloseHandle(handle);
    if (!ok) return std::unexpected("cannot terminate process " + std::to_string(*pid));
#else
    if (::kill(*pid, SIGTERM) != 0) {
        return std::unexpected("cannot signal process " + std::to_string(*pid));
    }
#endif
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!process_alive(*pid)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    remove_pid_file(pid_path);
    return {};
}

std::expected<void, std::string> daemonize(const fs::path& log_path) {
#if defined(_WIN32)
    (void)log_path;
    return std::unexpected(
        "daemon mode is not supported on Windows; run ghacc as a service or in a terminal");
#else
    const pid_t parent = ::fork();
    if (parent < 0) return std::unexpected("fork() failed");
    if (parent > 0) ::_exit(0);

    if (::setsid() < 0) return std::unexpected("setsid() failed");

    const pid_t second = ::fork();
    if (second < 0) return std::unexpected("second fork() failed");
    if (second > 0) ::_exit(0);

    std::error_code ec;
    if (const auto parent_dir = log_path.parent_path(); !parent_dir.empty()) {
        fs::create_directories(parent_dir, ec);
    }
    if (FILE* file = std::freopen(log_path.c_str(), "a", stdout)) {
        (void)file;
        std::freopen(log_path.c_str(), "a", stderr);
        std::freopen("/dev/null", "r", stdin);
    }
    return {};
#endif
}

} // namespace ghacc::app
