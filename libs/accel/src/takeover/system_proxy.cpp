module;

#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif

module ghacc.accel.takeover.system_proxy;

import std;

namespace ghacc::accel {

namespace {

constexpr std::string_view kWindowsKey =
    R"(HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings)";

std::string kde_value(std::string_view host, std::uint16_t port) {
    return "http://" + std::string(host) + ":" + std::to_string(port);
}

#if defined(_WIN32)
std::string quote_argument(std::string_view argument) {
    std::string out = "\"";
    for (char c : argument) {
        if (c == '"') out += "\\\"";
        else out.push_back(c);
    }
    out.push_back('"');
    return out;
}
#else
std::string quote_argument(std::string_view argument) {
    std::string out = "'";
    for (char c : argument) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out.push_back('\'');
    return out;
}
#endif

bool command_exists(std::string_view name) {
    const char* path = std::getenv("PATH");
    if (path == nullptr) return false;
#if defined(_WIN32)
    constexpr char separator = ';';
    const std::string suffix = ".exe";
#else
    constexpr char separator = ':';
    const std::string suffix;
#endif
    const std::string_view paths(path);
    std::size_t start = 0;
    while (start <= paths.size()) {
        const auto end = paths.find(separator, start);
        const std::string_view dir =
            paths.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        if (!dir.empty()) {
            std::error_code ec;
            const auto candidate = std::filesystem::path(dir) / (std::string(name) + suffix);
            if (std::filesystem::exists(candidate, ec) &&
                !std::filesystem::is_directory(candidate, ec)) {
                return true;
            }
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return false;
}

std::string trimmed(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
        text.remove_suffix(1);
    }
    return std::string(text);
}

} // namespace

std::vector<std::vector<std::string>> plan_http_proxy(const SystemProxyBackend& backend, bool enable,
                                                      std::string_view host, std::uint16_t port) {
    const std::string port_text = std::to_string(port);
    const std::string host_text(host);
    switch (backend.kind) {
        case SystemProxyKind::Gnome:
            if (!enable) return {{backend.tool, "set", "org.gnome.system.proxy", "mode", "none"}};
            return {
                {backend.tool, "set", "org.gnome.system.proxy", "mode", "manual"},
                {backend.tool, "set", "org.gnome.system.proxy.http", "host", host_text},
                {backend.tool, "set", "org.gnome.system.proxy.http", "port", port_text},
                {backend.tool, "set", "org.gnome.system.proxy.https", "host", host_text},
                {backend.tool, "set", "org.gnome.system.proxy.https", "port", port_text},
            };
        case SystemProxyKind::Kde:
            if (!enable) {
                return {{backend.tool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key",
                         "ProxyType", "0"}};
            }
            return {
                {backend.tool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key",
                 "ProxyType", "1"},
                {backend.tool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key",
                 "httpProxy", kde_value(host, port)},
                {backend.tool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key",
                 "httpsProxy", kde_value(host, port)},
            };
        case SystemProxyKind::MacOs:
            if (!enable) {
                return {
                    {backend.tool, "-setwebproxystate", backend.service, "off"},
                    {backend.tool, "-setsecurewebproxystate", backend.service, "off"},
                };
            }
            return {
                {backend.tool, "-setwebproxy", backend.service, host_text, port_text},
                {backend.tool, "-setsecurewebproxy", backend.service, host_text, port_text},
                {backend.tool, "-setwebproxystate", backend.service, "on"},
                {backend.tool, "-setsecurewebproxystate", backend.service, "on"},
            };
        case SystemProxyKind::Windows:
            if (!enable) {
                return {{backend.tool, "add", std::string(kWindowsKey), "/v", "ProxyEnable", "/t",
                         "REG_DWORD", "/d", "0", "/f"}};
            }
            return {
                {backend.tool, "add", std::string(kWindowsKey), "/v", "ProxyEnable", "/t",
                 "REG_DWORD", "/d", "1", "/f"},
                {backend.tool, "add", std::string(kWindowsKey), "/v", "ProxyServer", "/t", "REG_SZ",
                 "/d", host_text + ":" + port_text, "/f"},
            };
        case SystemProxyKind::None:
            break;
    }
    return {};
}

std::vector<std::vector<std::string>> plan_pac(const SystemProxyBackend& backend, bool enable,
                                               std::string_view url) {
    const std::string url_text(url);
    switch (backend.kind) {
        case SystemProxyKind::Gnome:
            if (!enable) return {{backend.tool, "set", "org.gnome.system.proxy", "mode", "none"}};
            return {
                {backend.tool, "set", "org.gnome.system.proxy", "mode", "auto"},
                {backend.tool, "set", "org.gnome.system.proxy", "autoconfig-url", url_text},
            };
        case SystemProxyKind::Kde:
            if (!enable) {
                return {{backend.tool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key",
                         "ProxyType", "0"}};
            }
            return {
                {backend.tool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key",
                 "ProxyType", "2"},
                {backend.tool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key",
                 "Proxy Config Script", url_text},
            };
        case SystemProxyKind::MacOs:
            if (!enable) {
                return {{backend.tool, "-setautoproxystate", backend.service, "off"}};
            }
            return {
                {backend.tool, "-setautoproxyurl", backend.service, url_text},
                {backend.tool, "-setautoproxystate", backend.service, "on"},
            };
        case SystemProxyKind::Windows:
            if (!enable) {
                return {{backend.tool, "delete", std::string(kWindowsKey), "/v", "AutoConfigURL",
                         "/f"}};
            }
            return {{backend.tool, "add", std::string(kWindowsKey), "/v", "AutoConfigURL", "/t",
                     "REG_SZ", "/d", url_text, "/f"}};
        case SystemProxyKind::None:
            break;
    }
    return {};
}

SystemProxyManager::SystemProxyManager(SystemProxyBackend backend)
    : backend_(std::move(backend)),
      runner_([](const std::vector<std::string>& argv) { return run_process(argv); }) {}

SystemProxyManager::SystemProxyManager(SystemProxyBackend backend, Runner runner)
    : backend_(std::move(backend)), runner_(std::move(runner)) {}

SystemProxyManager SystemProxyManager::detect() {
#if defined(_WIN32)
    return SystemProxyManager(SystemProxyBackend{SystemProxyKind::Windows, "reg", ""});
#elif defined(__APPLE__)
    SystemProxyBackend backend{SystemProxyKind::MacOs, "networksetup", ""};
    if (auto output = run_process({"networksetup", "-listallnetworkservices"})) {
        std::istringstream stream(*output);
        std::string line;
        while (std::getline(stream, line)) {
            const std::string value = trimmed(line);
            if (value.empty() || value.starts_with("An asterisk") || value.starts_with("*")) continue;
            backend.service = value;
            break;
        }
    }
    return SystemProxyManager(std::move(backend));
#else
    const char* desktop = std::getenv("XDG_CURRENT_DESKTOP");
    const std::string_view desktop_view(desktop != nullptr ? desktop : "");
    const bool gnome_desktop = desktop_view.find("GNOME") != std::string_view::npos ||
                               desktop_view.find("Unity") != std::string_view::npos ||
                               desktop_view.find("Cinnamon") != std::string_view::npos;
    if (gnome_desktop && command_exists("gsettings")) {
        return SystemProxyManager(SystemProxyBackend{SystemProxyKind::Gnome, "gsettings", ""});
    }
    if (command_exists("kwriteconfig6")) {
        return SystemProxyManager(SystemProxyBackend{SystemProxyKind::Kde, "kwriteconfig6", ""});
    }
    if (command_exists("kwriteconfig5")) {
        return SystemProxyManager(SystemProxyBackend{SystemProxyKind::Kde, "kwriteconfig5", ""});
    }
    if (command_exists("gsettings")) {
        return SystemProxyManager(SystemProxyBackend{SystemProxyKind::Gnome, "gsettings", ""});
    }
    return SystemProxyManager(SystemProxyBackend{});
#endif
}

std::expected<void, std::string> SystemProxyManager::set_http(bool enable, std::string_view host,
                                                              std::uint16_t port) {
    if (backend_.kind == SystemProxyKind::None) {
        return std::unexpected("no supported system proxy backend detected; set http_proxy/"
                               "https_proxy manually");
    }
    return run_all(plan_http_proxy(backend_, enable, host, port));
}

std::expected<void, std::string> SystemProxyManager::set_pac(bool enable, std::string_view url) {
    if (backend_.kind == SystemProxyKind::None) {
        return std::unexpected("no supported system proxy backend detected; set the PAC URL "
                               "manually in your browser");
    }
    return run_all(plan_pac(backend_, enable, url));
}

std::expected<void, std::string> SystemProxyManager::clear() {
    if (backend_.kind == SystemProxyKind::None) {
        return std::unexpected("no supported system proxy backend detected");
    }
    if (auto result = run_all(plan_http_proxy(backend_, false, "", 0)); !result) return result;
    return run_all(plan_pac(backend_, false, ""));
}

std::expected<void, std::string> SystemProxyManager::run_all(
    const std::vector<std::vector<std::string>>& commands) {
    for (const auto& command : commands) {
        if (auto result = runner_(command); !result) {
            return std::unexpected(result.error());
        }
    }
    return {};
}

std::expected<std::string, std::string> SystemProxyManager::run_process(
    const std::vector<std::string>& argv) {
    if (argv.empty()) return std::unexpected("empty command");

    std::string command;
    for (const auto& argument : argv) {
        if (!command.empty()) command.push_back(' ');
        command += quote_argument(argument);
    }

#if defined(_WIN32)
    FILE* pipe = _popen(command.c_str(), "r");
#else
    FILE* pipe = popen(command.c_str(), "r");
#endif
    if (pipe == nullptr) return std::unexpected("cannot run: " + command);

    std::string output;
    std::array<char, 4096> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
#if defined(_WIN32)
    const int status = _pclose(pipe);
    if (status != 0) return std::unexpected("command failed: " + command);
#else
    const int status = pclose(pipe);
    if (status == -1) return std::unexpected("cannot wait for: " + command);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        return std::unexpected("command exited with " + std::to_string(WEXITSTATUS(status)) + ": " +
                               command);
    }
#endif
    return output;
}

} // namespace ghacc::accel
