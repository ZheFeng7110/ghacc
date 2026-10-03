export module ghacc.accel.takeover.system_proxy;

import std;

export namespace ghacc::accel {

/// Which desktop/OS mechanism configures the system proxy.
enum class SystemProxyKind : std::uint8_t { None, Gnome, Kde, MacOs, Windows };

[[nodiscard]] constexpr std::string_view to_string(SystemProxyKind kind) noexcept {
    switch (kind) {
        case SystemProxyKind::None:    return "none";
        case SystemProxyKind::Gnome:   return "gnome";
        case SystemProxyKind::Kde:     return "kde";
        case SystemProxyKind::MacOs:   return "macos";
        case SystemProxyKind::Windows: return "windows";
    }
    return "none";
}

/// A detected backend plus the tool/service it drives.
struct SystemProxyBackend {
    SystemProxyKind kind = SystemProxyKind::None;
    /// Executable to invoke (`gsettings`, `kwriteconfig6`, `networksetup`, `reg`).
    std::string tool;
    /// macOS network service name (empty elsewhere).
    std::string service;
};

/// Command lines that enable/disable the HTTP(S) proxy on `backend`.
[[nodiscard]] std::vector<std::vector<std::string>> plan_http_proxy(
    const SystemProxyBackend& backend, bool enable, std::string_view host, std::uint16_t port);

/// Command lines that set/clear the PAC URL on `backend`.
[[nodiscard]] std::vector<std::vector<std::string>> plan_pac(const SystemProxyBackend& backend,
                                                             bool enable, std::string_view url);

/// Applies system proxy / PAC settings by running the planned commands.
///
/// Detection and command planning are pure (and unit tested); execution is
/// injectable so tests never touch the real system settings.
class SystemProxyManager {
public:
    using Runner = std::function<std::expected<std::string, std::string>(
        const std::vector<std::string>&)>;

    /// Detect the best backend for the current session.
    [[nodiscard]] static SystemProxyManager detect();
    explicit SystemProxyManager(SystemProxyBackend backend);
    SystemProxyManager(SystemProxyBackend backend, Runner runner);

    [[nodiscard]] const SystemProxyBackend& backend() const noexcept { return backend_; }
    [[nodiscard]] std::string_view backend_name() const noexcept { return to_string(backend_.kind); }

    std::expected<void, std::string> set_http(bool enable, std::string_view host,
                                              std::uint16_t port);
    std::expected<void, std::string> set_pac(bool enable, std::string_view url);
    std::expected<void, std::string> clear();

    /// Default runner: spawn the process and capture stdout.
    [[nodiscard]] static std::expected<std::string, std::string> run_process(
        const std::vector<std::string>& argv);

private:
    std::expected<void, std::string> run_all(const std::vector<std::vector<std::string>>& commands);

    SystemProxyBackend backend_;
    Runner runner_;
};

} // namespace ghacc::accel
