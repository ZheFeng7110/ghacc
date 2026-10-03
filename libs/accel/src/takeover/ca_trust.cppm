export module ghacc.accel.takeover.ca_trust;

import std;

export namespace ghacc::accel {

/// Which trust store mechanism a platform uses.
enum class CaTrustPlatform : std::uint8_t {
    LinuxDebian,
    LinuxRedHat,
    MacOs,
    Windows,
    Unsupported,
};

[[nodiscard]] constexpr std::string_view to_string(CaTrustPlatform platform) noexcept {
    switch (platform) {
        case CaTrustPlatform::LinuxDebian: return "linux-debian";
        case CaTrustPlatform::LinuxRedHat: return "linux-redhat";
        case CaTrustPlatform::MacOs:       return "macos";
        case CaTrustPlatform::Windows:     return "windows";
        case CaTrustPlatform::Unsupported: return "unsupported";
    }
    return "unsupported";
}

/// Deny-by-default command plan for trusting/untrusting a local CA.
struct CaTrustPlan {
    CaTrustPlatform platform = CaTrustPlatform::Unsupported;
    /// Source PEM passed to `plan_ca_trust`.
    std::filesystem::path certificate_path;
    /// Where the PEM must be copied before the install commands run (Linux);
    /// empty when the commands accept the source path directly.
    std::filesystem::path staging_path;
    std::vector<std::vector<std::string>> install_commands;
    std::vector<std::vector<std::string>> uninstall_commands;
    /// One-line explanation shown by the CLI.
    std::string description;
    /// Guidance when the commands fail for lack of privileges.
    std::string permission_hint;
};

/// Detect the best mechanism from the running OS (reads `/etc/os-release` and
/// the `PATH` on Linux).
[[nodiscard]] CaTrustPlatform detect_ca_trust_platform();

/// Pure command planning; unit tested without touching the real trust store.
[[nodiscard]] CaTrustPlan plan_ca_trust(const std::filesystem::path& certificate,
                                        CaTrustPlatform platform);

/// Executes a `CaTrustPlan`, staging the certificate and running the planned
/// commands through an injectable runner.
class CaTrustManager {
public:
    using Runner = std::function<std::expected<std::string, std::string>(
        const std::vector<std::string>&)>;

    explicit CaTrustManager(CaTrustPlan plan, Runner runner = run_process);

    std::expected<void, std::string> install();
    std::expected<void, std::string> uninstall();

    /// Best-effort check whether the CA is already trusted (staging file on
    /// Linux, keychain/store query on macOS/Windows).
    [[nodiscard]] std::expected<bool, std::string> is_trusted() const;

    [[nodiscard]] const CaTrustPlan& plan() const noexcept { return plan_; }

    /// Default runner: spawn the process and capture stdout.
    [[nodiscard]] static std::expected<std::string, std::string> run_process(
        const std::vector<std::string>& argv);

private:
    std::expected<void, std::string> run_all(
        const std::vector<std::vector<std::string>>& commands);

    CaTrustPlan plan_;
    Runner runner_;
};

} // namespace ghacc::accel
