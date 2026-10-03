module;

#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif

module ghacc.accel.takeover.ca_trust;

import std;

namespace ghacc::accel {

namespace {

constexpr std::string_view kCommonName = "ghacc Root CA";

std::string quote_argument(std::string_view argument) {
    std::string out = "'";
    for (char c : argument) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

bool command_exists(std::string_view name) {
    const char* path = std::getenv("PATH");
    if (path == nullptr) return false;
    const std::string_view paths(path);
    std::size_t start = 0;
    while (start <= paths.size()) {
        const auto end = paths.find(':', start);
        const std::string_view dir =
            paths.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        if (!dir.empty()) {
            std::error_code ec;
            const auto candidate = std::filesystem::path(dir) / std::string(name);
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

std::string read_os_release() {
    std::ifstream stream("/etc/os-release");
    if (!stream) return {};
    return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

bool os_release_contains(std::string_view text, std::string_view needle) {
    return text.find(needle) != std::string_view::npos;
}

} // namespace

CaTrustPlatform detect_ca_trust_platform() {
#if defined(_WIN32)
    return CaTrustPlatform::Windows;
#elif defined(__APPLE__)
    return CaTrustPlatform::MacOs;
#else
    const std::string release = read_os_release();
    if (os_release_contains(release, "debian") || os_release_contains(release, "ubuntu")) {
        return CaTrustPlatform::LinuxDebian;
    }
    if (os_release_contains(release, "rhel") || os_release_contains(release, "fedora") ||
        os_release_contains(release, "centos") || os_release_contains(release, "rocky") ||
        os_release_contains(release, "almalinux") || os_release_contains(release, "suse")) {
        return CaTrustPlatform::LinuxRedHat;
    }
    if (command_exists("update-ca-certificates")) return CaTrustPlatform::LinuxDebian;
    if (command_exists("update-ca-trust")) return CaTrustPlatform::LinuxRedHat;
    return CaTrustPlatform::Unsupported;
#endif
}

CaTrustPlan plan_ca_trust(const std::filesystem::path& certificate, CaTrustPlatform platform) {
    CaTrustPlan plan;
    plan.platform = platform;
    plan.certificate_path = certificate;
    plan.permission_hint =
        "Re-run with sudo (Linux/macOS) or an Administrator terminal (Windows) to trust the CA";

    switch (platform) {
        case CaTrustPlatform::LinuxDebian:
            plan.staging_path = "/usr/local/share/ca-certificates/ghacc.crt";
            plan.install_commands = {{"update-ca-certificates"}};
            plan.uninstall_commands = {{"update-ca-certificates", "--fresh"}};
            plan.description =
                "install into /usr/local/share/ca-certificates and run update-ca-certificates";
            break;
        case CaTrustPlatform::LinuxRedHat:
            plan.staging_path = "/etc/pki/ca-trust/source/anchors/ghacc.crt";
            plan.install_commands = {{"update-ca-trust", "extract"}};
            plan.uninstall_commands = {{"update-ca-trust", "extract"}};
            plan.description =
                "install into /etc/pki/ca-trust/source/anchors and run update-ca-trust";
            break;
        case CaTrustPlatform::MacOs:
            plan.install_commands = {
                {"security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k",
                 "/Library/Keychains/System.keychain", certificate.string()}};
            plan.uninstall_commands = {
                {"security", "remove-trusted-cert", "-d", certificate.string()}};
            plan.description = "add to the System keychain as a trusted root";
            break;
        case CaTrustPlatform::Windows:
            plan.install_commands = {
                {"certutil", "-addstore", "-f", "ROOT", certificate.string()}};
            plan.uninstall_commands = {
                {"certutil", "-delstore", "ROOT", std::string(kCommonName)}};
            plan.description = "add to the ROOT certificate store with certutil";
            break;
        case CaTrustPlatform::Unsupported:
            plan.description = "no supported CA trust mechanism detected";
            break;
    }
    return plan;
}

CaTrustManager::CaTrustManager(CaTrustPlan plan, Runner runner)
    : plan_(std::move(plan)), runner_(std::move(runner)) {}

std::expected<void, std::string> CaTrustManager::install() {
    if (plan_.platform == CaTrustPlatform::Unsupported) {
        return std::unexpected(
            "cannot manage the system CA trust store on this platform; "
            "import the CA certificate manually");
    }
    if (!plan_.staging_path.empty()) {
        std::error_code ec;
        const auto parent = plan_.staging_path.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent, ec);
        std::filesystem::copy_file(plan_.certificate_path, plan_.staging_path,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            return std::unexpected("cannot install CA certificate to " +
                                   plan_.staging_path.string() + ": " + ec.message() +
                                   "\nhint: " + plan_.permission_hint);
        }
    }
    if (auto result = run_all(plan_.install_commands); !result) {
        return std::unexpected(result.error() + "\nhint: " + plan_.permission_hint);
    }
    return {};
}

std::expected<void, std::string> CaTrustManager::uninstall() {
    if (plan_.platform == CaTrustPlatform::Unsupported) {
        return std::unexpected("no supported CA trust mechanism detected");
    }
    if (auto result = run_all(plan_.uninstall_commands); !result) {
        return std::unexpected(result.error() + "\nhint: " + plan_.permission_hint);
    }
    if (!plan_.staging_path.empty()) {
        std::error_code ec;
        std::filesystem::remove(plan_.staging_path, ec);
        if (ec) {
            return std::unexpected("removed the CA from the trust store but could not delete " +
                                   plan_.staging_path.string() + ": " + ec.message());
        }
    }
    return {};
}

std::expected<bool, std::string> CaTrustManager::is_trusted() const {
    switch (plan_.platform) {
        case CaTrustPlatform::Unsupported:
            return false;
        case CaTrustPlatform::LinuxDebian:
        case CaTrustPlatform::LinuxRedHat: {
            std::error_code ec;
            return std::filesystem::exists(plan_.staging_path, ec) && !ec;
        }
        case CaTrustPlatform::MacOs: {
            auto result = runner_({"security", "find-certificate", "-c", std::string(kCommonName),
                                   "/Library/Keychains/System.keychain"});
            return result.has_value();
        }
        case CaTrustPlatform::Windows: {
            auto result = runner_({"certutil", "-store", "ROOT", std::string(kCommonName)});
            return result.has_value();
        }
    }
    return false;
}

std::expected<void, std::string> CaTrustManager::run_all(
    const std::vector<std::vector<std::string>>& commands) {
    for (const auto& command : commands) {
        if (auto result = runner_(command); !result) return std::unexpected(result.error());
    }
    return {};
}

std::expected<std::string, std::string> CaTrustManager::run_process(
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
    if (_pclose(pipe) != 0) return std::unexpected("command failed: " + command);
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
