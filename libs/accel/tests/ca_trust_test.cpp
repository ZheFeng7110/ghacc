import std;
import boost.ut;
import ghacc.accel.takeover.ca_trust;

using namespace boost::ut;
using namespace ghacc::accel;

namespace fs = std::filesystem;

int main() {
    const fs::path cert = "/tmp/ghacc-ca.crt";

    "debian plan stages and runs update-ca-certificates"_test = [&] {
        auto plan = plan_ca_trust(cert, CaTrustPlatform::LinuxDebian);
        expect(plan.platform == CaTrustPlatform::LinuxDebian);
        expect(plan.staging_path ==
               fs::path("/usr/local/share/ca-certificates/ghacc.crt"));
        expect(plan.install_commands.size() == 1_u);
        expect(plan.install_commands.front() ==
               std::vector<std::string>{"update-ca-certificates"});
        expect(plan.uninstall_commands.front() ==
               std::vector<std::string>{"update-ca-certificates", "--fresh"});
    };

    "redhat plan uses update-ca-trust"_test = [&] {
        auto plan = plan_ca_trust(cert, CaTrustPlatform::LinuxRedHat);
        expect(plan.staging_path == fs::path("/etc/pki/ca-trust/source/anchors/ghacc.crt"));
        expect(plan.install_commands.front() ==
               std::vector<std::string>{"update-ca-trust", "extract"});
    };

    "macos plan uses security add-trusted-cert"_test = [&] {
        auto plan = plan_ca_trust(cert, CaTrustPlatform::MacOs);
        expect(plan.staging_path.empty());
        expect(plan.install_commands.size() == 1_u);
        expect(plan.install_commands.front().front() == std::string("security"));
        expect(plan.install_commands.front()[1] == std::string("add-trusted-cert"));
        expect(plan.install_commands.front().back() == cert.string());
        expect(plan.uninstall_commands.front()[1] == std::string("remove-trusted-cert"));
    };

    "windows plan uses certutil"_test = [&] {
        auto plan = plan_ca_trust(cert, CaTrustPlatform::Windows);
        expect(plan.install_commands.front().front() == std::string("certutil"));
        expect(plan.install_commands.front()[1] == std::string("-addstore"));
        expect(plan.uninstall_commands.front()[1] == std::string("-delstore"));
        expect(plan.uninstall_commands.front().back() == std::string("ghacc Root CA"));
    };

    "unsupported platform has an empty plan"_test = [&] {
        auto plan = plan_ca_trust(cert, CaTrustPlatform::Unsupported);
        expect(plan.install_commands.empty());
        expect(plan.uninstall_commands.empty());
    };

    "manager runs the injected commands"_test = [&] {
        std::vector<std::vector<std::string>> ran;
        CaTrustManager manager(plan_ca_trust(cert, CaTrustPlatform::MacOs),
                               [&](const std::vector<std::string>& command)
                                   -> std::expected<std::string, std::string> {
                                   ran.push_back(command);
                                   return std::string{};
                               });
        expect(manager.install().has_value());
        expect(manager.uninstall().has_value());
        expect(ran.size() == 2_u);
    };

    "manager surfaces runner failures"_test = [&] {
        CaTrustManager manager(plan_ca_trust(cert, CaTrustPlatform::MacOs),
                               [](const std::vector<std::string>&)
                                   -> std::expected<std::string, std::string> {
                                   return std::unexpected(std::string("boom"));
                               });
        auto result = manager.install();
        expect(!result.has_value());
        expect(result.error().find("boom") != std::string::npos);
        expect(result.error().find("sudo") != std::string::npos);
    };

    "unsupported manager refuses to run"_test = [&] {
        CaTrustManager manager(plan_ca_trust(cert, CaTrustPlatform::Unsupported));
        expect(!manager.install().has_value());
        expect(!manager.uninstall().has_value());
    };

    "is_trusted tracks the staging file on Linux"_test = [&] {
        const fs::path dir = fs::temp_directory_path() / "ghacc-ca-trust-test";
        fs::remove_all(dir);
        fs::create_directories(dir);
        const fs::path staged = dir / "ghacc.crt";

        CaTrustPlan plan;
        plan.platform = CaTrustPlatform::LinuxDebian;
        plan.staging_path = staged;
        CaTrustManager manager(plan);
        expect(!*manager.is_trusted());
        { std::ofstream(staged) << "cert"; }
        expect(*manager.is_trusted());
        fs::remove_all(dir);
    };

    return 0;
}
