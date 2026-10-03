import std;
import boost.ut;
import ghacc.accel.takeover.system_proxy;

using namespace boost::ut;
using namespace ghacc::accel;

int main() {
    const SystemProxyBackend gnome{SystemProxyKind::Gnome, "gsettings", ""};
    const SystemProxyBackend kde{SystemProxyKind::Kde, "kwriteconfig6", ""};
    const SystemProxyBackend mac{SystemProxyKind::MacOs, "networksetup", "Wi-Fi"};
    const SystemProxyBackend windows{SystemProxyKind::Windows, "reg", ""};

    "gnome http proxy plan"_test = [&] {
        const auto on = plan_http_proxy(gnome, true, "127.0.0.1", 26501);
        expect(on.size() == 5_u);
        expect(on[0] == std::vector<std::string>{"gsettings", "set", "org.gnome.system.proxy",
                                                 "mode", "manual"});
        expect(on[1] == std::vector<std::string>{"gsettings", "set", "org.gnome.system.proxy.http",
                                                 "host", "127.0.0.1"});
        expect(on[2].back() == std::string("26501"));
        expect(on[3][2] == std::string("org.gnome.system.proxy.https"));

        const auto off = plan_http_proxy(gnome, false, "", 0);
        expect(off.size() == 1_u);
        expect(off[0].back() == std::string("none"));
    };

    "gnome pac plan"_test = [&] {
        const auto on = plan_pac(gnome, true, "http://127.0.0.1:26501/pac");
        expect(on.size() == 2_u);
        expect(on[0].back() == std::string("auto"));
        expect(on[1].back() == std::string("http://127.0.0.1:26501/pac"));
        const auto off = plan_pac(gnome, false, "");
        expect(off.size() == 1_u);
    };

    "kde http proxy plan"_test = [&] {
        const auto on = plan_http_proxy(kde, true, "127.0.0.1", 26501);
        expect(on.size() == 3_u);
        expect(on[0].back() == std::string("1"));
        expect(on[1].back() == std::string("http://127.0.0.1:26501"));
        expect(on[2].back() == std::string("http://127.0.0.1:26501"));
    };

    "kde pac plan"_test = [&] {
        const auto on = plan_pac(kde, true, "http://127.0.0.1:26501/pac");
        expect(on.size() == 2_u);
        expect(on[0].back() == std::string("2"));
        expect(on[1].back() == std::string("http://127.0.0.1:26501/pac"));
    };

    "macos http proxy plan"_test = [&] {
        const auto on = plan_http_proxy(mac, true, "127.0.0.1", 26501);
        expect(on.size() == 4_u);
        expect(on[0] == std::vector<std::string>{"networksetup", "-setwebproxy", "Wi-Fi",
                                                 "127.0.0.1", "26501"});
        expect(on[1][1] == std::string("-setsecurewebproxy"));
        expect(on[2].back() == std::string("on"));
        const auto off = plan_http_proxy(mac, false, "", 0);
        expect(off.size() == 2_u);
        expect(off[0].back() == std::string("off"));
    };

    "macos pac plan"_test = [&] {
        const auto on = plan_pac(mac, true, "http://127.0.0.1:26501/pac");
        expect(on.size() == 2_u);
        expect(on[1][1] == std::string("-setautoproxystate"));
        const auto off = plan_pac(mac, false, "");
        expect(off.size() == 1_u);
        expect(off[0].back() == std::string("off"));
    };

    "windows proxy plan uses reg"_test = [&] {
        const auto on = plan_http_proxy(windows, true, "127.0.0.1", 26501);
        expect(on.size() == 2_u);
        expect(on[0][1] == std::string("add"));
        expect(on[0][8] == std::string("1"));
        expect(on[1][8] == std::string("127.0.0.1:26501"));

        const auto pac_on = plan_pac(windows, true, "http://127.0.0.1:26501/pac");
        expect(pac_on.size() == 1_u);
        expect(pac_on[0][1] == std::string("add"));
        const auto pac_off = plan_pac(windows, false, "");
        expect(pac_off.size() == 1_u);
        expect(pac_off[0][1] == std::string("delete"));
    };

    "unconfigured backend reports an error"_test = [&] {
        SystemProxyManager manager(SystemProxyBackend{});
        const auto result = manager.set_http(true, "127.0.0.1", 26501);
        expect(!result.has_value());
        expect(!manager.set_pac(true, "http://x/pac").has_value());
        expect(!manager.clear().has_value());
    };

    "commands run through the injected runner"_test = [&] {
        std::vector<std::vector<std::string>> ran;
        SystemProxyManager manager(gnome, [&](const std::vector<std::string>& command)
                                              -> std::expected<std::string, std::string> {
            ran.push_back(command);
            return std::string{};
        });
        const auto result = manager.set_http(true, "127.0.0.1", 26501);
        expect(result.has_value()) << (result ? "" : result.error());
        expect(ran.size() == 5_u);
        expect(manager.backend_name() == std::string_view("gnome"));
    };

    return 0;
}
