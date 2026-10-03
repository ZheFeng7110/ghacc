import std;
import boost.ut;
import ghacc.accel.config;
import ghacc.accel.log;
import ghacc.accel.rule;

using namespace boost::ut;
using namespace ghacc::accel;

namespace {

constexpr std::string_view sample = R"(
[general]
mode = "system"
log_level = "debug"

[listen]
address = "0.0.0.0"
proxy_port = 12345
http_port = 8080
https_port = 8443

[dns]
doh = ["https://dns.example/dns-query"]
prefer_ipv6 = true
cache_ttl = 60

[providers]
enabled = ["github"]

[[provider.custom]]
id = "example"
name = "Example"

[[provider.custom.rules]]
pattern = "*.example.com"
action = "tunnel"
tls_sni = false
timeout_ms = 5000
)";

} // namespace

int main() {
    "defaults are sane"_test = [] {
        auto config = default_config();
        expect(config.mode == ProxyMode::Hosts);
        expect(config.listen.https_port == 443_u);
        expect(config.enabled_providers.size() == 2_u);
    };

    "parse full config"_test = [] {
        auto parsed = parse_config(sample);
        expect(parsed.has_value());
        if (!parsed) return;

        const auto& config = *parsed;
        expect(config.mode == ProxyMode::System);
        expect(config.log_level == LogLevel::Debug);
        expect(config.listen.address == std::string("0.0.0.0"));
        expect(config.listen.proxy_port == 12345_u);
        expect(config.dns.prefer_ipv6);
        expect(config.dns.cache_ttl_seconds == 60_u);
        expect(config.enabled_providers.size() == 1_u);
        expect(config.custom_providers.size() == 1_u);

        const auto& custom = config.custom_providers.front();
        expect(custom.id == std::string("example"));
        expect(custom.rules.size() == 1_u);
        expect(custom.rules.front().action == RuleAction::Tunnel);
        expect(!custom.rules.front().tls_sni);
        expect(custom.rules.front().timeout == std::chrono::milliseconds{5000});
    };

    "invalid toml reports an error"_test = [] {
        auto parsed = parse_config("this is = = not toml");
        expect(!parsed.has_value());
    };

    "platform paths use the expected leaf names"_test = [] {
        expect(default_config_path().filename() == std::filesystem::path("config.toml"));
        expect(default_ca_dir().filename() == std::filesystem::path("ca"));
        expect(default_log_path().filename() == std::filesystem::path("ghacc.log"));
        expect(default_pid_path().filename() == std::filesystem::path("ghacc.pid"));
        expect(default_cert_cache_dir().filename() == std::filesystem::path("certs"));
        expect(!default_data_dir().empty());
        expect(!default_state_dir().empty());
    };

    "round trip preserves values"_test = [] {
        auto parsed = parse_config(sample);
        expect(parsed.has_value());
        if (!parsed) return;

        const std::string serialized = to_toml(*parsed);
        auto again = parse_config(serialized);
        expect(again.has_value());
        if (!again) return;

        expect(again->mode == parsed->mode);
        expect(again->listen.proxy_port == parsed->listen.proxy_port);
        expect(again->custom_providers.size() == 1_u);
        expect(again->custom_providers.front().rules.size() == 1_u);
        expect(again->custom_providers.front().rules.front().pattern ==
               std::string("*.example.com"));
    };

    return 0;
}
