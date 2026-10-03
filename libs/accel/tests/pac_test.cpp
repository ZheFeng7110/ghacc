import std;
import boost.ut;
import ghacc.accel.engine.pac;
import ghacc.accel.rule;

using namespace boost::ut;
using namespace ghacc::accel;

namespace {

DomainRule make(std::string pattern) {
    DomainRule rule;
    rule.pattern = std::move(pattern);
    return rule;
}

} // namespace

int main() {
    RuleSet rules;
    rules.add(make("github.com"));
    rules.add(make("*.githubusercontent.com"));
    rules.add(make(R"(re:^foo\d+\.com$)"));

    PacOptions options;
    options.proxy_host = "127.0.0.1";
    options.proxy_port = 26501;

    "pac patterns skip regex"_test = [&] {
        const auto patterns = pac_patterns(rules);
        expect(patterns.size() == 2_u);
        expect(patterns[0] == std::string("github.com"));
        expect(patterns[1] == std::string("*.githubusercontent.com"));
    };

    "generated pac routes matching hosts through the proxy"_test = [&] {
        const std::string script = generate_pac(rules, options);
        expect(script.find("function FindProxyForURL") != std::string::npos);
        expect(script.find(R"(shExpMatch(host, "github.com"))") != std::string::npos);
        expect(script.find(R"(shExpMatch(host, "*.githubusercontent.com"))") != std::string::npos);
        expect(script.find("PROXY 127.0.0.1:26501") != std::string::npos);
        expect(script.find("DIRECT") != std::string::npos);
        expect(script.find("foo") == std::string::npos) << "regex is not expressible in PAC";
    };

    "empty rule set yields a direct pac"_test = [&] {
        RuleSet empty;
        const std::string script = generate_pac(empty, options);
        expect(script.find("PROXY") == std::string::npos);
        expect(script.find("DIRECT") != std::string::npos);
    };

    "pac requests are recognised in both forms"_test = [&] {
        expect(is_pac_request("/pac", options));
        expect(is_pac_request("/proxy.pac", options));
        expect(is_pac_request("/pac?t=1", options));
        expect(is_pac_request("http://127.0.0.1:26501/pac", options));
        expect(!is_pac_request("/other", options));
        expect(is_pac_request("http://example.com/pac", options))
            << "path matching is host independent";
    };

    return 0;
}
