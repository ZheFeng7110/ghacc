import std;
import boost.ut;
import ghacc.accel.rule;

using namespace boost::ut;
using namespace ghacc::accel;

namespace {

DomainRule make(std::string pattern, std::string description) {
    DomainRule rule;
    rule.pattern = std::move(pattern);
    rule.description = std::move(description);
    return rule;
}

} // namespace

int main() {
    "exact match is case-insensitive"_test = [] {
        RuleSet set;
        set.add(make("github.com", "exact"));
        expect(set.match("github.com").has_value());
        expect(set.match("GitHub.COM").has_value());
        expect(!set.match("api.github.com").has_value());
    };

    "host port is stripped"_test = [] {
        RuleSet set;
        set.add(make("github.com", "exact"));
        expect(set.match("github.com:443").has_value());
    };

    "wildcard matches subdomains"_test = [] {
        RuleSet set;
        set.add(make("*.githubusercontent.com", "wild"));
        expect(set.match("raw.githubusercontent.com").has_value());
        expect(set.match("a.b.githubusercontent.com").has_value());
        expect(!set.match("githubusercontent.com").has_value());
    };

    "wildcard question mark matches one char"_test = [] {
        RuleSet set;
        set.add(make("cdn?.example.com", "wild"));
        expect(set.match("cdn1.example.com").has_value());
        expect(!set.match("cdn12.example.com").has_value());
    };

    "exact wins over wildcard"_test = [] {
        RuleSet set;
        set.add(make("*.example.com", "wild"));
        set.add(make("api.example.com", "exact"));
        auto matched = set.match("api.example.com");
        expect(matched.has_value());
        expect(matched->description == "exact");
    };

    "explicit regex form"_test = [] {
        RuleSet set;
        set.add(make(R"(re:^foo\d+\.com$)", "regex"));
        expect(set.match("foo123.com").has_value());
        expect(!set.match("foo.com").has_value());
    };

    "slash delimited regex form"_test = [] {
        RuleSet set;
        set.add(make(R"(/^bar\.com$/)", "regex"));
        expect(set.match("bar.com").has_value());
        expect(!set.match("barbar.com").has_value());
    };

    "patterns are ordered by specificity"_test = [] {
        RuleSet set;
        set.add(make("*.example.com", "wild"));
        set.add(make("api.example.com", "exact"));
        auto patterns = set.patterns();
        expect(patterns.size() == 2_u);
        expect(patterns.front() == std::string("api.example.com"));
    };

    "hostnames keeps exact hosts and wildcard apexes"_test = [] {
        RuleSet set;
        set.add(make("github.com", "exact"));
        set.add(make("*.github.com", "wild"));
        set.add(make("*.githubusercontent.com", "wild"));
        set.add(make("cdn?.example.com", "mid-wild"));
        set.add(make(R"(re:^foo\d+\.com$)", "regex"));

        const auto hosts = set.hostnames();
        const std::vector<std::string> expected = {"github.com", "githubusercontent.com"};
        expect(hosts == expected);
    };

    return 0;
}
