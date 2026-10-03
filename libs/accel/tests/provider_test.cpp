import std;
import boost.ut;
import ghacc.accel.provider;
import ghacc.accel.provider.github;
import ghacc.accel.provider.steam;

using namespace boost::ut;
using namespace ghacc::accel;

namespace {

ProviderRegistry make_registry() {
    ProviderRegistry registry;
    registry.add(std::make_unique<GitHubProvider>());
    registry.add(std::make_unique<SteamProvider>());
    return registry;
}

} // namespace

int main() {
    "registry exposes both providers"_test = [] {
        auto registry = make_registry();
        expect(registry.size() == 2_u);
        expect(registry.find("github") != nullptr);
        expect(registry.find("steam") != nullptr);
        expect(registry.find("missing") == nullptr);
    };

    "default rules cover github and steam"_test = [] {
        auto registry = make_registry();
        auto rules = registry.build_default_rules();
        expect(rules.match("github.com").has_value());
        expect(rules.match("raw.githubusercontent.com").has_value());
        expect(rules.match("store.steampowered.com").has_value());
        expect(rules.match("steamcommunity.com").has_value());
        expect(rules.match("example.org") == std::nullopt);
    };

    "enabling one provider excludes the other"_test = [] {
        auto registry = make_registry();
        std::array<std::string, 1> enabled{"github"};
        auto rules = registry.build_rules(enabled);
        expect(rules.match("github.com").has_value());
        expect(!rules.match("store.steampowered.com").has_value());
    };

    "rules are tagged with their provider"_test = [] {
        auto registry = make_registry();
        auto rules = registry.build_default_rules();
        auto github = rules.match("github.com");
        expect(github.has_value());
        expect(github->provider_id == "github");
    };

    "github coverage includes api and codeload"_test = [] {
        auto registry = make_registry();
        std::array<std::string, 1> enabled{"github"};
        auto rules = registry.build_rules(enabled);
        expect(rules.match("api.github.com").has_value());
        expect(rules.match("codeload.github.com").has_value());
        expect(rules.match("gist.github.com").has_value());
        expect(rules.match("objects.githubusercontent.com").has_value());
    };

    "steam coverage includes stores and cdn"_test = [] {
        auto registry = make_registry();
        std::array<std::string, 1> enabled{"steam"};
        auto rules = registry.build_rules(enabled);
        expect(rules.match("cdn.steamstatic.com").has_value());
        expect(rules.match("login.steampowered.com").has_value());
        expect(rules.match("checkout.steampowered.com").has_value());
        expect(rules.match("cdn.steamcontent.com").has_value());
    };

    return 0;
}
