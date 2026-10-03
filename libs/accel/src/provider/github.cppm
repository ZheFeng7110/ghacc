export module ghacc.accel.provider.github;

import std;
import ghacc.accel.rule;
import ghacc.accel.provider;

export namespace ghacc::accel {

/// Built-in acceleration rules for GitHub.
///
/// The domain set is intentionally a compile-time default and can be extended
/// or overridden through user configuration; see the config provider.
class GitHubProvider final : public IAccelerationProvider {
public:
    [[nodiscard]] ProviderMeta meta() const override {
        return ProviderMeta{
            .id = "github",
            .display_name = "GitHub",
            .description = "Accelerate github.com, raw.githubusercontent.com and related hosts",
            .homepage = "https://github.com",
            .default_enabled = true,
        };
    }

    [[nodiscard]] std::vector<DomainRule> rules() const override {
        static constexpr std::string_view patterns[] = {
            "github.com",
            "*.github.com",
            "github.io",
            "*.github.io",
            "githubassets.com",
            "*.githubassets.com",
            "*.githubusercontent.com",
            "raw.githubusercontent.com",
            "objects.githubusercontent.com",
            "objects-origin.githubusercontent.com",
            "camo.githubusercontent.com",
            "avatars.githubusercontent.com",
            "user-images.githubusercontent.com",
            "github.global.ssl.fastly.net",
            "github.map.fastly.net",
        };

        std::vector<DomainRule> out;
        out.reserve(std::size(patterns));
        for (auto pattern : patterns) {
            DomainRule rule;
            rule.pattern = std::string(pattern);
            rule.provider_id = "github";
            rule.description = "GitHub";
            out.push_back(std::move(rule));
        }
        return out;
    }
};

} // namespace ghacc::accel
