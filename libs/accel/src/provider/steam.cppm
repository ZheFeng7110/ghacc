export module ghacc.accel.provider.steam;

import std;
import ghacc.accel.rule;
import ghacc.accel.provider;

export namespace ghacc::accel {

/// Built-in acceleration rules for Steam (store, community and CDN hosts).
class SteamProvider final : public IAccelerationProvider {
public:
    [[nodiscard]] ProviderMeta meta() const override {
        return ProviderMeta{
            .id = "steam",
            .display_name = "Steam",
            .description = "Accelerate store, community and CDN hosts of Steam",
            .homepage = "https://store.steampowered.com",
            .default_enabled = true,
        };
    }

    [[nodiscard]] std::vector<DomainRule> rules() const override {
        static constexpr std::string_view patterns[] = {
            "steamcommunity.com",
            "*.steamcommunity.com",
            "steampowered.com",
            "*.steampowered.com",
            "store.steampowered.com",
            "api.steampowered.com",
            "login.steampowered.com",
            "checkout.steampowered.com",
            "help.steampowered.com",
            "steamstatic.com",
            "*.steamstatic.com",
            "store.steamstatic.com",
            "cdn.steamstatic.com",
            "community.steamstatic.com",
            "steamcdn-a.akamaihd.net",
            "steamcloud.akamaized.net",
            "steamcontent.com",
            "*.steamcontent.com",
            "steamusercontent.com",
            "*.steamusercontent.com",
        };

        std::vector<DomainRule> out;
        out.reserve(std::size(patterns));
        for (auto pattern : patterns) {
            DomainRule rule;
            rule.pattern = std::string(pattern);
            rule.provider_id = "steam";
            rule.description = "Steam";
            out.push_back(std::move(rule));
        }
        return out;
    }
};

} // namespace ghacc::accel
