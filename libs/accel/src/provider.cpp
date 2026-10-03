module ghacc.accel.provider;

import std;

namespace ghacc::accel {

void ProviderRegistry::add(std::unique_ptr<IAccelerationProvider> provider) {
    if (provider) providers_.push_back(std::move(provider));
}

IAccelerationProvider* ProviderRegistry::find(std::string_view id) const {
    for (const auto& provider : providers_) {
        if (provider->meta().id == id) return provider.get();
    }
    return nullptr;
}

std::vector<IAccelerationProvider*> ProviderRegistry::all() const {
    std::vector<IAccelerationProvider*> out;
    out.reserve(providers_.size());
    for (const auto& provider : providers_) out.push_back(provider.get());
    return out;
}

void ProviderRegistry::clear() { providers_.clear(); }

RuleSet ProviderRegistry::build_rules(std::span<const std::string> enabled_ids) const {
    RuleSet set;
    for (const auto& id : enabled_ids) {
        auto* provider = find(id);
        if (provider == nullptr) continue;
        for (auto& rule : provider->rules()) {
            if (rule.provider_id.empty()) rule.provider_id = provider->meta().id;
            set.add(std::move(rule));
        }
    }
    return set;
}

RuleSet ProviderRegistry::build_default_rules() const {
    RuleSet set;
    for (const auto& provider : providers_) {
        auto meta = provider->meta();
        if (!meta.default_enabled) continue;
        for (auto& rule : provider->rules()) {
            if (rule.provider_id.empty()) rule.provider_id = meta.id;
            set.add(std::move(rule));
        }
    }
    return set;
}

std::vector<ProviderMeta> ProviderRegistry::metas() const {
    std::vector<ProviderMeta> out;
    out.reserve(providers_.size());
    for (const auto& provider : providers_) out.push_back(provider->meta());
    return out;
}

} // namespace ghacc::accel
