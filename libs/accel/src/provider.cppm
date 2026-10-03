export module ghacc.accel.provider;

import std;
import ghacc.accel.rule;

export namespace ghacc::accel {

struct ProviderMeta {
    std::string id;
    std::string display_name;
    std::string description;
    std::string homepage;
    bool default_enabled = true;
};

/// Opaque context handed to provider lifecycle hooks.
///
/// Kept intentionally minimal for now; the engine will flesh it out with
/// access to configuration and the running proxy once those land.
class ProviderContext {
public:
    virtual ~ProviderContext() = default;
};

/// Optional capability: inject JavaScript into accelerated web pages.
///
/// Not implemented by any built-in provider yet (Steam script injection is a
/// future milestone); the interface only reserves the extension point.
class IScriptInjector {
public:
    virtual ~IScriptInjector() = default;
    [[nodiscard]] virtual bool matches(std::string_view url) const = 0;
    [[nodiscard]] virtual std::string script_for(std::string_view url) const = 0;
};

/// Extension interface for an acceleration target (GitHub, Steam, ...).
class IAccelerationProvider {
public:
    virtual ~IAccelerationProvider() = default;

    [[nodiscard]] virtual ProviderMeta meta() const = 0;

    [[nodiscard]] virtual std::vector<DomainRule> rules() const = 0;

    virtual void on_register(ProviderContext& /*context*/) {}
    virtual void on_start(ProviderContext& /*context*/) {}
    virtual void on_stop(ProviderContext& /*context*/) {}

    [[nodiscard]] virtual std::shared_ptr<IScriptInjector> script_injector() const { return nullptr; }
};

/// Owns the registered providers and compiles their rules.
class ProviderRegistry {
public:
    void add(std::unique_ptr<IAccelerationProvider> provider);

    [[nodiscard]] IAccelerationProvider* find(std::string_view id) const;
    [[nodiscard]] std::vector<IAccelerationProvider*> all() const;
    [[nodiscard]] std::size_t size() const noexcept { return providers_.size(); }
    void clear();

    /// Rules from the named providers, in the order requested.
    [[nodiscard]] RuleSet build_rules(std::span<const std::string> enabled_ids) const;

    /// Rules from every provider whose meta().default_enabled is true.
    [[nodiscard]] RuleSet build_default_rules() const;

    /// All provider metadata, in registration order.
    [[nodiscard]] std::vector<ProviderMeta> metas() const;

private:
    std::vector<std::unique_ptr<IAccelerationProvider>> providers_;
};

} // namespace ghacc::accel
