# Provider extension API

English | [简体中文](provider-api.md)

ghacc organises acceleration targets as **providers**. Each provider contributes a set of domain
rules (`DomainRule`) that the engine compiles into a single `RuleSet` used by MITM, the forward
proxy, and PAC.

There are two extension paths:

1. **Data-driven (recommended)**: write domain rules directly under `[[provider.custom]]` in
   `config.toml`; no rebuild required.
2. **Compile-time**: add a C++ module implementing `IAccelerationProvider` and register it at
   startup, for targets that need dynamic logic (for example environment-dependent rules, or
   future script injection).

> Dynamic library plugins are not supported: C++ modules have no stable ABI, and loading a `.so`
> across compilers/versions is not portable.

## Interface

Declared in `ghacc.accel.provider` (`libs/accel/src/provider.cppm`):

```cpp
struct ProviderMeta {
    std::string id;             // unique id used by config and the CLI
    std::string display_name;
    std::string description;
    std::string homepage;
    bool default_enabled = true;
};

class IAccelerationProvider {
public:
    virtual ~IAccelerationProvider() = default;

    virtual ProviderMeta meta() const = 0;
    virtual std::vector<DomainRule> rules() const = 0;

    // Lifecycle hooks; all optional
    virtual void on_register(ProviderContext&) {}
    virtual void on_start(ProviderContext&) {}
    virtual void on_stop(ProviderContext&) {}

    // Optional capability: web page script injection (no built-in implementation yet)
    virtual std::shared_ptr<IScriptInjector> script_injector() const { return nullptr; }
};

class ProviderRegistry {
public:
    void add(std::unique_ptr<IAccelerationProvider> provider);
    IAccelerationProvider* find(std::string_view id) const;
    std::vector<IAccelerationProvider*> all() const;
    RuleSet build_rules(std::span<const std::string> enabled_ids) const;
    RuleSet build_default_rules() const;
    std::vector<ProviderMeta> metas() const;
};
```

## DomainRule

Declared in `ghacc.accel.rule`:

```cpp
struct DomainRule {
    std::string pattern;                 // pattern form, see below
    RuleAction action = RuleAction::ReverseProxy;
    bool tls_sni = true;                 // intercept TLS (MITM) when matched
    bool tls_ignore_name_mismatch = false;
    std::string destination;             // optional rewrite target
    std::string forward_destination;     // optional: resolve IPs from this host
    std::optional<std::string> ip;       // fixed upstream IP
    std::optional<std::string> user_agent;
    std::chrono::milliseconds timeout{10'000};
    int order = 0;                       // tie-break among equally specific rules
    std::string provider_id;
    std::string description;
};
```

### Pattern forms

| Form | Meaning |
|---|---|
| `github.com` | exact host (case-insensitive) |
| `*.githubusercontent.com` | wildcard: `*` matches any run, `?` one character |
| `/^raw\.github.*$/` | explicit regex (slash-delimited) |
| `re:^raw\.github.*$` | explicit regex (`re:` prefix) |

Precedence: exact > wildcard > regex; ties break on `order`. `RuleSet::hostnames()` expands the
names that can be written to hosts (exact names plus the apex of `*.suffix`); regex and middle
wildcards are skipped.

### Actions

| `RuleAction` | Behaviour |
|---|---|
| `ReverseProxy` | route through the local engine (MITM / reverse proxy) |
| `Tunnel` | plain TCP tunnel, no TLS interception |
| `Block` | return 403 / reject |
| `StaticResponse` | reserved: return a canned response |

## Data-driven extension

```toml
[[provider.custom]]
id = "example"
name = "Example"
[[provider.custom.rules]]
pattern = "*.example.com"
action = "reverse_proxy"     # reverse_proxy | tunnel | block | static_response
tls_sni = true
timeout_ms = 10000
order = 0
```

Enable it by adding `example` to `[providers].enabled` or running
`ghacc provider enable example`. The application merges the built-in providers (`github`, `steam`)
with this configuration.

## Compile-time provider

```cpp
// libs/accel/src/provider/example.cppm
export module ghacc.accel.provider.example;

import std;
import ghacc.accel.rule;
import ghacc.accel.provider;

export namespace ghacc::accel {

class ExampleProvider final : public IAccelerationProvider {
public:
    ProviderMeta meta() const override {
        return ProviderMeta{.id = "example", .display_name = "Example",
                            .description = "example.com", .homepage = "https://example.com"};
    }
    std::vector<DomainRule> rules() const override {
        DomainRule rule;
        rule.pattern = "*.example.com";
        rule.provider_id = "example";
        return {rule};
    }
};

} // namespace ghacc::accel
```

Then register it in `make_registry()` in `apps/ghacc/src/app.cpp`:

```cpp
registry.add(std::make_unique<GitHubProvider>());
registry.add(std::make_unique<SteamProvider>());
registry.add(std::make_unique<ExampleProvider>());  // new
```

Also add `export import ghacc.accel.provider.example;` to `libs/accel/src/accel.cppm` so the
application can see it.

## Lifecycle hooks

`on_register` / `on_start` / `on_stop` receive a `ProviderContext&`. Today `ProviderContext` is an
opaque placeholder; in the future it will expose configuration and a handle to the running engine.

## Script injection (reserved)

```cpp
class IScriptInjector {
public:
    virtual ~IScriptInjector() = default;
    virtual bool matches(std::string_view url) const = 0;
    virtual std::string script_for(std::string_view url) const = 0;
};
```

Every built-in provider currently returns `nullptr`. The interface reserves the extension point for
Steam client JS injection; once the engine implements HTML injection a provider only has to
implement this interface.

## Testing

- Rule matching: assert matches and actions with `RuleSet::match(host)`.
- Provider registration: `ProviderRegistry::build_rules({id})` and assert rules come only from that
  provider.
- See `libs/accel/tests/provider_test.cpp` and `rule_test.cpp`.
