# Provider 扩展 API

[English](provider-api_en.md) | 简体中文

ghacc 的加速目标以 **provider** 为单位组织。每个 provider 提供一组域名规则（`DomainRule`），
由引擎编译成 `RuleSet` 统一用于 MITM、正向代理与 PAC。

有两种扩展方式：

1. **数据驱动（推荐）**：在 `config.toml` 的 `[[provider.custom]]` 里直接写域名规则，无需重新编译。
2. **编译期**：新增一个 C++ 模块实现 `IAccelerationProvider`，并在应用启动时注册，适合需要
   动态逻辑（例如按环境生成规则、未来的脚本注入）的场景。

> 不支持动态库插件：C++ 模块没有稳定 ABI，跨编译器/版本加载 `.so` 不可移植。

## 接口

定义在 `ghacc.accel.provider`（`libs/accel/src/provider.cppm`）：

```cpp
struct ProviderMeta {
    std::string id;             // 唯一标识，用于配置与 CLI
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

    // 生命周期钩子，均可留空
    virtual void on_register(ProviderContext&) {}
    virtual void on_start(ProviderContext&) {}
    virtual void on_stop(ProviderContext&) {}

    // 可选能力：网页脚本注入（当前未实现任何内置实现）
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

定义在 `ghacc.accel.rule`：

```cpp
struct DomainRule {
    std::string pattern;                 // 匹配模式，见下
    RuleAction action = RuleAction::ReverseProxy;
    bool tls_sni = true;                 // 命中后是否做 TLS 入侵（MITM）
    bool tls_ignore_name_mismatch = false;
    std::string destination;             // 可选：改写目标
    std::string forward_destination;     // 可选：改用该域名解析出的 IP
    std::optional<std::string> ip;       // 固定上游 IP
    std::optional<std::string> user_agent;
    std::chrono::milliseconds timeout{10'000};
    int order = 0;                       // 同具体度时的排序
    std::string provider_id;             // 归属 provider
    std::string description;
};
```

### 模式形态

| 写法 | 含义 |
|---|---|
| `github.com` | 精确主机名（大小写不敏感） |
| `*.githubusercontent.com` | 通配：`*` 匹配任意序列，`?` 匹配单个字符 |
| `/^raw\.github.*$/` | 显式正则（斜杠包裹） |
| `re:^raw\.github.*$` | 显式正则（`re:` 前缀） |

匹配优先级：精确 > 通配 > 正则；同具体度按 `order`。`RuleSet::hostnames()` 会把可写入 hosts
的名称展开（精确名 + `*.suffix` 的基名），正则与中间通配跳过。

### 动作

| `RuleAction` | 行为 |
|---|---|
| `ReverseProxy` | 命中后走本地引擎（MITM / 反向代理） |
| `Tunnel` | 纯 TCP 隧道，不做 TLS 解密 |
| `Block` | 返回 403 / 拒绝 |
| `StaticResponse` | 预留：返回固定响应 |

## 数据驱动扩展

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

启用方式：把 `example` 加入 `[providers].enabled`，或运行
`ghacc provider enable example`。应用会把内置 provider（`github`、`steam`）与此配置合并。

## 编译期 provider

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

然后在 `apps/ghacc/src/app.cpp` 的 `make_registry()` 中注册：

```cpp
registry.add(std::make_unique<GitHubProvider>());
registry.add(std::make_unique<SteamProvider>());
registry.add(std::make_unique<ExampleProvider>());  // 新增
```

同时在 `libs/accel/src/accel.cppm` 里 `export import ghacc.accel.provider.example;`，以便应用侧
可见。

## 生命周期钩子

`on_register` / `on_start` / `on_stop` 接收 `ProviderContext&`。当前 `ProviderContext` 是一个
不透明占位类型，仅用于预留；未来会注入配置与运行中的引擎句柄。

## 脚本注入（预留）

```cpp
class IScriptInjector {
public:
    virtual ~IScriptInjector() = default;
    virtual bool matches(std::string_view url) const = 0;
    virtual std::string script_for(std::string_view url) const = 0;
};
```

内置 provider 目前均返回 `nullptr`。该接口为 Steam 客户端 JS 注入等后续能力预留；一旦引擎实现
HTML 注入，provider 只需实现本接口即可接入。

## 测试

- 规则匹配：使用 `RuleSet::match(host)` 断言命中与动作。
- provider 注册：`ProviderRegistry::build_rules({id})` 后断言规则只来自指定 provider。
- 参考 `libs/accel/tests/provider_test.cpp` 与 `rule_test.cpp`。
