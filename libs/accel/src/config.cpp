module ghacc.accel.config;

import std;
import ghacc.accel.log;
import ghacc.accel.rule;
import tomlplusplus;

namespace ghacc::accel {

std::string_view to_string(ProxyMode mode) noexcept {
    switch (mode) {
        case ProxyMode::Hosts:       return "hosts";
        case ProxyMode::System:      return "system";
        case ProxyMode::Pac:         return "pac";
        case ProxyMode::ForwardOnly: return "forward";
    }
    return "hosts";
}

std::optional<ProxyMode> proxy_mode_from(std::string_view text) noexcept {
    if (text == "hosts" || text == "mitm") return ProxyMode::Hosts;
    if (text == "system") return ProxyMode::System;
    if (text == "pac") return ProxyMode::Pac;
    if (text == "forward" || text == "forward_only" || text == "proxy") return ProxyMode::ForwardOnly;
    return std::nullopt;
}

namespace {

std::optional<LogLevel> log_level_from(std::string_view text) noexcept {
    if (text == "debug") return LogLevel::Debug;
    if (text == "info") return LogLevel::Info;
    if (text == "warn" || text == "warning") return LogLevel::Warn;
    if (text == "error") return LogLevel::Error;
    return std::nullopt;
}

template <class T>
std::optional<T> get_value(const toml::table& table, std::string_view key) {
    if (auto value = table[key].value<T>()) return value;
    return std::nullopt;
}

std::string get_string(const toml::table& table, std::string_view key, std::string fallback) {
    if (auto value = table[key].value<std::string>()) return *value;
    return fallback;
}

bool get_bool(const toml::table& table, std::string_view key, bool fallback) {
    if (auto value = table[key].value<bool>()) return *value;
    return fallback;
}

std::int64_t get_int(const toml::table& table, std::string_view key, std::int64_t fallback) {
    if (auto value = table[key].value<std::int64_t>()) return *value;
    return fallback;
}

std::vector<std::string> get_string_array(const toml::table& table, std::string_view key) {
    std::vector<std::string> out;
    if (auto* array = table[key].as_array()) {
        for (const auto& element : *array) {
            if (auto value = element.value<std::string>()) out.push_back(*value);
        }
    }
    return out;
}

DomainRule parse_rule(const toml::table& table) {
    DomainRule rule;
    rule.pattern = get_string(table, "pattern", "");
    if (auto action = rule_action_from(get_string(table, "action", "reverse_proxy"))) {
        rule.action = *action;
    }
    rule.tls_sni = get_bool(table, "tls_sni", rule.tls_sni);
    rule.tls_ignore_name_mismatch =
        get_bool(table, "tls_ignore_name_mismatch", rule.tls_ignore_name_mismatch);
    rule.destination = get_string(table, "destination", "");
    rule.forward_destination = get_string(table, "forward_destination", "");
    if (auto ip = table["ip"].value<std::string>()) rule.ip = *ip;
    if (auto ua = table["user_agent"].value<std::string>()) rule.user_agent = *ua;
    rule.timeout = std::chrono::milliseconds{
        get_int(table, "timeout_ms", static_cast<std::int64_t>(rule.timeout.count()))};
    rule.order = static_cast<int>(get_int(table, "order", rule.order));
    rule.description = get_string(table, "description", "");
    return rule;
}

toml::table rule_to_table(const DomainRule& rule) {
    toml::table table;
    table.insert("pattern", rule.pattern);
    table.insert("action", std::string(to_string(rule.action)));
    table.insert("tls_sni", rule.tls_sni);
    if (rule.tls_ignore_name_mismatch) table.insert("tls_ignore_name_mismatch", true);
    if (!rule.destination.empty()) table.insert("destination", rule.destination);
    if (!rule.forward_destination.empty()) table.insert("forward_destination", rule.forward_destination);
    if (rule.ip) table.insert("ip", *rule.ip);
    if (rule.user_agent) table.insert("user_agent", *rule.user_agent);
    table.insert("timeout_ms", static_cast<std::int64_t>(rule.timeout.count()));
    table.insert("order", static_cast<std::int64_t>(rule.order));
    if (!rule.description.empty()) table.insert("description", rule.description);
    return table;
}

} // namespace

Config default_config() { return Config{}; }

std::expected<Config, std::string> parse_config(std::string_view toml_text) {
    Config config = default_config();

    toml::table root;
    try {
        root = toml::parse(toml_text);
    } catch (const toml::parse_error& error) {
        return std::unexpected(std::string("TOML parse error: ") + std::string(error.description()));
    }

    if (auto* general = root["general"].as_table()) {
        if (auto mode = proxy_mode_from(get_string(*general, "mode", "hosts"))) config.mode = *mode;
        if (auto level = log_level_from(get_string(*general, "log_level", "info"))) {
            config.log_level = *level;
        }
    }

    if (auto* listen = root["listen"].as_table()) {
        config.listen.address = get_string(*listen, "address", config.listen.address);
        config.listen.proxy_port = static_cast<std::uint16_t>(
            get_int(*listen, "proxy_port", config.listen.proxy_port));
        config.listen.http_port =
            static_cast<std::uint16_t>(get_int(*listen, "http_port", config.listen.http_port));
        config.listen.https_port =
            static_cast<std::uint16_t>(get_int(*listen, "https_port", config.listen.https_port));
    }

    if (auto* dns = root["dns"].as_table()) {
        if (auto doh = get_string_array(*dns, "doh"); !doh.empty()) config.dns.doh = std::move(doh);
        config.dns.prefer_ipv6 = get_bool(*dns, "prefer_ipv6", config.dns.prefer_ipv6);
        config.dns.cache_ttl_seconds = static_cast<std::uint32_t>(
            get_int(*dns, "cache_ttl", config.dns.cache_ttl_seconds));
    }

    if (auto* providers = root["providers"].as_table()) {
        if (auto enabled = get_string_array(*providers, "enabled"); !enabled.empty()) {
            config.enabled_providers = std::move(enabled);
        }
    }

    if (auto* provider = root["provider"].as_table()) {
        if (auto* custom = (*provider)["custom"].as_array()) {
            for (const auto& element : *custom) {
                if (auto* table = element.as_table()) {
                    CustomProviderConfig entry;
                    entry.id = get_string(*table, "id", "");
                    entry.name = get_string(*table, "name", entry.id);
                    if (auto* rules = (*table)["rules"].as_array()) {
                        for (const auto& rule_element : *rules) {
                            if (auto* rule_table = rule_element.as_table()) {
                                auto rule = parse_rule(*rule_table);
                                if (!rule.pattern.empty()) {
                                    rule.provider_id = entry.id;
                                    entry.rules.push_back(std::move(rule));
                                }
                            }
                        }
                    }
                    if (!entry.id.empty()) config.custom_providers.push_back(std::move(entry));
                }
            }
        }
    }

    return config;
}

std::string to_toml(const Config& config) {
    toml::table root;

    toml::table general;
    general.insert("mode", std::string(to_string(config.mode)));
    general.insert("log_level", std::string(to_string(config.log_level)));
    root.insert("general", std::move(general));

    toml::table listen;
    listen.insert("address", config.listen.address);
    listen.insert("proxy_port", static_cast<std::int64_t>(config.listen.proxy_port));
    listen.insert("http_port", static_cast<std::int64_t>(config.listen.http_port));
    listen.insert("https_port", static_cast<std::int64_t>(config.listen.https_port));
    root.insert("listen", std::move(listen));

    toml::table dns;
    toml::array doh;
    for (const auto& server : config.dns.doh) doh.push_back(server);
    dns.insert("doh", std::move(doh));
    dns.insert("prefer_ipv6", config.dns.prefer_ipv6);
    dns.insert("cache_ttl", static_cast<std::int64_t>(config.dns.cache_ttl_seconds));
    root.insert("dns", std::move(dns));

    toml::table providers;
    toml::array enabled;
    for (const auto& id : config.enabled_providers) enabled.push_back(id);
    providers.insert("enabled", std::move(enabled));
    root.insert("providers", std::move(providers));

    if (!config.custom_providers.empty()) {
        toml::array custom;
        for (const auto& provider : config.custom_providers) {
            toml::table entry;
            entry.insert("id", provider.id);
            entry.insert("name", provider.name);
            toml::array rules;
            for (const auto& rule : provider.rules) rules.push_back(rule_to_table(rule));
            entry.insert("rules", std::move(rules));
            custom.push_back(std::move(entry));
        }
        toml::table provider_section;
        provider_section.insert("custom", std::move(custom));
        root.insert("provider", std::move(provider_section));
    }

    std::ostringstream stream;
    stream << toml::toml_formatter{root};
    return stream.str();
}

std::expected<Config, std::string> load_config(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return default_config();

    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::unexpected("cannot open config file: " + path.string());

    std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    return parse_config(text);
}

std::expected<void, std::string> save_config(const std::filesystem::path& path,
                                             const Config& config) {
    std::error_code ec;
    if (auto parent = path.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) return std::unexpected("cannot create config directory: " + parent.string());
    }

    const auto temporary = path.string() + ".tmp";
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream) return std::unexpected("cannot write config file: " + temporary);
        stream << to_toml(config);
        if (!stream) return std::unexpected("failed writing config file: " + temporary);
    }

    std::filesystem::rename(temporary, path, ec);
    if (ec) {
        std::filesystem::remove(temporary, ec);
        return std::unexpected("cannot replace config file: " + path.string());
    }
    return {};
}

std::filesystem::path default_config_path() {
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA"); appdata != nullptr) {
        return std::filesystem::path(appdata) / "ghacc" / "config.toml";
    }
    return std::filesystem::path("ghacc") / "config.toml";
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME"); home != nullptr) {
        return std::filesystem::path(home) / "Library" / "Application Support" / "ghacc" /
               "config.toml";
    }
    return std::filesystem::path("ghacc") / "config.toml";
#else
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg != nullptr && *xdg != '\0') {
        return std::filesystem::path(xdg) / "ghacc" / "config.toml";
    }
    if (const char* home = std::getenv("HOME"); home != nullptr) {
        return std::filesystem::path(home) / ".config" / "ghacc" / "config.toml";
    }
    return std::filesystem::path("ghacc") / "config.toml";
#endif
}

} // namespace ghacc::accel
