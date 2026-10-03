module;

#include <cstdlib>

module ghacc.cli;

import std;
import mcpplibs.cmdline;
import ghacc.accel;
import ghacc.app;
import ghacc.session;
import ghacc.tui;

namespace ghacc::app {

using namespace mcpplibs::cmdline;
namespace fs = std::filesystem;

namespace {

// --- argument helpers -----------------------------------------------------

std::optional<std::string> option_value(const ParsedArgs& sub, const ParsedArgs& root,
                                        std::string_view name) {
    if (auto value = sub.option(name); value && value->get().is_set()) return value->get().value();
    if (auto value = root.option(name); value && value->get().is_set()) return value->get().value();
    return std::nullopt;
}

bool flag_set(const ParsedArgs& sub, const ParsedArgs& root, std::string_view name) {
    return sub.is_flag_set(name) || root.is_flag_set(name);
}

RuntimeOptions runtime_options(const ParsedArgs& sub, const ParsedArgs& root) {
    RuntimeOptions options;
    if (auto value = option_value(sub, root, "config")) options.config_path = *value;
    if (auto value = option_value(sub, root, "dir")) options.ca_dir = *value;
    return options;
}

bool apply_port(const std::optional<std::string>& text, std::uint16_t& target, const char* label) {
    if (!text) return true;
    auto parsed = parse_port(*text);
    if (!parsed) {
        std::println(std::cerr, "error: invalid {} port '{}'", label, *text);
        return false;
    }
    target = *parsed;
    return true;
}

std::string provider_list_text(const Config& config) {
    return config.enabled_providers.empty() ? std::string("(none)")
                                            : join(config.enabled_providers, ",");
}

// --- App definition -------------------------------------------------------

// The `global` flag of mcpplibs.cmdline 0.0.2 loses a global option's value
// when a subcommand is present (the subcommand parse moves it out), so the
// standard `--config` / `--dir` options are repeated on every subcommand and
// read from either level.
App with_standard_options(App app) {
    app.option(Option("config").takes_value().value_name("FILE").help(
        "Configuration file (default: platform config dir)"));
    app.option(Option("dir").takes_value().value_name("DIR").help(
        "Certificate authority directory"));
    return app;
}

App make_app() {
    App app = with_standard_options(App("ghacc"));
    app.version(std::string(version));
    app.description("GitHub / Steam network accelerator with Hosts/MITM, system and PAC modes");

    app.subcommand(with_standard_options(
        App("run")
            .description("Start the accelerator")
            .option(Option("mode").takes_value().value_name("MODE").help(
                "hosts | system | pac | forward"))
            .option(Option("provider").takes_value().value_name("LIST").help(
                "Comma separated provider ids"))
            .option(Option("address").takes_value().value_name("IP").help(
                "Listen address (default 127.0.0.1)"))
            .option(Option("http-port").takes_value().value_name("N"))
            .option(Option("https-port").takes_value().value_name("N"))
            .option(Option("proxy-port").takes_value().value_name("N"))
            .option(Option("daemon").short_name('d').help("Detach and run in background"))
            .option(Option("force").help("Replace an existing pid file"))));

    app.subcommand(with_standard_options(
        App("stop").description("Stop a running background instance")));
    app.subcommand(with_standard_options(
        App("tui").description("Open the interactive dashboard")));

    app.subcommand(with_standard_options(
        App("status")
            .description("Show runtime status")
            .option(Option("json").help("Emit machine readable JSON"))));

    app.subcommand(with_standard_options(
        App("provider")
            .description("List or toggle providers")
            .arg(Arg("action"))
            .arg(Arg("id"))));

    app.subcommand(with_standard_options(
        App("ca")
            .description("Manage the local certificate authority")
            .arg(Arg("action"))
            .option(Option("path").takes_value().value_name("FILE"))));

    app.subcommand(with_standard_options(
        App("hosts")
            .description("Manage the hosts takeover block")
            .arg(Arg("action"))
            .option(Option("ip").takes_value().value_name("IP"))
            .option(Option("provider").takes_value().value_name("LIST"))
            .option(Option("path").takes_value().value_name("FILE"))
            .option(Option("backup").takes_value().value_name("FILE"))));

    app.subcommand(with_standard_options(
        App("proxy")
            .description("Set or clear the system proxy")
            .arg(Arg("action"))
            .option(Option("pac").help("Configure the PAC URL instead of a fixed proxy"))
            .option(Option("host").takes_value().value_name("HOST"))
            .option(Option("port").takes_value().value_name("N"))));

    app.subcommand(with_standard_options(
        App("test")
            .description("Resolve a domain through DoH and rank the addresses")
            .arg(Arg("domain"))
            .option(Option("dns").multiple().takes_value().value_name("URL"))));

    app.subcommand(with_standard_options(
        App("config")
            .description("Inspect or edit configuration")
            .arg(Arg("action"))
            .arg(Arg("key"))
            .arg(Arg("value"))));

    app.subcommand(with_standard_options(
        App("completion")
            .description("Print a shell completion script")
            .arg(Arg("shell"))));

    app.subcommand(App("version").description("Print the version"));
    app.subcommand(App("help").description("Show help"));
    return app;
}

// --- commands -------------------------------------------------------------

int command_run(const ParsedArgs& sub, const ParsedArgs& root) {
    RuntimePaths paths = resolve_paths(runtime_options(sub, root));
    std::string warning;
    Config config = load_effective_config(paths, warning);
    if (!warning.empty()) std::println(std::cerr, "warning: {}; using defaults", warning);

    if (auto mode = option_value(sub, root, "mode"); mode) {
        const auto parsed = proxy_mode_from(*mode);
        if (!parsed) {
            std::println(std::cerr, "error: unknown mode '{}'", *mode);
            return 2;
        }
        config.mode = *parsed;
    }
    if (auto providers = option_value(sub, root, "provider"); providers) {
        config.enabled_providers = split(*providers, ',');
    }
    if (auto address = option_value(sub, root, "address"); address) config.listen.address = *address;
    if (!apply_port(option_value(sub, root, "http-port"), config.listen.http_port, "http")) return 2;
    if (!apply_port(option_value(sub, root, "https-port"), config.listen.https_port, "https")) {
        return 2;
    }
    if (!apply_port(option_value(sub, root, "proxy-port"), config.listen.proxy_port, "proxy")) {
        return 2;
    }

    configure_logging(paths, config.log_level);

    auto ca = CertificateAuthority::load_or_create(paths.ca);
    if (!ca) {
        std::println(std::cerr, "error: cannot load CA: {}", ca.error());
        return 1;
    }

    const bool daemon = flag_set(sub, root, "daemon");
    if (daemon) {
        if (auto detached = daemonize(paths.log); !detached) {
            std::println(std::cerr, "error: {}", detached.error());
            return 1;
        }
    }

    if (auto pid = write_pid_file(paths.pid, flag_set(sub, root, "force")); !pid) {
        std::println(std::cerr, "error: {}", pid.error());
        return 1;
    }

    ProviderRegistry registry = make_registry();
    FlowAnalyzer flow;
    RequestLog requests;
    EngineSession session(config, paths, *ca, flow, requests, registry);

    auto started = session.start();
    if (!started) {
        std::println(std::cerr, "error: {} ({})", started.error(), to_string(config.mode));
        if (config.mode == ProxyMode::Hosts) {
            std::println(std::cerr,
                         "hint: binding ports 80/443 needs root or "
                         "`setcap cap_net_bind_service=+eip`");
        }
        remove_pid_file(paths.pid);
        return 1;
    }

    const auto ports = session.ports();
    for (const auto port : ports) {
        std::println("listening on {}:{}", config.listen.address, port);
    }
    if (config.mode == ProxyMode::Pac && !ports.empty()) {
        std::println("PAC: http://{}:{}{}", config.listen.address, ports.back(),
                     config.listen.pac_path);
    }
    std::println("mode '{}', providers: {}", to_string(config.mode), provider_list_text(config));
    session.start_config_watch();
    if (daemon) {
        std::println("ghacc running in background (pid file: {})", paths.pid.string());
    } else {
        std::println("press Ctrl-C to stop");
    }

    session.handle_signals();
    session.wait();
    remove_pid_file(paths.pid);
    return 0;
}

int command_stop(const RuntimePaths& paths) {
    auto result = stop_process(paths.pid, std::chrono::seconds(5));
    if (!result) {
        std::println(std::cerr, "error: {}", result.error());
        return 1;
    }
    std::println("stopped ghacc");
    return 0;
}

int command_status(const ParsedArgs& sub, const RuntimePaths& paths, const Config& config,
                   const ProviderRegistry& registry) {
    const StatusInfo status = gather_status(paths, config, registry);
    if (flag_set(sub, sub, "json")) {
        std::println("{}", to_json(status));
    } else {
        std::print("{}", to_text(status));
    }
    return 0;
}

int command_provider(const ParsedArgs& sub, const RuntimePaths& paths, Config& config,
                     const ProviderRegistry& registry) {
    const std::string action = sub.positional_or(0, "list");
    if (action == "list") {
        std::println("providers:");
        for (const auto& meta : registry.metas()) {
            const bool enabled = std::ranges::find(config.enabled_providers, meta.id) !=
                                 config.enabled_providers.end();
            std::println("  [{}] {:<10} {} ({})", enabled ? "x" : " ", meta.id, meta.display_name,
                         meta.description);
        }
        return 0;
    }
    if (action == "enable" || action == "disable") {
        const std::string id = sub.positional(1);
        if (id.empty()) {
            std::println(std::cerr, "error: 'provider {}' requires an id", action);
            return 2;
        }
        if (registry.find(id) == nullptr) {
            std::println(std::cerr, "error: unknown provider '{}'", id);
            return 2;
        }
        auto& enabled = config.enabled_providers;
        const bool present = std::ranges::find(enabled, id) != enabled.end();
        if (action == "enable") {
            if (!present) enabled.push_back(id);
        } else {
            std::erase(enabled, id);
        }
        if (auto saved = save_config(paths.config, config); !saved) {
            std::println(std::cerr, "error: {}", saved.error());
            return 1;
        }
        std::println("provider '{}' {}", id, action == "enable" ? "enabled" : "disabled");
        return 0;
    }
    std::println(std::cerr, "error: unknown provider action '{}'", action);
    return 2;
}

int command_ca(const ParsedArgs& sub, const RuntimePaths& paths) {
    const std::string action = sub.positional_or(0, "path");

    if (action == "install" || action == "uninstall") {
        const fs::path cert = paths.ca / "ca.crt";
        CaTrustPlatform platform = detect_ca_trust_platform();
        CaTrustManager manager(plan_ca_trust(cert, platform));
        std::println("{} CA via {} ...", action, to_string(platform));
        auto result = action == "install" ? manager.install() : manager.uninstall();
        if (!result) {
            std::println(std::cerr, "error: {}", result.error());
            return 1;
        }
        std::println("CA {} complete", action == "install" ? "trust" : "untrust");
        return 0;
    }

    auto ca = CertificateAuthority::load_or_create(paths.ca);
    if (!ca) {
        std::println(std::cerr, "error: cannot load CA: {}", ca.error());
        return 1;
    }
    if (action == "path") {
        std::println("{}", ca->ca_certificate_path().string());
        return 0;
    }
    if (action == "show") {
        std::print("{}", ca->ca_certificate_pem());
        return 0;
    }
    if (action == "export") {
        const std::optional<std::string> value = option_value(sub, sub, "path");
        const fs::path destination =
            value ? fs::path(*value) : fs::current_path() / "ghacc-ca.crt";
        auto result = ca->export_certificate(destination);
        if (!result) {
            std::println(std::cerr, "error: {}", result.error());
            return 1;
        }
        std::println("exported CA certificate to {}", destination.string());
        return 0;
    }
    std::println(std::cerr, "error: unknown ca action '{}'", action);
    return 2;
}

int command_hosts(const ParsedArgs& sub, const ParsedArgs& root, const RuntimePaths& paths,
                  Config& config) {
    const std::string action = sub.positional_or(0, "show");
    if (auto providers = option_value(sub, root, "provider"); providers) {
        config.enabled_providers = split(*providers, ',');
    }

    const fs::path path = option_value(sub, root, "path")
                              ? fs::path(*option_value(sub, root, "path"))
                              : paths.hosts;
    const fs::path backup = option_value(sub, root, "backup")
                                ? fs::path(*option_value(sub, root, "backup"))
                                : paths.hosts_backup;
    HostsManager manager(path, backup);

    if (action == "show") {
        if (!manager.contains_our_block()) {
            std::println("no ghacc block in {}", path.string());
            return 0;
        }
        for (const auto& entry : manager.current_block()) {
            std::println("{}\t{}", entry.ip, entry.host);
        }
        return 0;
    }
    if (action == "revert") {
        auto result = manager.revert();
        if (!result) {
            std::println(std::cerr, "error: {}", result.error());
            return 1;
        }
        std::println("removed the ghacc block from {}", path.string());
        return 0;
    }
    if (action == "apply") {
        if (!manager.is_writable()) {
            std::println(std::cerr, "error: {} is not writable", path.string());
            std::println(std::cerr, "hint: {}", manager.permission_hint());
            return 1;
        }
        const std::string ip = option_value(sub, root, "ip").value_or(config.listen.address);
        ProviderRegistry registry = make_registry();
        RuleSet rules = build_rules(config, registry);
        std::vector<HostEntry> entries;
        for (const auto& host : rules.hostnames()) entries.push_back({ip, host});
        if (entries.empty()) {
            std::println(std::cerr, "error: no host names to write (enable a provider)");
            return 1;
        }
        auto result = manager.apply(entries);
        if (!result) {
            std::println(std::cerr, "error: {}", result.error());
            return 1;
        }
        std::println("wrote {} entries to {} (backup: {})", entries.size(), path.string(),
                     backup.string());
        return 0;
    }
    std::println(std::cerr, "error: unknown hosts action '{}'", action);
    return 2;
}

int command_proxy(const ParsedArgs& sub, const RuntimePaths& paths, const Config& config) {
    const std::string action = sub.positional_or(0, "set");
    SystemProxyManager manager = SystemProxyManager::detect();
    const std::string host = option_value(sub, sub, "host").value_or(config.listen.address);
    const std::uint16_t port =
        option_value(sub, sub, "port") ? parse_port(*option_value(sub, sub, "port")).value_or(
                                             config.listen.proxy_port)
                                       : config.listen.proxy_port;

    if (action == "set") {
        auto result = flag_set(sub, sub, "pac")
                          ? manager.set_pac(true, "http://" + host + ":" + std::to_string(port) +
                                                      config.listen.pac_path)
                          : manager.set_http(true, host, port);
        if (!result) {
            std::println(std::cerr, "error: {}", result.error());
            return 1;
        }
        std::println("system proxy set via {}", manager.backend_name());
        return 0;
    }
    if (action == "clear") {
        auto result = manager.clear();
        if (!result) {
            std::println(std::cerr, "error: {}", result.error());
            return 1;
        }
        std::println("system proxy cleared via {}", manager.backend_name());
        return 0;
    }
    std::println(std::cerr, "error: unknown proxy action '{}'", action);
    return 2;
}

int command_test(const ParsedArgs& sub, const Config& config) {
    std::string host = sub.positional(0);
    if (host.empty()) {
        std::println(std::cerr, "error: 'test' requires a domain");
        return 2;
    }
    DnsConfig dns = config.dns;
    if (auto option = sub.option("dns"); option && !option->get().values.empty()) {
        dns.doh = option->get().values;
    }

    DnsResolver resolver(dns);
    std::println("resolving {} ...", host);
    const auto ranked = resolver.resolve_ranked(host, 443);
    if (ranked.empty()) {
        std::println(std::cerr, "no addresses for {}", host);
        return 1;
    }
    for (const auto& entry : ranked) {
        if (entry.reachable) {
            std::println("  {:<40} reachable  {:>5} ms", entry.address.to_string(),
                         entry.rtt.count());
        } else {
            std::println("  {:<40} unreachable", entry.address.to_string());
        }
    }
    return 0;
}

std::optional<std::string> config_get_value(const Config& config, std::string_view key) {
    if (key == "mode" || key == "general.mode") return std::string(to_string(config.mode));
    if (key == "log_level" || key == "general.log_level") {
        return std::string(to_string(config.log_level));
    }
    if (key == "listen.address") return config.listen.address;
    if (key == "listen.proxy_port") return std::to_string(config.listen.proxy_port);
    if (key == "listen.http_port") return std::to_string(config.listen.http_port);
    if (key == "listen.https_port") return std::to_string(config.listen.https_port);
    if (key == "listen.pac_path") return config.listen.pac_path;
    if (key == "dns.prefer_ipv6") return std::string(config.dns.prefer_ipv6 ? "true" : "false");
    if (key == "dns.cache_ttl") return std::to_string(config.dns.cache_ttl_seconds);
    if (key == "dns.doh") return join(config.dns.doh, ",");
    if (key == "providers.enabled") return join(config.enabled_providers, ",");
    return std::nullopt;
}

std::expected<void, std::string> config_set_value(Config& config, std::string_view key,
                                                  std::string_view value) {
    if (key == "mode" || key == "general.mode") {
        auto mode = proxy_mode_from(value);
        if (!mode) return std::unexpected("unknown mode '" + std::string(value) + "'");
        config.mode = *mode;
        return {};
    }
    if (key == "log_level" || key == "general.log_level") {
        auto level = log_level_from(value);
        if (!level) return std::unexpected("unknown log level '" + std::string(value) + "'");
        config.log_level = *level;
        return {};
    }
    if (key == "listen.address") {
        config.listen.address = std::string(value);
        return {};
    }
    if (key == "listen.pac_path") {
        config.listen.pac_path = std::string(value);
        return {};
    }
    if (key == "listen.proxy_port" || key == "listen.http_port" || key == "listen.https_port") {
        auto port = parse_port(value);
        if (!port) return std::unexpected("invalid port '" + std::string(value) + "'");
        if (key == "listen.proxy_port") config.listen.proxy_port = *port;
        else if (key == "listen.http_port") config.listen.http_port = *port;
        else config.listen.https_port = *port;
        return {};
    }
    if (key == "dns.prefer_ipv6") {
        if (value == "true" || value == "1" || value == "yes") config.dns.prefer_ipv6 = true;
        else if (value == "false" || value == "0" || value == "no") config.dns.prefer_ipv6 = false;
        else return std::unexpected("expected a boolean for dns.prefer_ipv6");
        return {};
    }
    if (key == "dns.cache_ttl") {
        unsigned ttl = 0;
        const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), ttl);
        if (ec != std::errc{} || ptr != value.data() + value.size()) {
            return std::unexpected("invalid integer '" + std::string(value) + "'");
        }
        config.dns.cache_ttl_seconds = ttl;
        return {};
    }
    if (key == "dns.doh") {
        config.dns.doh = split(value, ',');
        return {};
    }
    if (key == "providers.enabled") {
        config.enabled_providers = split(value, ',');
        return {};
    }
    return std::unexpected("unknown configuration key '" + std::string(key) + "'");
}

int command_config(const ParsedArgs& sub, const RuntimePaths& paths, Config& config) {
    const std::string action = sub.positional_or(0, "path");
    if (action == "path") {
        std::println("{}", paths.config.string());
        return 0;
    }
    if (action == "get") {
        const std::string key = sub.positional(1);
        if (key.empty()) {
            std::print("{}", to_toml(config));
            return 0;
        }
        auto value = config_get_value(config, key);
        if (!value) {
            std::println(std::cerr, "error: unknown key '{}'", key);
            return 2;
        }
        std::println("{}", *value);
        return 0;
    }
    if (action == "set") {
        const std::string key = sub.positional(1);
        const std::string value = sub.positional(2);
        if (key.empty() || value.empty()) {
            std::println(std::cerr, "error: 'config set' requires <key> <value>");
            return 2;
        }
        auto applied = config_set_value(config, key, value);
        if (!applied) {
            std::println(std::cerr, "error: {}", applied.error());
            return 2;
        }
        if (auto saved = save_config(paths.config, config); !saved) {
            std::println(std::cerr, "error: {}", saved.error());
            return 1;
        }
        std::println("{} = {}", key, value);
        return 0;
    }
    if (action == "edit") {
        const char* editor = std::getenv("EDITOR");
        if (editor == nullptr || *editor == '\0') {
            std::println("EDITOR is not set; configuration file: {}", paths.config.string());
            return 0;
        }
        const std::string command = std::string(editor) + " " + paths.config.string();
        return std::system(command.c_str()) == 0 ? 0 : 1;
    }
    std::println(std::cerr, "error: unknown config action '{}'", action);
    return 2;
}

int command_completion(const ParsedArgs& sub) {
    const std::string shell = sub.positional(0);
    const std::string script = completion_script(shell);
    if (script.empty()) {
        std::println(std::cerr, "error: unsupported shell '{}' (bash|zsh|fish)", shell);
        return 2;
    }
    std::print("{}", script);
    return 0;
}

} // namespace

int run_cli(int argc, char** argv) {
    App app = make_app();
    auto parsed = app.parse(argc, argv);
    if (!parsed) {
        if (parsed.error().is_error()) {
            std::println(std::cerr, "error: {}", parsed.error().message);
            return 2;
        }
        return 0;  // --help / --version already printed by the library
    }

    const ParsedArgs& root = *parsed;
    if (!root.has_subcommand()) {
        app.print_help("ghacc");
        return 2;
    }
    const std::string command(root.subcommand_name());
    const ParsedArgs& sub = root.subcommand()->get();

    if (command == "help") {
        app.print_help("ghacc");
        return 0;
    }
    if (command == "version") {
        std::println("ghacc {}", version);
        return 0;
    }

    RuntimePaths paths = resolve_paths(runtime_options(sub, root));
    std::string warning;
    Config config = load_effective_config(paths, warning);

    if (command == "run") return command_run(sub, root);
    if (command == "stop") return command_stop(paths);
    if (command == "tui") return tui::run_tui(paths);
    if (command == "status") {
        ProviderRegistry registry = make_registry();
        return command_status(sub, paths, config, registry);
    }
    if (command == "provider") {
        ProviderRegistry registry = make_registry();
        return command_provider(sub, paths, config, registry);
    }
    if (command == "ca") return command_ca(sub, paths);
    if (command == "hosts") return command_hosts(sub, root, paths, config);
    if (command == "proxy") return command_proxy(sub, paths, config);
    if (command == "test") return command_test(sub, config);
    if (command == "config") return command_config(sub, paths, config);
    if (command == "completion") return command_completion(sub);

    std::println(std::cerr, "error: unknown command '{}'", command);
    return 2;
}

} // namespace ghacc::app
