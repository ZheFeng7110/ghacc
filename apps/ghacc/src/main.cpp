import std;
import asio;
import ghacc.accel;

using namespace ghacc::accel;

namespace {

// --- tiny argument helpers ------------------------------------------------

std::optional<std::string_view> option(const std::vector<std::string>& args,
                                       std::string_view name) {
    for (std::size_t i = 0; i + 1 < args.size(); ++i) {
        if (args[i] == name) return args[i + 1];
    }
    return std::nullopt;
}

bool has_flag(const std::vector<std::string>& args, std::string_view name) {
    return std::ranges::find(args, name) != args.end();
}

std::uint16_t port_option(const std::vector<std::string>& args, std::string_view name,
                          std::uint16_t fallback) {
    const auto value = option(args, name);
    if (!value) return fallback;
    unsigned parsed = 0;
    const auto [ptr, ec] =
        std::from_chars(value->data(), value->data() + value->size(), parsed);
    if (ec != std::errc{} || ptr != value->data() + value->size() || parsed > 65535) {
        return fallback;
    }
    return static_cast<std::uint16_t>(parsed);
}

std::vector<std::string> split(std::string_view text, char separator) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto end = text.find(separator, start);
        const auto part = text.substr(start, end == std::string_view::npos ? std::string_view::npos
                                                                           : end - start);
        if (!part.empty()) out.emplace_back(part);
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return out;
}

Config load_effective_config(const std::vector<std::string>& args) {
    const auto path = option(args, "--config");
    auto loaded = load_config(path ? std::filesystem::path(*path) : default_config_path());
    if (!loaded) {
        std::println(std::cerr, "warning: {}; using defaults", loaded.error());
        return default_config();
    }
    return *loaded;
}

std::filesystem::path ca_directory(const std::vector<std::string>& args) {
    if (const auto dir = option(args, "--dir"); dir) return std::filesystem::path(*dir);
    return default_config_path().parent_path() / "ca";
}

RuleSet build_rules(const Config& config) {
    ProviderRegistry registry;
    registry.add(std::make_unique<GitHubProvider>());
    registry.add(std::make_unique<SteamProvider>());
    RuleSet rules = registry.build_rules(config.enabled_providers);
    for (const auto& custom : config.custom_providers) {
        for (auto rule : custom.rules) {
            if (rule.provider_id.empty()) rule.provider_id = custom.id;
            rules.add(std::move(rule));
        }
    }
    return rules;
}

void print_usage() {
    std::println("usage:");
    std::println("  ghacc run     [--mode hosts|system|pac|forward] [--provider a,b]");
    std::println("                [--address IP] [--http-port N] [--https-port N]");
    std::println("                [--proxy-port N] [--config FILE]");
    std::println("  ghacc hosts   show|apply|revert [--ip IP] [--provider a,b] [--path FILE]");
    std::println("  ghacc ca      path|show|export [--path FILE] [--dir DIR]");
    std::println("  ghacc test    <domain>     resolve a domain through DoH and rank addresses");
    std::println("  ghacc version");
}

// --- commands -------------------------------------------------------------

int command_run(const std::vector<std::string>& args) {
    Config config = load_effective_config(args);
    if (const auto mode = option(args, "--mode"); mode) {
        const auto parsed = proxy_mode_from(*mode);
        if (!parsed) {
            std::println(std::cerr, "error: unknown mode '{}'", *mode);
            return 2;
        }
        config.mode = *parsed;
    }
    if (const auto providers = option(args, "--provider"); providers) {
        config.enabled_providers = split(*providers, ',');
    }
    if (const auto address = option(args, "--address"); address) config.listen.address = *address;
    config.listen.http_port = port_option(args, "--http-port", config.listen.http_port);
    config.listen.https_port = port_option(args, "--https-port", config.listen.https_port);
    config.listen.proxy_port = port_option(args, "--proxy-port", config.listen.proxy_port);

    Log::instance().set_level(config.log_level);

    auto ca = CertificateAuthority::load_or_create(ca_directory(args));
    if (!ca) {
        std::println(std::cerr, "error: cannot load CA: {}", ca.error());
        return 1;
    }

    RuleSet rules = build_rules(config);
    if (rules.empty()) {
        std::println(std::cerr, "warning: no acceleration rules enabled");
    }

    EngineOptions options = engine_options_from_config(config);
    FlowAnalyzer flow;
    RequestLog requests;

    asio::io_context io;
    ProxyEngine engine(io, options, std::move(rules), *ca, flow, requests);
    try {
        engine.start();
    } catch (const std::exception& error) {
        std::println(std::cerr, "error: {} ({})", error.what(), to_string(config.mode));
        if (config.mode == ProxyMode::Hosts) {
            std::println(std::cerr,
                         "hint: binding ports 80/443 needs root or "
                         "`setcap cap_net_bind_service=+eip`");
        }
        return 1;
    }

    for (const auto port : engine.listening_ports()) {
        std::println("listening on {}:{}", config.listen.address, port);
    }
    if (options.enable_pac) {
        // The forward listener is bound last; report its actual port (a 0
        // request means "pick one" and the engine fills it in).
        const auto bound = engine.listening_ports();
        const std::uint16_t forward_port =
            bound.empty() ? options.proxy_port : bound.back();
        std::println("PAC: http://{}:{}{}", config.listen.address, forward_port,
                     config.listen.pac_path);
    }
    std::println("mode '{}', providers: {}", to_string(config.mode),
                 config.enabled_providers.empty()
                     ? std::string("(none)")
                     : std::ranges::fold_left(config.enabled_providers, std::string{},
                                              [](std::string acc, const std::string& id) {
                                                  return acc.empty() ? id : acc + "," + id;
                                              }));
    std::println("press Ctrl-C to stop");

    asio::signal_set signals(io, 2 /* SIGINT */, 15 /* SIGTERM */);
    signals.async_wait([&engine](const std::error_code&, int) { engine.request_stop(); });
    io.run();
    return 0;
}

int command_hosts(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::println(std::cerr, "error: 'hosts' requires show|apply|revert");
        return 2;
    }
    const std::string& action = args[1];

    Config config = load_effective_config(args);
    if (const auto providers = option(args, "--provider"); providers) {
        config.enabled_providers = split(*providers, ',');
    }

    const std::filesystem::path path =
        option(args, "--path") ? std::filesystem::path(*option(args, "--path"))
                               : HostsManager::default_path();
    const std::filesystem::path backup =
        option(args, "--backup") ? std::filesystem::path(*option(args, "--backup"))
                                 : HostsManager::default_backup_path();
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
        const std::string ip = option(args, "--ip") ? std::string(*option(args, "--ip"))
                                                    : config.listen.address;
        RuleSet rules = build_rules(config);
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

int command_ca(const std::vector<std::string>& args) {
    auto ca = CertificateAuthority::load_or_create(ca_directory(args));
    if (!ca) {
        std::println(std::cerr, "error: cannot load CA: {}", ca.error());
        return 1;
    }

    const std::string action = args.size() >= 2 ? args[1] : "path";
    if (action == "path") {
        std::println("{}", ca->ca_certificate_path().string());
        return 0;
    }
    if (action == "show") {
        std::print("{}", ca->ca_certificate_pem());
        return 0;
    }
    if (action == "export") {
        const std::filesystem::path destination =
            option(args, "--path") ? std::filesystem::path(*option(args, "--path"))
                                   : std::filesystem::current_path() / "ghacc-ca.crt";
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

int command_test(std::string host) {
    DnsResolver resolver(DnsConfig{});
    std::println("resolving {} ...", host);
    const auto ranked = resolver.resolve_ranked(host, 443);
    if (ranked.empty()) {
        std::println(std::cerr, "no addresses for {}", host);
        return 1;
    }
    for (const auto& entry : ranked) {
        if (entry.reachable) {
            std::println("  {:<40} reachable  {:>5} ms", entry.address.to_string(), entry.rtt.count());
        } else {
            std::println("  {:<40} unreachable", entry.address.to_string());
        }
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.empty()) {
        std::println("ghacc {} — network accelerator", version);
        print_usage();
        return 0;
    }

    const std::string& command = args[0];
    if (command == "version" || command == "--version" || command == "-V") {
        std::println("ghacc {}", version);
        return 0;
    }
    if (command == "run") return command_run(args);
    if (command == "hosts") return command_hosts(args);
    if (command == "ca") return command_ca(args);
    if (command == "test") {
        if (args.size() < 2) {
            std::println(std::cerr, "error: 'test' requires a domain");
            return 2;
        }
        return command_test(args[1]);
    }
    if (command == "help" || command == "--help" || command == "-h") {
        print_usage();
        return 0;
    }

    std::println(std::cerr, "error: unknown command '{}'", command);
    print_usage();
    return 2;
}
