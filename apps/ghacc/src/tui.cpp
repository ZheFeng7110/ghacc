module ghacc.tui;

import std;
import ftxui;
import ghacc.accel;
import ghacc.app;
import ghacc.session;

namespace ghacc::app::tui {

namespace {

namespace fs = std::filesystem;

std::string human_bytes(std::uint64_t bytes) {
    constexpr double unit = 1024.0;
    const char* suffixes[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    int index = 0;
    while (value >= unit && index < 4) {
        value /= unit;
        ++index;
    }
    return std::format("{:.1f} {}", value, suffixes[index]);
}

std::string human_rate(double bytes_per_second) {
    return human_bytes(static_cast<std::uint64_t>(bytes_per_second)) + "/s";
}

std::string short_time(std::chrono::system_clock::time_point time) {
    const auto seconds = std::chrono::floor<std::chrono::seconds>(time);
    const auto days = std::chrono::floor<std::chrono::days>(seconds);
    const std::chrono::hh_mm_ss clock{seconds - days};
    return std::format("{:02}:{:02}:{:02}", clock.hours().count(), clock.minutes().count(),
                       clock.seconds().count());
}

float progress(double rate) {
    constexpr double scale = 1024.0 * 1024.0;  // full bar = 1 MiB/s
    return static_cast<float>(std::clamp(rate / scale, 0.0, 1.0));
}

} // namespace

ftxui::Element render_dashboard(const DashboardState& state) {
    using namespace ftxui;

    const auto& status = state.status;
    const bool running = status.running;
    Element title = hbox({
        text(" ghacc ") | bold,
        text(status.version) | dim,
        separator(),
        text("mode: " + status.mode),
        separator(),
        text(running ? "running" : "stopped") | color(running ? Color::Green : Color::Red),
        filler(),
        text(status.address + ":" + std::to_string(status.proxy_port)) | dim,
    });

    Elements provider_rows;
    for (const auto& [id, enabled] : state.providers) {
        provider_rows.push_back(hbox({
            text(enabled ? "[x] " : "[ ] ") | color(enabled ? Color::Green : Color::GrayDark),
            text(id),
        }));
    }
    if (provider_rows.empty()) provider_rows.push_back(text("(none)") | dim);
    Element providers_panel = window(text("Providers"), vbox(std::move(provider_rows)));

    Element traffic_panel = window(
        text("Traffic"),
        vbox({
            hbox({text("Down "), filler(), text(human_rate(state.flow.read_rate)) | bold}),
            gauge(progress(state.flow.read_rate)) | color(Color::Cyan),
            hbox({text("Up   "), filler(), text(human_rate(state.flow.write_rate)) | bold}),
            gauge(progress(state.flow.write_rate)) | color(Color::Yellow),
            separator(),
            text("total down " + human_bytes(state.flow.total_read)) | dim,
            text("total up   " + human_bytes(state.flow.total_write)) | dim,
        }));

    Elements request_rows;
    request_rows.push_back(text("time      method  host                      status  upstream") | dim);
    for (const auto& record : state.requests) {
        const std::string line = std::format("{}  {:<6}  {:<24}  {:>4}   {}",
                                             short_time(record.time), record.method, record.host,
                                             record.status, record.upstream);
        Element row = text(line);
        if (record.accelerated) row = row | color(Color::Green);
        request_rows.push_back(std::move(row));
    }
    if (state.requests.empty()) request_rows.push_back(text("no requests yet") | dim);
    Element requests_panel = window(text("Requests"), vbox(std::move(request_rows)) | flex);

    Element footer = hbox({
        text("[s] start/stop") | dim,
        text("  "),
        text("[p] pause") | dim,
        text("  "),
        text("[r] clear") | dim,
        text("  "),
        text("[m] mode") | dim,
        text("  "),
        text("[c] trust CA") | dim,
        text("  "),
        text("[h] hosts") | dim,
        text("  "),
        text("[q] quit") | dim,
        filler(),
        text(state.paused ? "PAUSED" : "") | color(Color::Yellow),
    });

    Elements body;
    body.push_back(title);
    body.push_back(hbox({providers_panel, traffic_panel | flex}));
    body.push_back(requests_panel | flex);
    if (!state.message.empty()) body.push_back(text(state.message) | color(Color::Yellow));
    body.push_back(footer);
    return vbox(std::move(body)) | border;
}

int run_tui(const RuntimePaths& paths) {
    std::string warning;
    Config config = load_effective_config(paths, warning);
    configure_logging(paths, config.log_level);
    if (!warning.empty()) log_warn("config", warning);

    ProviderRegistry registry = make_registry();
    auto ca = CertificateAuthority::load_or_create(paths.ca);
    if (!ca) {
        std::println(std::cerr, "error: cannot load CA: {}", ca.error());
        return 1;
    }

    FlowAnalyzer flow;
    RequestLog requests;
    EngineSession session(config, paths, *ca, flow, requests, registry);

    std::string message;
    if (auto started = session.start(); !started) {
        message = "engine not started: " + started.error();
        log_warn("tui", message);
    } else {
        session.start_config_watch();
    }

    using namespace ftxui;
    auto screen = ScreenInteractive::Fullscreen();
    std::atomic<bool> paused{false};

    DashboardState state;
    auto build = [&]() -> Element {
        state.status = gather_status(paths, config, registry);
        state.flow = flow.snapshot();
        state.requests = requests.tail(64);
        state.logs = Log::instance().tail(64);
        state.providers.clear();
        for (const auto& meta : registry.metas()) {
            const bool enabled =
                std::ranges::find(config.enabled_providers, meta.id) !=
                config.enabled_providers.end();
            state.providers.emplace_back(meta.id, enabled);
        }
        state.paused = paused.load();
        state.message = message;
        return render_dashboard(state);
    };

    auto apply_hosts = [&]() {
        ProviderRegistry local = make_registry();
        RuleSet rules = build_rules(config, local);
        std::vector<HostEntry> entries;
        for (const auto& host : rules.hostnames()) entries.push_back({config.listen.address, host});
        HostsManager manager(paths.hosts, paths.hosts_backup);
        if (!manager.is_writable()) {
            message = "hosts: " + manager.permission_hint();
            return;
        }
        auto result = manager.apply(entries);
        message = result ? std::format("hosts: applied {} entries", entries.size())
                         : "hosts: " + result.error();
    };

    auto trust_ca = [&]() {
        const fs::path cert = paths.ca / "ca.crt";
        CaTrustManager manager(plan_ca_trust(cert, detect_ca_trust_platform()));
        auto result = manager.install();
        message = result ? "CA trusted" : "CA: " + result.error();
    };

    auto toggle_engine = [&]() {
        if (session.running()) {
            session.stop();
            message = "engine stopped";
        } else {
            auto started = session.start();
            if (started) {
                session.start_config_watch();
                message = "engine started";
            } else {
                message = "engine: " + started.error();
            }
        }
    };

    auto cycle_mode = [&]() {
        constexpr ProxyMode order[] = {ProxyMode::Hosts, ProxyMode::System, ProxyMode::Pac,
                                       ProxyMode::ForwardOnly};
        int index = 0;
        for (int i = 0; i < 4; ++i) {
            if (order[i] == config.mode) index = i;
        }
        config.mode = order[(index + 1) % 4];
        if (auto saved = save_config(paths.config, config); !saved) {
            message = "config: " + saved.error();
        } else {
            message = std::format("mode -> {} (restart to apply listeners)",
                                  to_string(config.mode));
        }
    };

    auto component = Renderer(build);
    component = CatchEvent(component, [&](Event event) {
        if (event == Event::Character('q') || event == Event::Character('Q') ||
            event == Event::Escape) {
            screen.Exit();
            return true;
        }
        if (event == Event::Character('p')) {
            paused.store(!paused.load());
            return true;
        }
        if (event == Event::Character('r')) {
            requests.clear();
            return true;
        }
        if (event == Event::Character('s')) {
            toggle_engine();
            return true;
        }
        if (event == Event::Character('m')) {
            cycle_mode();
            return true;
        }
        if (event == Event::Character('c')) {
            trust_ca();
            return true;
        }
        if (event == Event::Character('h')) {
            apply_hosts();
            return true;
        }
        return false;
    });

    std::jthread refresher([&](std::stop_token token) {
        while (!token.stop_requested()) {
            for (int i = 0; i < 5 && !token.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (token.stop_requested()) break;
            if (!paused.load()) screen.PostEvent(Event::Custom);
        }
    });

    screen.Loop(component);
    refresher.request_stop();
    session.stop();
    return 0;
}

} // namespace ghacc::app::tui
