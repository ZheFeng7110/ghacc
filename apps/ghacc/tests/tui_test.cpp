import std;
import boost.ut;
import ftxui;
import ghacc.accel;
import ghacc.app;
import ghacc.tui;

using namespace boost::ut;
using namespace ghacc::app;
using namespace ghacc::accel;

int main() {
    "dashboard renders status, providers and requests"_test = [] {
        tui::DashboardState state;
        state.status.version = "0.1.0";
        state.status.mode = "hosts";
        state.status.running = true;
        state.status.address = "127.0.0.1";
        state.status.proxy_port = 26501;
        state.providers = {{"github", true}, {"steam", false}};
        state.flow.total_read = 2048;
        state.flow.read_rate = 1024.0;

        RequestRecord record;
        record.method = "GET";
        record.host = "github.com";
        record.path = "/";
        record.status = 200;
        record.upstream = "1.2.3.4";
        record.accelerated = true;
        state.requests.push_back(record);
        state.message = "ready";

        auto element = tui::render_dashboard(state);
        auto screen =
            ftxui::Screen::Create(ftxui::Dimension::Fit(element), ftxui::Dimension::Fit(element));
        ftxui::Render(screen, element);
        const std::string rendered = screen.ToString();

        expect(rendered.find("ghacc") != std::string::npos);
        expect(rendered.find("github") != std::string::npos);
        expect(rendered.find("GET") != std::string::npos);
        expect(rendered.find("ready") != std::string::npos);
    };

    "dashboard renders without a running engine"_test = [] {
        tui::DashboardState state;
        state.status.version = "0.1.0";
        state.status.mode = "forward";
        state.status.running = false;
        auto element = tui::render_dashboard(state);
        auto screen =
            ftxui::Screen::Create(ftxui::Dimension::Fit(element), ftxui::Dimension::Fit(element));
        ftxui::Render(screen, element);
        const std::string rendered = screen.ToString();
        expect(rendered.find("stopped") != std::string::npos);
        expect(rendered.find("no requests yet") != std::string::npos);
    };

    return 0;
}
