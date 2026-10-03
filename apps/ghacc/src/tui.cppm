export module ghacc.tui;

import std;
import ftxui;
import ghacc.accel;
import ghacc.app;

export namespace ghacc::app::tui {

/// Immutable snapshot the dashboard renders from. Pulling all data out of the
/// engine first keeps the render function pure and unit testable.
struct DashboardState {
    StatusInfo status;
    FlowStatistics flow;
    std::vector<RequestRecord> requests;
    std::vector<LogEntry> logs;
    std::vector<std::pair<std::string, bool>> providers;  // id, enabled
    std::string message;
    bool paused = false;
};

/// Build the dashboard element tree (no terminal required).
[[nodiscard]] ftxui::Element render_dashboard(const DashboardState& state);

/// Run the interactive FTXUI dashboard until the user quits.
int run_tui(const RuntimePaths& paths);

} // namespace ghacc::app::tui
