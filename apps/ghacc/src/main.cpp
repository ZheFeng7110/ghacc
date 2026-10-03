import std;
import ghacc.app;
import ghacc.cli;
import ghacc.tui;

int main(int argc, char** argv) {
    if (argc <= 1) {
        return ghacc::app::tui::run_tui(ghacc::app::resolve_paths({}));
    }
    return ghacc::app::run_cli(argc, argv);
}
