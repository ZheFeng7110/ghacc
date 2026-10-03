import std;
import boost.ut;
import ftxui;

using namespace boost::ut;

int main() {
    "ftxui renders an element"_test = [] {
        using namespace ftxui;
        Element document = hbox({text("ghacc"), separator(), text("tui")});
        auto screen = Screen::Create(Dimension::Fit(document), Dimension::Fit(document));
        Render(screen, document);
        const std::string rendered = screen.ToString();
        expect(rendered.find("ghacc") != std::string::npos);
        expect(rendered.find("tui") != std::string::npos);
    };
    return 0;
}
