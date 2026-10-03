import std;
import boost.ut;
import ghacc.accel.log;

using namespace boost::ut;
using namespace ghacc::accel;

namespace fs = std::filesystem;

int main() {
    auto& log = Log::instance();
    const fs::path dir = fs::temp_directory_path() / "ghacc-log-test";
    fs::remove_all(dir);

    "ring buffer keeps the most recent entries"_test = [&] {
        log.set_level(LogLevel::Debug);
        log.clear();
        for (int i = 0; i < 5; ++i) log.write(LogLevel::Info, "t", std::to_string(i));
        auto entries = log.tail(3);
        expect(entries.size() == 3_u);
        expect(entries.back().message == std::string("4"));
    };

    "level filtering drops lower levels"_test = [&] {
        log.set_level(LogLevel::Warn);
        log.clear();
        log.write(LogLevel::Info, "t", "info");
        log.write(LogLevel::Error, "t", "error");
        auto entries = log.tail(10);
        expect(entries.size() == 1_u);
        expect(entries.front().level == LogLevel::Error);
        log.set_level(LogLevel::Info);
    };

    "file sink writes and rotates"_test = [&] {
        log.clear();
        const fs::path path = dir / "ghacc.log";
        log.set_file(path, 64, 2);
        for (int i = 0; i < 20; ++i) {
            log.write(LogLevel::Info, "file", std::string(30, 'x'));
        }
        log.close_file();

        expect(fs::exists(path));
        expect(fs::file_size(path) > 0_u);
        expect(fs::exists(path.string() + ".1"));
        // At most `backups` generations are kept.
        expect(!fs::exists(path.string() + ".3"));
    };

    "close_file stops writing"_test = [&] {
        const fs::path path = dir / "second.log";
        log.set_file(path, 1024, 1);
        log.write(LogLevel::Info, "file", "hello");
        log.close_file();
        const auto before = fs::file_size(path);
        log.write(LogLevel::Info, "file", "after close");
        expect(fs::file_size(path) == before);
    };

    fs::remove_all(dir);
    return 0;
}
