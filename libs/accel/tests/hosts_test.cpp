import std;
import boost.ut;
import ghacc.accel.takeover.hosts;

using namespace boost::ut;
using namespace ghacc::accel;

namespace {

std::string read_text(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

std::size_t count_occurrences(std::string_view haystack, std::string_view needle) {
    std::size_t count = 0;
    for (std::size_t pos = haystack.find(needle); pos != std::string_view::npos;
         pos = haystack.find(needle, pos + needle.size())) {
        ++count;
    }
    return count;
}

} // namespace

int main() {
    const auto directory = std::filesystem::temp_directory_path() / "ghacc-hosts-test";
    std::error_code ec;
    std::filesystem::remove_all(directory, ec);
    std::filesystem::create_directories(directory, ec);

    const auto hosts_path = directory / "hosts";
    const auto backup_path = directory / "state" / "hosts.backup";
    {
        std::ofstream stream(hosts_path);
        stream << "127.0.0.1 localhost\n::1 localhost\n";
    }

    HostsManager manager(hosts_path, backup_path);

    "apply writes the marker block"_test = [&] {
        const std::vector<HostEntry> entries = {{"127.0.0.1", "github.com"},
                                                {"127.0.0.1", "api.github.com"}};
        auto result = manager.apply(entries);
        expect(result.has_value()) << (result ? "" : result.error());
        const std::string content = read_text(hosts_path);
        expect(content.find(std::string(HostsManager::begin_marker())) != std::string::npos);
        expect(content.find(std::string(HostsManager::end_marker())) != std::string::npos);
        expect(content.find("127.0.0.1\tgithub.com") != std::string::npos);
        expect(content.find("localhost") != std::string::npos) << "unrelated lines preserved";
        expect(manager.contains_our_block());
        expect(std::filesystem::exists(backup_path)) << "backup created";
    };

    "apply is idempotent and replaces the block"_test = [&] {
        const std::string backup_before = read_text(backup_path);
        const std::vector<HostEntry> entries = {{"127.0.0.1", "steamcommunity.com"}};
        auto result = manager.apply(entries);
        expect(result.has_value()) << (result ? "" : result.error());
        const std::string content = read_text(hosts_path);
        expect(count_occurrences(content, HostsManager::begin_marker()) == 1_u);
        expect(count_occurrences(content, HostsManager::end_marker()) == 1_u);
        expect(content.find("github.com") == std::string::npos) << "old block replaced";
        expect(content.find("127.0.0.1\tsteamcommunity.com") != std::string::npos);

        const auto block = manager.current_block();
        expect(block.size() == 1_u);
        expect(block.front().ip == std::string("127.0.0.1"));
        expect(block.front().host == std::string("steamcommunity.com"));
        expect(read_text(backup_path) == backup_before) << "backup is never overwritten";
    };

    "revert removes only the block"_test = [&] {
        auto result = manager.revert();
        expect(result.has_value()) << (result ? "" : result.error());
        const std::string content = read_text(hosts_path);
        expect(!manager.contains_our_block());
        expect(content.find(std::string(HostsManager::begin_marker())) == std::string::npos);
        expect(content.find("localhost") != std::string::npos);
        expect(manager.current_block().empty());
    };

    "revert is idempotent"_test = [&] {
        auto result = manager.revert();
        expect(result.has_value());
    };

    "permission helpers report writability"_test = [&] {
        expect(manager.is_writable()) << "temp directory is writable";
        expect(!manager.permission_hint().empty());
    };

    std::filesystem::remove_all(directory, ec);
    return 0;
}
