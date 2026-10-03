module;

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

module ghacc.accel.takeover.hosts;

import std;

namespace ghacc::accel {

namespace fs = std::filesystem;

namespace {

constexpr std::size_t npos = std::string_view::npos;

std::optional<std::pair<std::size_t, std::size_t>> find_block(std::string_view content) {
    const std::string_view begin = HostsManager::begin_marker();
    const std::string_view end = HostsManager::end_marker();
    const auto b = content.find(begin);
    if (b == npos) return std::nullopt;
    if (b != 0 && content[b - 1] != '\n') return std::nullopt;
    const auto e = content.find(end, b);
    if (e == npos) return std::nullopt;
    const auto line_end = content.find('\n', e);
    const std::size_t finish = line_end == npos ? content.size() : line_end + 1;
    return std::pair{b, finish};
}

std::string make_block(std::span<const HostEntry> entries) {
    std::string out;
    out += HostsManager::begin_marker();
    out.push_back('\n');
    for (const auto& entry : entries) {
        out += entry.ip;
        out.push_back('\t');
        out += entry.host;
        out.push_back('\n');
    }
    out += HostsManager::end_marker();
    out.push_back('\n');
    return out;
}

std::expected<std::string, std::string> read_file(const fs::path& path) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return std::string{};
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::unexpected("cannot read " + path.string());
    return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

std::expected<void, std::string> write_atomic(const fs::path& path, std::string_view data) {
    std::error_code ec;
    if (const auto parent = path.parent_path(); !parent.empty()) fs::create_directories(parent, ec);

    const fs::path temporary = path.string() + ".ghacc.tmp";
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream) return std::unexpected("cannot write " + temporary.string());
        stream.write(data.data(), static_cast<std::streamsize>(data.size()));
        if (!stream) {
            fs::remove(temporary, ec);
            return std::unexpected("failed writing " + temporary.string());
        }
    }
#if defined(_WIN32)
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        fs::remove(temporary, ec);
        return std::unexpected("cannot replace " + path.string());
    }
#else
    fs::rename(temporary, path, ec);
    if (ec) {
        fs::remove(temporary, ec);
        return std::unexpected("cannot replace " + path.string());
    }
#endif
    return {};
}

void backup_once(const fs::path& path, const fs::path& backup) {
    std::error_code ec;
    if (fs::exists(backup, ec)) return;
    if (!fs::exists(path, ec)) return;
    if (const auto parent = backup.parent_path(); !parent.empty()) fs::create_directories(parent, ec);
    fs::copy_file(path, backup, fs::copy_options::none, ec);
}

} // namespace

std::filesystem::path HostsManager::default_path() {
#if defined(_WIN32)
    if (const char* root = std::getenv("SystemRoot"); root != nullptr) {
        return fs::path(root) / "System32" / "drivers" / "etc" / "hosts";
    }
    return fs::path("C:/Windows/System32/drivers/etc/hosts");
#else
    return fs::path("/etc/hosts");
#endif
}

std::filesystem::path HostsManager::default_backup_path() {
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA"); appdata != nullptr) {
        return fs::path(appdata) / "ghacc" / "hosts.backup";
    }
    return fs::path("ghacc") / "hosts.backup";
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME"); home != nullptr) {
        return fs::path(home) / "Library" / "Application Support" / "ghacc" / "hosts.backup";
    }
    return fs::path("ghacc") / "hosts.backup";
#else
    if (const char* state = std::getenv("XDG_STATE_HOME"); state != nullptr && *state != '\0') {
        return fs::path(state) / "ghacc" / "hosts.backup";
    }
    if (const char* home = std::getenv("HOME"); home != nullptr) {
        return fs::path(home) / ".local" / "state" / "ghacc" / "hosts.backup";
    }
    return fs::path("ghacc") / "hosts.backup";
#endif
}

std::string_view HostsManager::begin_marker() noexcept {
    return "# >>> ghacc begin (managed by ghacc; do not edit) >>>";
}

std::string_view HostsManager::end_marker() noexcept {
    return "# <<< ghacc end <<<";
}

HostsManager::HostsManager(fs::path path, fs::path backup)
    : path_(std::move(path)), backup_(std::move(backup)) {}

bool HostsManager::is_writable() const {
#if defined(_WIN32)
    if (fs::exists(path_)) return ::_access(path_.string().c_str(), 2) == 0;
    auto parent = path_.parent_path();
    return ::_access((parent.empty() ? fs::path(".") : parent).string().c_str(), 2) == 0;
#else
    if (fs::exists(path_)) return ::access(path_.c_str(), W_OK) == 0;
    auto parent = path_.parent_path();
    if (parent.empty()) parent = fs::path(".");
    return ::access(parent.c_str(), W_OK) == 0;
#endif
}

std::string HostsManager::permission_hint() const {
#if defined(_WIN32)
    return "Run ghacc with Administrator privileges to edit " + path_.string();
#else
    return "Re-run with sudo (or grant write access to " + path_.string() + ")";
#endif
}

bool HostsManager::contains_our_block() const {
    auto content = read_file(path_);
    if (!content) return false;
    return find_block(*content).has_value();
}

std::vector<HostEntry> HostsManager::current_block() const {
    std::vector<HostEntry> out;
    auto content = read_file(path_);
    if (!content) return out;
    const auto range = find_block(*content);
    if (!range) return out;

    const std::string_view block(content->data() + range->first, range->second - range->first);
    std::size_t pos = 0;
    while (pos < block.size()) {
        const auto nl = block.find('\n', pos);
        std::string_view line = block.substr(pos, nl == npos ? npos : nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        pos = nl == npos ? block.size() : nl + 1;

        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
        if (line.empty() || line.front() == '#') continue;
        const auto separator = line.find_first_of(" \t");
        if (separator == npos) continue;

        HostEntry entry;
        entry.ip = std::string(line.substr(0, separator));
        std::string_view host_part = line.substr(separator);
        while (!host_part.empty() && (host_part.front() == ' ' || host_part.front() == '\t')) {
            host_part.remove_prefix(1);
        }
        const auto host_end = host_part.find_first_of(" \t");
        entry.host = std::string(host_part.substr(0, host_end));
        if (!entry.host.empty()) out.push_back(std::move(entry));
    }
    return out;
}

std::expected<void, std::string> HostsManager::apply(std::span<const HostEntry> entries) {
    if (entries.empty()) return revert();
    if (!is_writable()) return std::unexpected(permission_hint());

    auto content = read_file(path_);
    if (!content) return std::unexpected(content.error());

    const std::string block = make_block(entries);
    if (const auto range = find_block(*content)) {
        content->replace(range->first, range->second - range->first, block);
    } else {
        if (!content->empty() && content->back() != '\n') content->push_back('\n');
        if (!content->empty()) content->push_back('\n');
        content->append(block);
    }

    backup_once(path_, backup_);
    return write_atomic(path_, *content);
}

std::expected<void, std::string> HostsManager::revert() {
    auto content = read_file(path_);
    if (!content) return std::unexpected(content.error());
    const auto range = find_block(*content);
    if (!range) return {};  // idempotent
    if (!is_writable()) return std::unexpected(permission_hint());

    content->erase(range->first, range->second - range->first);
    backup_once(path_, backup_);
    return write_atomic(path_, *content);
}

} // namespace ghacc::accel
