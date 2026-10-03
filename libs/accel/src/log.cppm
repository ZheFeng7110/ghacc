export module ghacc.accel.log;

import std;

export namespace ghacc::accel {

enum class LogLevel : std::uint8_t { Debug, Info, Warn, Error };

[[nodiscard]] constexpr std::string_view to_string(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO";
        case LogLevel::Warn:  return "WARN";
        case LogLevel::Error: return "ERROR";
    }
    return "?";
}

[[nodiscard]] inline std::optional<LogLevel> log_level_from(std::string_view text) noexcept {
    if (text == "debug") return LogLevel::Debug;
    if (text == "info") return LogLevel::Info;
    if (text == "warn" || text == "warning") return LogLevel::Warn;
    if (text == "error") return LogLevel::Error;
    return std::nullopt;
}

struct LogEntry {
    std::chrono::system_clock::time_point time;
    LogLevel level = LogLevel::Info;
    std::string scope;
    std::string message;
};

/// Process-wide logger with an in-memory ring buffer (for the TUI) and an
/// optional rotating file sink.
///
/// The ring buffer is always available; call `set_file()` to additionally
/// append every record to disk. The file is rotated when a write would push it
/// past `max_bytes`; at most `backups` older generations are kept.
class Log {
public:
    static Log& instance() {
        static Log log;
        return log;
    }

    void set_level(LogLevel level) noexcept {
        std::lock_guard lock(mutex_);
        level_ = level;
    }

    [[nodiscard]] LogLevel level() const noexcept {
        std::lock_guard lock(mutex_);
        return level_;
    }

    [[nodiscard]] bool enabled(LogLevel level) const noexcept { return level >= this->level(); }

    /// Open (or reopen) the rotating file sink. Creates parent directories.
    void set_file(std::filesystem::path path, std::uintmax_t max_bytes = 4u * 1024u * 1024u,
                  unsigned backups = 3) {
        std::lock_guard lock(mutex_);
        if (file_.is_open()) file_.close();
        file_path_ = std::move(path);
        max_bytes_ = max_bytes == 0 ? 1 : max_bytes;
        backups_ = backups;
        open_locked();
    }

    void close_file() {
        std::lock_guard lock(mutex_);
        if (file_.is_open()) file_.close();
        file_path_.clear();
    }

    [[nodiscard]] const std::filesystem::path& file_path() const noexcept {
        std::lock_guard lock(mutex_);
        return file_path_;
    }

    void write(LogLevel level, std::string_view scope, std::string_view message) {
        std::lock_guard lock(mutex_);
        if (level < level_) return;
        const auto now = std::chrono::system_clock::now();
        if (ring_.size() >= capacity_) ring_.pop_front();
        ring_.push_back({now, level, std::string(scope), std::string(message)});
        write_file_locked(now, level, scope, message);
    }

    [[nodiscard]] std::vector<LogEntry> tail(std::size_t count) const {
        std::lock_guard lock(mutex_);
        const std::size_t begin = count >= ring_.size() ? 0 : ring_.size() - count;
        return {ring_.begin() + static_cast<std::ptrdiff_t>(begin), ring_.end()};
    }

    void clear() {
        std::lock_guard lock(mutex_);
        ring_.clear();
    }

private:
    Log() = default;

    static std::string timestamp(std::chrono::system_clock::time_point now) {
        const auto seconds = std::chrono::floor<std::chrono::seconds>(now);
        const auto days = std::chrono::floor<std::chrono::days>(seconds);
        const std::chrono::year_month_day date{days};
        const std::chrono::hh_mm_ss time{seconds - days};
        const auto year = static_cast<int>(date.year());
        const auto month = static_cast<unsigned>(date.month());
        const auto day = static_cast<unsigned>(date.day());
        return std::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day,
                           time.hours().count(), time.minutes().count(), time.seconds().count());
    }

    void open_locked() {
        if (file_path_.empty()) return;
        std::error_code ec;
        const auto parent = file_path_.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent, ec);
        file_.open(file_path_, std::ios::app | std::ios::binary);
    }

    void rotate_locked() {
        if (file_.is_open()) file_.close();
        std::error_code ec;
        if (backups_ == 0) {
            std::filesystem::remove(file_path_, ec);
            open_locked();
            return;
        }
        const auto oldest = std::filesystem::path(file_path_.string() + "." +
                                                  std::to_string(backups_));
        std::filesystem::remove(oldest, ec);
        for (unsigned index = backups_; index > 1; --index) {
            const auto from = std::filesystem::path(file_path_.string() + "." +
                                                    std::to_string(index - 1));
            const auto to = std::filesystem::path(file_path_.string() + "." +
                                                  std::to_string(index));
            if (std::filesystem::exists(from, ec)) std::filesystem::rename(from, to, ec);
        }
        if (std::filesystem::exists(file_path_, ec)) {
            std::filesystem::rename(file_path_,
                                    std::filesystem::path(file_path_.string() + ".1"), ec);
        }
        open_locked();
    }

    void write_file_locked(std::chrono::system_clock::time_point now, LogLevel level,
                           std::string_view scope, std::string_view message) {
        if (file_path_.empty()) return;
        const std::string line = std::format("[{}] {} {}: {}\n", timestamp(now),
                                             to_string(level), scope, message);
        if (!file_.is_open()) open_locked();
        if (!file_.is_open()) return;

        if (max_bytes_ != 0) {
            std::error_code ec;
            const auto size = std::filesystem::file_size(file_path_, ec);
            if (!ec && size + line.size() > max_bytes_) rotate_locked();
        }
        file_.write(line.data(), static_cast<std::streamsize>(line.size()));
        file_.flush();
    }

    mutable std::mutex mutex_;
    LogLevel level_ = LogLevel::Info;
    std::deque<LogEntry> ring_;
    std::size_t capacity_ = 1024;

    std::ofstream file_;
    std::filesystem::path file_path_;
    std::uintmax_t max_bytes_ = 4u * 1024u * 1024u;
    unsigned backups_ = 3;
};

inline void log_debug(std::string_view scope, std::string_view message) {
    Log::instance().write(LogLevel::Debug, scope, message);
}
inline void log_info(std::string_view scope, std::string_view message) {
    Log::instance().write(LogLevel::Info, scope, message);
}
inline void log_warn(std::string_view scope, std::string_view message) {
    Log::instance().write(LogLevel::Warn, scope, message);
}
inline void log_error(std::string_view scope, std::string_view message) {
    Log::instance().write(LogLevel::Error, scope, message);
}

} // namespace ghacc::accel
