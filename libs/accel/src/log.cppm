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

struct LogEntry {
    std::chrono::system_clock::time_point time;
    LogLevel level = LogLevel::Info;
    std::string scope;
    std::string message;
};

/// Process-wide logger with an in-memory ring buffer for the TUI.
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

    void write(LogLevel level, std::string_view scope, std::string_view message) {
        std::lock_guard lock(mutex_);
        if (level < level_) return;
        if (ring_.size() >= capacity_) ring_.pop_front();
        ring_.push_back({std::chrono::system_clock::now(), level, std::string(scope), std::string(message)});
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

    mutable std::mutex mutex_;
    LogLevel level_ = LogLevel::Info;
    std::deque<LogEntry> ring_;
    std::size_t capacity_ = 1024;
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
