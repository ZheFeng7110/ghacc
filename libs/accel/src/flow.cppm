export module ghacc.accel.flow;

import std;

export namespace ghacc::accel {

enum class Direction : std::uint8_t { Read, Write };

struct FlowStatistics {
    std::uint64_t total_read = 0;
    std::uint64_t total_write = 0;
    double read_rate = 0.0;   // bytes/second over the sliding window
    double write_rate = 0.0;
};

/// Sliding-window byte-rate tracker, mirroring SteamTools' FlowAnalyzer.
class FlowAnalyzer {
public:
    explicit FlowAnalyzer(std::chrono::seconds window = std::chrono::seconds{5});

    void on_flow(Direction direction, std::size_t bytes);

    [[nodiscard]] FlowStatistics snapshot() const;

    void reset();

private:
    struct Sample {
        std::chrono::steady_clock::time_point time;
        std::size_t bytes = 0;
    };

    static double rate_locked(std::deque<Sample>& samples,
                              std::chrono::steady_clock::time_point now,
                              std::chrono::seconds window);

    std::chrono::seconds window_;
    mutable std::mutex mutex_;
    mutable std::deque<Sample> read_;
    mutable std::deque<Sample> write_;
    std::uint64_t total_read_ = 0;
    std::uint64_t total_write_ = 0;
};

/// A single proxied request, for the TUI/status tables.
struct RequestRecord {
    std::chrono::system_clock::time_point time;
    std::string method;
    std::string host;
    std::string path;
    int status = 0;
    std::chrono::milliseconds duration{0};
    std::string upstream;    // upstream IP actually connected to
    bool accelerated = false; // matched an acceleration rule
};

/// Bounded, thread-safe ring buffer of recent requests.
class RequestLog {
public:
    void add(RequestRecord record);

    [[nodiscard]] std::vector<RequestRecord> tail(std::size_t count) const;

    void clear();

    [[nodiscard]] std::size_t size() const noexcept;

private:
    mutable std::mutex mutex_;
    std::deque<RequestRecord> ring_;
    std::size_t capacity_ = 512;
};

} // namespace ghacc::accel
