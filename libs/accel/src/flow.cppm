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

} // namespace ghacc::accel
