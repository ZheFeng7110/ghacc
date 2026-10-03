module ghacc.accel.flow;

import std;

namespace ghacc::accel {

FlowAnalyzer::FlowAnalyzer(std::chrono::seconds window)
    : window_(window.count() > 0 ? window : std::chrono::seconds{1}) {}

void FlowAnalyzer::on_flow(Direction direction, std::size_t bytes) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(mutex_);
    if (direction == Direction::Read) {
        total_read_ += bytes;
        read_.push_back({now, bytes});
    } else {
        total_write_ += bytes;
        write_.push_back({now, bytes});
    }
}

double FlowAnalyzer::rate_locked(std::deque<Sample>& samples,
                                 std::chrono::steady_clock::time_point now,
                                 std::chrono::seconds window) {
    while (!samples.empty() && now - samples.front().time >= window) {
        samples.pop_front();
    }
    std::size_t sum = 0;
    for (const auto& s : samples) sum += s.bytes;
    const double seconds = static_cast<double>(window.count());
    return static_cast<double>(sum) / seconds;
}

FlowStatistics FlowAnalyzer::snapshot() const {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(mutex_);
    FlowStatistics stats;
    stats.total_read = total_read_;
    stats.total_write = total_write_;
    stats.read_rate = rate_locked(read_, now, window_);
    stats.write_rate = rate_locked(write_, now, window_);
    return stats;
}

void FlowAnalyzer::reset() {
    std::lock_guard lock(mutex_);
    read_.clear();
    write_.clear();
    total_read_ = 0;
    total_write_ = 0;
}

} // namespace ghacc::accel
