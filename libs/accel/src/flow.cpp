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

void RequestLog::add(RequestRecord record) {
    std::lock_guard lock(mutex_);
    if (ring_.size() >= capacity_) ring_.pop_front();
    ring_.push_back(std::move(record));
}

std::vector<RequestRecord> RequestLog::tail(std::size_t count) const {
    std::lock_guard lock(mutex_);
    const std::size_t begin = count >= ring_.size() ? 0 : ring_.size() - count;
    return {ring_.begin() + static_cast<std::ptrdiff_t>(begin), ring_.end()};
}

void RequestLog::clear() {
    std::lock_guard lock(mutex_);
    ring_.clear();
}

std::size_t RequestLog::size() const noexcept {
    std::lock_guard lock(mutex_);
    return ring_.size();
}

} // namespace ghacc::accel
