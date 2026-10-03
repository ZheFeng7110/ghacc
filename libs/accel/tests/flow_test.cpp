import std;
import boost.ut;
import ghacc.accel.flow;

using namespace boost::ut;
using namespace ghacc::accel;

int main() {
    "totals accumulate"_test = [] {
        FlowAnalyzer analyzer(std::chrono::seconds{5});
        analyzer.on_flow(Direction::Read, 100);
        analyzer.on_flow(Direction::Read, 200);
        analyzer.on_flow(Direction::Write, 50);

        auto stats = analyzer.snapshot();
        expect(stats.total_read == 300_u);
        expect(stats.total_write == 50_u);
    };

    "rate is bytes over the window"_test = [] {
        FlowAnalyzer analyzer(std::chrono::seconds{5});
        analyzer.on_flow(Direction::Read, 1000);
        auto stats = analyzer.snapshot();
        // 1000 bytes over a 5 second window => 200 B/s
        expect(stats.read_rate > 199.0_d && stats.read_rate < 201.0_d);
    };

    "reset clears everything"_test = [] {
        FlowAnalyzer analyzer(std::chrono::seconds{5});
        analyzer.on_flow(Direction::Read, 1000);
        analyzer.reset();
        auto stats = analyzer.snapshot();
        expect(stats.total_read == 0_u);
        expect(stats.read_rate == 0.0_d);
    };

    return 0;
}
