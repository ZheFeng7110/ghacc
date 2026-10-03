import std;
import boost.ut;
import asio;

using namespace boost::ut;

int main() {
    "asio ssl context is usable"_test = [] {
        asio::ssl::context ctx(asio::ssl::context::tls_client);
        ctx.set_default_verify_paths();
        expect(sizeof(asio::ssl::stream<asio::ip::tcp::socket>) > 0);
        expect(true);
    };

    asio::io_context io;
    "io_context runs"_test = [&io] {
        auto work = asio::make_work_guard(io);
        int ticks = 0;
        asio::post(io, [&] { ++ticks; });
        work.reset();
        io.run();
        expect(ticks == 1);
        io.restart();
    };

    return 0;
}
