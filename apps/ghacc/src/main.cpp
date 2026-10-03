import std;
import ghacc.accel;

using namespace ghacc::accel;

namespace {

void print_usage() {
    std::println("usage:");
    std::println("  ghacc                 launch the (future) TUI dashboard");
    std::println("  ghacc test <domain>   resolve a domain through DoH and rank addresses");
    std::println("  ghacc version         print the version");
}

int command_test(std::string host) {
    DnsResolver resolver(DnsConfig{});
    std::println("resolving {} ...", host);
    const auto ranked = resolver.resolve_ranked(host, 443);
    if (ranked.empty()) {
        std::println(std::cerr, "no addresses for {}", host);
        return 1;
    }
    for (const auto& entry : ranked) {
        if (entry.reachable) {
            std::println("  {:<40} reachable  {:>5} ms", entry.address.to_string(), entry.rtt.count());
        } else {
            std::println("  {:<40} unreachable", entry.address.to_string());
        }
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.empty()) {
        std::println("ghacc {} — network accelerator", version);
        print_usage();
        return 0;
    }

    const std::string& command = args[0];
    if (command == "version" || command == "--version" || command == "-V") {
        std::println("ghacc {}", version);
        return 0;
    }
    if (command == "test") {
        if (args.size() < 2) {
            std::println(std::cerr, "error: 'test' requires a domain");
            return 2;
        }
        return command_test(args[1]);
    }

    print_usage();
    return 1;
}
