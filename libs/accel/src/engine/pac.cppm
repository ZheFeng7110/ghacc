export module ghacc.accel.engine.pac;

import std;
import ghacc.accel.rule;

export namespace ghacc::accel {

/// Where the PAC file points clients.
struct PacOptions {
    std::string proxy_host = "127.0.0.1";
    std::uint16_t proxy_port = 26501;
    std::string pac_path = "/pac";
};

/// Rule patterns expressible in a PAC file (regex patterns are skipped).
[[nodiscard]] std::vector<std::string> pac_patterns(const RuleSet& rules);

/// Build a `FindProxyForURL` script routing matching hosts through the proxy.
[[nodiscard]] std::string generate_pac(const RuleSet& rules, const PacOptions& options);

/// Whether `target` (origin-form or absolute-form) requests the PAC file.
[[nodiscard]] bool is_pac_request(std::string_view target, const PacOptions& options);

} // namespace ghacc::accel
