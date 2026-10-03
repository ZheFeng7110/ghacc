export module ghacc.accel.rule;

import std;

export namespace ghacc::accel {

/// What the engine should do with a matched domain.
enum class RuleAction : std::uint8_t {
    /// MITM / reverse-proxy through the local engine.
    ReverseProxy,
    /// Plain TCP tunnel to the resolved upstream without TLS interception.
    Tunnel,
    /// Reject the connection.
    Block,
    /// Serve a canned response (not used by built-in providers yet).
    StaticResponse,
};

/// How a DomainRule pattern is interpreted.
enum class RuleMatch : std::uint8_t {
    Exact,
    Wildcard,
    Regex,
};

/// A single acceleration rule for one domain pattern.
///
/// Pattern forms:
///   - `github.com`                 exact host
///   - `*.githubusercontent.com`    wildcard (`*` matches any sequence, `?` one char)
///   - `re:^raw\.github.*$`         explicit regular expression
///   - `/^raw\.github.*$/`          regular expression (slash-delimited form)
struct DomainRule {
    std::string pattern;
    RuleAction action = RuleAction::ReverseProxy;
    /// Present a certificate for the requested host (MITM) instead of tunnelling.
    bool tls_sni = true;
    /// Accept upstream certificates whose name does not match.
    bool tls_ignore_name_mismatch = false;
    /// Optional rewrite target; supports `@domain` / `@uri` placeholders.
    std::string destination;
    /// Optional different hostname to resolve upstream addresses from.
    std::string forward_destination;
    /// Optional fixed upstream IP.
    std::optional<std::string> ip;
    /// Optional User-Agent override for upstream requests.
    std::optional<std::string> user_agent;
    std::chrono::milliseconds timeout{10'000};
    /// Tie-breaker; lower runs first among equally specific patterns.
    int order = 0;
    /// Provider that contributed this rule.
    std::string provider_id;
    /// Human readable note (TUI / logs).
    std::string description;
};

[[nodiscard]] std::string_view to_string(RuleAction action) noexcept;
[[nodiscard]] std::optional<RuleAction> rule_action_from(std::string_view text) noexcept;

/// Compiled, ordered set of rules with fast host lookup.
///
/// Matching is case-insensitive. Exact patterns win over wildcard patterns,
/// which win over regex patterns; ties are broken by `order`.
class RuleSet {
public:
    RuleSet();
    RuleSet(RuleSet&&) noexcept;
    RuleSet& operator=(RuleSet&&) noexcept;
    RuleSet(const RuleSet&) = delete;
    RuleSet& operator=(const RuleSet&) = delete;
    ~RuleSet();

    void add(DomainRule rule);
    void add_all(std::span<const DomainRule> rules);

    /// First (most specific) rule matching `host`, if any.
    [[nodiscard]] std::optional<DomainRule> match(std::string_view host) const;

    /// Whether any rule matches `host`.
    [[nodiscard]] bool contains(std::string_view host) const { return match(host).has_value(); }

    /// Original patterns, in compiled order (used to build a PAC file).
    [[nodiscard]] std::vector<std::string> patterns() const;

    /// Concrete host names that can be written to a hosts file.
    ///
    /// Exact patterns are returned verbatim; a simple `*.suffix` wildcard
    /// contributes its apex `suffix` (hosts has no wildcard support). Regex
    /// patterns and wildcards with `*`/`?` beyond a leading `*.` are skipped.
    /// The result is lower-cased, de-duplicated and sorted.
    [[nodiscard]] std::vector<std::string> hostnames() const;

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ghacc::accel
