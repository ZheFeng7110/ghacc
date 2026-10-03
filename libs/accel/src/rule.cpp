module ghacc.accel.rule;

import std;

namespace ghacc::accel {

namespace {

/// ASCII lower-case a host name without allocating when already lower.
std::string ascii_lower(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

bool is_wildcard(std::string_view p) {
    return p.find_first_of("*?") != std::string_view::npos;
}

/// Case-insensitive glob where `*` matches any sequence and `?` one char.
bool glob_match(std::string_view pat, std::string_view str) {
    std::size_t p = 0, s = 0;
    std::size_t star = std::string_view::npos, resume = 0;
    while (s < str.size()) {
        if (p < pat.size() && (pat[p] == '?' || pat[p] == str[s])) {
            ++p;
            ++s;
        } else if (p < pat.size() && pat[p] == '*') {
            star = p++;
            resume = s;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            s = ++resume;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*') ++p;
    return p == pat.size();
}

std::size_t specificity_of(RuleMatch kind, std::string_view pattern) {
    switch (kind) {
        case RuleMatch::Exact:
            return 1'000'000 + pattern.size();
        case RuleMatch::Wildcard: {
            std::size_t literal = 0;
            for (char c : pattern) {
                if (c != '*' && c != '?') ++literal;
            }
            return literal * 1000;
        }
        case RuleMatch::Regex:
        default:
            return 0;
    }
}

} // namespace

struct RuleSet::Impl {
    struct Compiled {
        DomainRule rule;
        RuleMatch kind = RuleMatch::Exact;
        std::string pattern;  // normalised (lower-case for exact/wildcard)
        std::regex regex;     // only for RuleMatch::Regex
        std::size_t specificity = 0;
    };

    std::vector<Compiled> rules;
    bool sorted = true;

    static Compiled compile(DomainRule rule) {
        Compiled c;
        c.rule = std::move(rule);

        std::string_view pat = c.rule.pattern;
        if (pat.starts_with("re:")) {
            c.kind = RuleMatch::Regex;
            c.regex = std::regex(std::string(pat.substr(3)),
                                 std::regex::ECMAScript | std::regex::icase);
        } else if (pat.size() >= 2 && pat.front() == '/' && pat.back() == '/') {
            c.kind = RuleMatch::Regex;
            c.regex = std::regex(std::string(pat.substr(1, pat.size() - 2)),
                                 std::regex::ECMAScript | std::regex::icase);
        } else if (is_wildcard(pat)) {
            c.kind = RuleMatch::Wildcard;
            c.pattern = ascii_lower(pat);
        } else {
            c.kind = RuleMatch::Exact;
            c.pattern = ascii_lower(pat);
        }
        c.specificity = specificity_of(c.kind, c.pattern.empty() ? pat : c.pattern);
        return c;
    }

    void sort_if_needed() {
        if (sorted) return;
        std::stable_sort(rules.begin(), rules.end(), [](const Compiled& a, const Compiled& b) {
            if (a.specificity != b.specificity) return a.specificity > b.specificity;
            if (a.rule.order != b.rule.order) return a.rule.order < b.rule.order;
            return a.rule.pattern < b.rule.pattern;
        });
        sorted = true;
    }

    bool matches(const Compiled& c, std::string_view lower_host) const {
        switch (c.kind) {
            case RuleMatch::Exact:
                return c.pattern == lower_host;
            case RuleMatch::Wildcard:
                return glob_match(c.pattern, lower_host);
            case RuleMatch::Regex:
                return std::regex_match(lower_host.begin(), lower_host.end(), c.regex);
        }
        return false;
    }
};

std::string_view to_string(RuleAction action) noexcept {
    switch (action) {
        case RuleAction::ReverseProxy: return "reverse_proxy";
        case RuleAction::Tunnel:       return "tunnel";
        case RuleAction::Block:        return "block";
        case RuleAction::StaticResponse: return "static";
    }
    return "reverse_proxy";
}

std::optional<RuleAction> rule_action_from(std::string_view text) noexcept {
    if (text == "reverse_proxy") return RuleAction::ReverseProxy;
    if (text == "tunnel") return RuleAction::Tunnel;
    if (text == "block") return RuleAction::Block;
    if (text == "static") return RuleAction::StaticResponse;
    return std::nullopt;
}

RuleSet::RuleSet() : impl_(std::make_unique<Impl>()) {}
RuleSet::RuleSet(RuleSet&&) noexcept = default;
RuleSet& RuleSet::operator=(RuleSet&&) noexcept = default;
RuleSet::~RuleSet() = default;

void RuleSet::add(DomainRule rule) {
    impl_->rules.push_back(Impl::compile(std::move(rule)));
    impl_->sorted = false;
}

void RuleSet::add_all(std::span<const DomainRule> rules) {
    for (const auto& r : rules) add(r);
}

std::optional<DomainRule> RuleSet::match(std::string_view host) const {
    impl_->sort_if_needed();
    if (host.empty()) return std::nullopt;

    // Strip a trailing port and any brackets.
    std::string host_str(host);
    if (auto colon = host_str.rfind(':'); colon != std::string::npos &&
                                            host_str.find(']') == std::string::npos &&
                                            host_str.find(':') == colon) {
        host_str.resize(colon);
    }
    const std::string lowered = ascii_lower(host_str);

    for (const auto& c : impl_->rules) {
        if (impl_->matches(c, lowered)) return c.rule;
    }
    return std::nullopt;
}

std::vector<std::string> RuleSet::patterns() const {
    impl_->sort_if_needed();
    std::vector<std::string> out;
    out.reserve(impl_->rules.size());
    for (const auto& c : impl_->rules) out.push_back(c.rule.pattern);
    return out;
}

std::vector<std::string> RuleSet::hostnames() const {
    impl_->sort_if_needed();
    std::vector<std::string> out;
    out.reserve(impl_->rules.size());
    for (const auto& c : impl_->rules) {
        switch (c.kind) {
            case RuleMatch::Exact:
                out.push_back(c.pattern);
                break;
            case RuleMatch::Wildcard:
                // Only a leading `*.` with no further wildcard maps to a host.
                if (c.pattern.starts_with("*.") &&
                    c.pattern.find_first_of("*?", 2) == std::string::npos) {
                    out.push_back(c.pattern.substr(2));
                }
                break;
            case RuleMatch::Regex:
                break;
        }
    }
    std::ranges::sort(out);
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::size_t RuleSet::size() const noexcept { return impl_->rules.size(); }

} // namespace ghacc::accel
