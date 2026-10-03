export module ghacc.accel.http.message;

import std;

export namespace ghacc::accel::http {

/// ASCII case-insensitive equality (only A-Z/a-z folded).
[[nodiscard]] bool iequals(std::string_view a, std::string_view b) noexcept;

/// Case-insensitive, order-preserving HTTP header collection.
///
/// Header names keep their original casing for serialization; lookups compare
/// ASCII case-insensitively. Repeated names (e.g. `Set-Cookie`) are preserved
/// and returned in insertion order by `get_all`.
class Headers {
public:
    /// Replace every existing field with `name`, then append one.
    void set(std::string_view name, std::string_view value) {
        remove(name);
        add(name, value);
    }

    /// Append a field without touching existing ones.
    void add(std::string_view name, std::string_view value) {
        fields_.emplace_back(std::string(name), std::string(value));
    }

    void remove(std::string_view name) {
        std::erase_if(fields_, [name](const auto& field) { return iequals(field.first, name); });
    }

    void clear() noexcept { fields_.clear(); }

    [[nodiscard]] std::optional<std::string_view> get(std::string_view name) const {
        for (const auto& field : fields_) {
            if (iequals(field.first, name)) return field.second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<std::string_view> get_all(std::string_view name) const {
        std::vector<std::string_view> out;
        for (const auto& field : fields_) {
            if (iequals(field.first, name)) out.push_back(field.second);
        }
        return out;
    }

    [[nodiscard]] bool contains(std::string_view name) const { return get(name).has_value(); }

    [[nodiscard]] std::size_t size() const noexcept { return fields_.size(); }
    [[nodiscard]] bool empty() const noexcept { return fields_.empty(); }

    [[nodiscard]] std::span<const std::pair<std::string, std::string>> fields() const noexcept {
        return fields_;
    }

private:
    std::vector<std::pair<std::string, std::string>> fields_;
};

/// An HTTP/1.x request head (request line + headers; body handled separately).
struct Request {
    std::string method;
    std::string target;
    std::string version = "HTTP/1.1";
    Headers headers;
};

/// An HTTP/1.x response head (status line + headers; body handled separately).
struct Response {
    std::string version = "HTTP/1.1";
    int status = 0;
    std::string reason;
    Headers headers;
};

/// ASCII case-insensitive equality (only A-Z/a-z folded).
[[nodiscard]] bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

[[nodiscard]] std::string lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

/// Remove leading/trailing ASCII whitespace.
[[nodiscard]] constexpr std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
}

/// Whether `value` (a comma-separated token list) contains `token`.
[[nodiscard]] bool header_contains_token(std::string_view value, std::string_view token) noexcept {
    std::size_t pos = 0;
    while (pos <= value.size()) {
        auto comma = value.find(',', pos);
        std::string_view part = value.substr(pos, comma == std::string_view::npos ? std::string_view::npos
                                                                                  : comma - pos);
        if (iequals(trim(part), token)) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

} // namespace ghacc::accel::http
