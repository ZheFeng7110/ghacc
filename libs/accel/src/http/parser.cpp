module ghacc.accel.http.parser;

import std;
import ghacc.accel.http.message;

namespace ghacc::accel::http {

namespace {

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const auto nl = text.find('\n', pos);
        std::string_view line;
        if (nl == std::string_view::npos) {
            line = text.substr(pos);
            pos = text.size() + 1;
        } else {
            line = text.substr(pos, nl - pos);
            pos = nl + 1;
        }
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        lines.push_back(line);
        if (nl == std::string_view::npos) break;
    }
    return lines;
}

std::vector<std::string_view> split_whitespace(std::string_view text) {
    std::vector<std::string_view> parts;
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
        const std::size_t begin = i;
        while (i < text.size() && text[i] != ' ' && text[i] != '\t') ++i;
        if (i > begin) parts.push_back(text.substr(begin, i - begin));
    }
    return parts;
}

std::expected<void, std::string> parse_header_lines(std::span<const std::string_view> lines,
                                                    Headers& headers) {
    for (std::size_t i = 1; i < lines.size(); ++i) {
        const std::string_view line = lines[i];
        if (line.empty()) continue;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) {
            return std::unexpected("malformed header line: " + std::string(line));
        }
        const std::string_view name = trim(line.substr(0, colon));
        const std::string_view value = trim(line.substr(colon + 1));
        if (name.empty()) return std::unexpected("empty header name");
        headers.add(name, value);
    }
    return {};
}

std::expected<std::uint64_t, std::string> parse_u64(std::string_view text) {
    text = trim(text);
    if (text.empty()) return std::unexpected("empty number");
    std::uint64_t value = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);
    if (ec != std::errc{} || ptr != end) return std::unexpected("invalid number: " + std::string(text));
    return value;
}

bool status_has_no_body(int status) noexcept {
    return (status >= 100 && status < 200) || status == 204 || status == 304;
}

} // namespace

std::expected<Request, std::string> parse_request_head(std::string_view head) {
    if (head.empty()) return std::unexpected("empty request head");
    const auto lines = split_lines(head);
    const auto first = split_whitespace(lines.front());
    if (first.size() != 3) return std::unexpected("malformed request line");
    if (!first[2].starts_with("HTTP/")) return std::unexpected("unsupported protocol version");

    Request request;
    request.method = std::string(first[0]);
    request.target = std::string(first[1]);
    request.version = std::string(first[2]);

    if (auto ok = parse_header_lines(lines, request.headers); !ok) {
        return std::unexpected(ok.error());
    }
    return request;
}

std::expected<Response, std::string> parse_response_head(std::string_view head) {
    if (head.empty()) return std::unexpected("empty response head");
    const auto lines = split_lines(head);
    const auto first = split_whitespace(lines.front());
    if (first.size() < 2) return std::unexpected("malformed status line");
    if (!first[0].starts_with("HTTP/")) return std::unexpected("unsupported protocol version");

    auto status = parse_u64(first[1]);
    if (!status) return std::unexpected("invalid status code");

    Response response;
    response.version = std::string(first[0]);
    response.status = static_cast<int>(*status);
    // Reason phrase: everything after "HTTP/x.y <code> " on the first line.
    const auto code_pos = lines.front().find(first[1]);
    if (code_pos != std::string_view::npos) {
        auto reason = lines.front().substr(code_pos + first[1].size());
        reason = trim(reason);
        response.reason = std::string(reason);
    }

    if (auto ok = parse_header_lines(lines, response.headers); !ok) {
        return std::unexpected(ok.error());
    }
    return response;
}

std::expected<BodyInfo, std::string> request_body_info(const Request& request) {
    if (const auto te = request.headers.get("transfer-encoding")) {
        if (header_contains_token(*te, "chunked")) return BodyInfo{BodyFraming::Chunked, 0};
    }
    if (const auto cl = request.headers.get("content-length")) {
        auto length = parse_u64(*cl);
        if (!length) return std::unexpected("invalid Content-Length");
        return BodyInfo{BodyFraming::ContentLength, *length};
    }
    return BodyInfo{BodyFraming::None, 0};
}

std::expected<BodyInfo, std::string> response_body_info(const Request& request,
                                                        const Response& response) {
    if (status_has_no_body(response.status) || iequals(request.method, "HEAD")) {
        return BodyInfo{BodyFraming::None, 0};
    }
    if (const auto te = response.headers.get("transfer-encoding")) {
        if (header_contains_token(*te, "chunked")) return BodyInfo{BodyFraming::Chunked, 0};
    }
    if (const auto cl = response.headers.get("content-length")) {
        auto length = parse_u64(*cl);
        if (!length) return std::unexpected("invalid Content-Length");
        return BodyInfo{BodyFraming::ContentLength, *length};
    }
    return BodyInfo{BodyFraming::UntilClose, 0};
}

bool is_hop_by_hop(std::string_view name) noexcept {
    return iequals(name, "connection") || iequals(name, "keep-alive") ||
           iequals(name, "proxy-authenticate") || iequals(name, "proxy-authorization") ||
           iequals(name, "te") || iequals(name, "trailer") || iequals(name, "transfer-encoding") ||
           iequals(name, "upgrade") || iequals(name, "proxy-connection");
}

void ChunkedScanner::reset() noexcept {
    state_ = State::Size;
    remaining_ = 0;
    data_crlf_ = 0;
    line_.clear();
    done_ = false;
    failed_ = false;
}

std::size_t ChunkedScanner::consume(std::string_view data) {
    std::size_t i = 0;
    while (i < data.size() && !done_ && !failed_) {
        switch (state_) {
            case State::Size: {
                const char c = data[i++];
                line_.push_back(c);
                if (c == '\n') {
                    std::string_view text = line_;
                    if (!text.empty() && text.back() == '\n') text.remove_suffix(1);
                    if (!text.empty() && text.back() == '\r') text.remove_suffix(1);
                    const auto semi = text.find(';');
                    if (semi != std::string_view::npos) text = text.substr(0, semi);
                    text = trim(text);
                    std::uint64_t size = 0;
                    const auto [ptr, ec] =
                        std::from_chars(text.data(), text.data() + text.size(), size, 16);
                    if (ec != std::errc{} || ptr != text.data() + text.size()) {
                        failed_ = true;
                        break;
                    }
                    remaining_ = size;
                    line_.clear();
                    state_ = size == 0 ? State::Trailer : State::Data;
                }
                break;
            }
            case State::Data: {
                const std::size_t available = data.size() - i;
                const auto take = static_cast<std::size_t>(
                    std::min<std::uint64_t>(remaining_, available));
                i += take;
                remaining_ -= take;
                if (remaining_ == 0) state_ = State::DataCrlf;
                break;
            }
            case State::DataCrlf: {
                const char c = data[i++];
                if (data_crlf_ == 0) {
                    if (c != '\r') {
                        failed_ = true;
                        break;
                    }
                    data_crlf_ = 1;
                } else {
                    if (c != '\n') {
                        failed_ = true;
                        break;
                    }
                    data_crlf_ = 0;
                    state_ = State::Size;
                }
                break;
            }
            case State::Trailer: {
                const char c = data[i++];
                line_.push_back(c);
                if (c == '\n') {
                    if (line_ == "\r\n" || line_ == "\n") done_ = true;
                    line_.clear();
                }
                break;
            }
        }
    }
    return i;
}

} // namespace ghacc::accel::http
