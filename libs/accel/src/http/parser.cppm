export module ghacc.accel.http.parser;

import std;
import ghacc.accel.http.message;

export namespace ghacc::accel::http {

/// Parse a request head (request line + header lines, no trailing blank line).
[[nodiscard]] std::expected<Request, std::string> parse_request_head(std::string_view head);

/// Parse a response head (status line + header lines, no trailing blank line).
[[nodiscard]] std::expected<Response, std::string> parse_response_head(std::string_view head);

/// How the body following a head is delimited.
enum class BodyFraming : std::uint8_t {
    None,
    ContentLength,
    Chunked,
    UntilClose,
};

struct BodyInfo {
    BodyFraming framing = BodyFraming::None;
    std::uint64_t length = 0;
};

[[nodiscard]] std::expected<BodyInfo, std::string> request_body_info(const Request& request);
[[nodiscard]] std::expected<BodyInfo, std::string> response_body_info(const Request& request,
                                                                      const Response& response);

/// Whether a header name is hop-by-hop and must not be forwarded verbatim.
[[nodiscard]] bool is_hop_by_hop(std::string_view name) noexcept;

/// Incrementally recognizes the end of a chunked transfer body.
///
/// The scanner consumes raw (still-encoded) bytes and reports how many belong to
/// the chunked body; the caller forwards those bytes unchanged. `done()` becomes
/// true once the terminating zero-length chunk and its trailer are complete.
class ChunkedScanner {
public:
    /// Feed raw bytes; returns the number of leading bytes consumed.
    [[nodiscard]] std::size_t consume(std::string_view data);

    [[nodiscard]] bool done() const noexcept { return done_; }
    [[nodiscard]] bool failed() const noexcept { return failed_; }
    void reset() noexcept;

private:
    enum class State : std::uint8_t { Size, Data, DataCrlf, Trailer };

    State state_ = State::Size;
    std::uint64_t remaining_ = 0;
    std::size_t data_crlf_ = 0;
    std::string line_;
    bool done_ = false;
    bool failed_ = false;
};

} // namespace ghacc::accel::http
