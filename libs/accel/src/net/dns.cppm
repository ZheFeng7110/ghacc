export module ghacc.accel.net.dns;

import std;

export namespace ghacc::accel::dns {

/// DNS resource record types used by the accelerator.
enum class RecordType : std::uint16_t {
    A = 1,
    CNAME = 5,
    AAAA = 28,
};

enum class Rcode : std::uint8_t {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,   // NXDOMAIN
    NotImplemented = 4,
    Refused = 5,
};

struct Question {
    std::string name;
    RecordType type = RecordType::A;
};

struct Answer {
    std::string name;
    RecordType type = RecordType::A;
    std::uint32_t ttl = 0;
    /// For A/AAAA: raw address bytes (4 or 16), `address_length` valid bytes.
    std::optional<std::array<std::uint8_t, 16>> address;
    std::uint8_t address_length = 0;
    /// For CNAME: the canonical target.
    std::optional<std::string> cname;
};

struct Message {
    std::uint16_t id = 0;
    bool is_response = false;
    Rcode rcode = Rcode::NoError;
    bool truncated = false;
    std::vector<Question> questions;
    std::vector<Answer> answers;
};

/// Encode a single-question query in DNS wire format.
[[nodiscard]] std::vector<std::byte> encode_query(std::string_view name, RecordType type,
                                                  std::uint16_t id);

/// Encode with a freshly generated random transaction id.
[[nodiscard]] std::vector<std::byte> encode_query(std::string_view name, RecordType type);

/// Transaction id of a wire-format message, if it is long enough.
[[nodiscard]] std::optional<std::uint16_t> peek_id(std::span<const std::byte> message);

/// Parse a wire-format DNS message (with name compression).
[[nodiscard]] std::expected<Message, std::string> parse_message(std::span<const std::byte> message);

} // namespace ghacc::accel::dns
