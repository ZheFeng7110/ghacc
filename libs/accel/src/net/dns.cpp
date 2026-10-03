module ghacc.accel.net.dns;

import std;

namespace ghacc::accel::dns {

namespace {

using bytes = std::span<const std::byte>;

std::uint8_t at(bytes data, std::size_t offset) {
    return std::to_integer<std::uint8_t>(data[offset]);
}

std::uint16_t read_u16(bytes data, std::size_t offset) {
    return static_cast<std::uint16_t>((at(data, offset) << 8) | at(data, offset + 1));
}

std::uint32_t read_u32(bytes data, std::size_t offset) {
    return (static_cast<std::uint32_t>(at(data, offset)) << 24) |
           (static_cast<std::uint32_t>(at(data, offset + 1)) << 16) |
           (static_cast<std::uint32_t>(at(data, offset + 2)) << 8) |
           static_cast<std::uint32_t>(at(data, offset + 3));
}

void write_u16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(value & 0xFF));
}

void write_u32(std::vector<std::byte>& out, std::uint32_t value) {
    out.push_back(static_cast<std::byte>((value >> 24) & 0xFF));
    out.push_back(static_cast<std::byte>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(value & 0xFF));
}

void write_name(std::vector<std::byte>& out, std::string_view name) {
    std::size_t start = 0;
    while (start < name.size()) {
        auto dot = name.find('.', start);
        const std::size_t end = dot == std::string_view::npos ? name.size() : dot;
        const std::size_t length = end - start;
        if (length > 0) {
            out.push_back(static_cast<std::byte>(length));
            for (std::size_t i = start; i < end; ++i) {
                out.push_back(static_cast<std::byte>(name[i]));
            }
        }
        if (dot == std::string_view::npos) break;
        start = dot + 1;
    }
    out.push_back(std::byte{0});
}

/// Read a (possibly compressed) domain name starting at `position`.
/// On success `position` is advanced past the name in the original stream.
bool read_name(bytes data, std::size_t& position, std::string& out, int depth = 0) {
    if (depth > 32) return false;

    std::size_t cursor = position;
    std::size_t after = position;
    bool jumped = false;

    for (;;) {
        if (cursor >= data.size()) return false;
        const std::uint8_t length = at(data, cursor);

        if ((length & 0xC0) == 0xC0) {
            if (cursor + 1 >= data.size()) return false;
            const std::size_t pointer = ((length & 0x3F) << 8) | at(data, cursor + 1);
            if (!jumped) {
                after = cursor + 2;
                jumped = true;
            }
            if (pointer >= data.size() || pointer >= cursor) return false;  // no forward/loop
            cursor = pointer;
            continue;
        }
        if ((length & 0xC0) != 0) return false;

        if (length == 0) {
            ++cursor;
            break;
        }
        if (cursor + 1 + length > data.size()) return false;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(data.data()) + cursor + 1, length);
        cursor += 1 + length;
    }

    position = jumped ? after : cursor;
    return true;
}

std::uint16_t random_id() {
    static std::mt19937 rng{std::random_device{}()};
    return static_cast<std::uint16_t>(rng() & 0xFFFF);
}

} // namespace

std::vector<std::byte> encode_query(std::string_view name, RecordType type, std::uint16_t id) {
    std::vector<std::byte> out;
    out.reserve(12 + name.size() + 6);
    write_u16(out, id);
    write_u16(out, 0x0100);  // standard query, recursion desired
    write_u16(out, 1);       // QDCOUNT
    write_u16(out, 0);       // ANCOUNT
    write_u16(out, 0);       // NSCOUNT
    write_u16(out, 0);       // ARCOUNT
    write_name(out, name);
    write_u16(out, static_cast<std::uint16_t>(type));
    write_u16(out, 1);  // IN class
    return out;
}

std::vector<std::byte> encode_query(std::string_view name, RecordType type) {
    return encode_query(name, type, random_id());
}

std::optional<std::uint16_t> peek_id(bytes message) {
    if (message.size() < 2) return std::nullopt;
    return read_u16(message, 0);
}

std::expected<Message, std::string> parse_message(bytes data) {
    if (data.size() < 12) return std::unexpected("dns: truncated header");

    Message message;
    message.id = read_u16(data, 0);
    const std::uint16_t flags = read_u16(data, 2);
    message.is_response = (flags & 0x8000) != 0;
    message.truncated = (flags & 0x0200) != 0;
    message.rcode = static_cast<Rcode>(flags & 0x000F);

    const std::uint16_t qdcount = read_u16(data, 4);
    const std::uint16_t ancount = read_u16(data, 6);

    std::size_t offset = 12;
    for (std::uint16_t i = 0; i < qdcount; ++i) {
        Question question;
        if (!read_name(data, offset, question.name)) return std::unexpected("dns: bad question name");
        if (offset + 4 > data.size()) return std::unexpected("dns: truncated question");
        question.type = static_cast<RecordType>(read_u16(data, offset));
        offset += 4;  // QTYPE + QCLASS
        message.questions.push_back(std::move(question));
    }

    for (std::uint16_t i = 0; i < ancount; ++i) {
        Answer answer;
        if (!read_name(data, offset, answer.name)) return std::unexpected("dns: bad answer name");
        if (offset + 10 > data.size()) return std::unexpected("dns: truncated answer");
        answer.type = static_cast<RecordType>(read_u16(data, offset));
        answer.ttl = read_u32(data, offset + 4);
        const std::uint16_t rdlength = read_u16(data, offset + 8);
        const std::size_t rdata = offset + 10;
        if (rdata + rdlength > data.size()) return std::unexpected("dns: truncated rdata");

        switch (answer.type) {
            case RecordType::A:
                if (rdlength == 4) {
                    std::array<std::uint8_t, 16> bytes{};
                    for (int b = 0; b < 4; ++b) bytes[static_cast<std::size_t>(b)] = at(data, rdata + b);
                    answer.address = bytes;
                    answer.address_length = 4;
                }
                break;
            case RecordType::AAAA:
                if (rdlength == 16) {
                    std::array<std::uint8_t, 16> bytes{};
                    for (int b = 0; b < 16; ++b) bytes[static_cast<std::size_t>(b)] = at(data, rdata + b);
                    answer.address = bytes;
                    answer.address_length = 16;
                }
                break;
            case RecordType::CNAME: {
                std::size_t name_offset = rdata;
                std::string target;
                if (read_name(data, name_offset, target)) answer.cname = std::move(target);
                break;
            }
            default:
                break;
        }

        offset = rdata + rdlength;
        message.answers.push_back(std::move(answer));
    }

    return message;
}

} // namespace ghacc::accel::dns
