import std;
import boost.ut;
import ghacc.accel.net.dns;

using namespace boost::ut;
using namespace ghacc::accel::dns;

namespace {

void push_u16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>(value >> 8));
    out.push_back(static_cast<std::byte>(value & 0xFF));
}

void push_u32(std::vector<std::byte>& out, std::uint32_t value) {
    out.push_back(static_cast<std::byte>(value >> 24));
    out.push_back(static_cast<std::byte>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(value & 0xFF));
}

void push_name(std::vector<std::byte>& out, std::string_view name) {
    std::size_t start = 0;
    while (start < name.size()) {
        auto dot = name.find('.', start);
        const std::size_t end = dot == std::string_view::npos ? name.size() : dot;
        out.push_back(static_cast<std::byte>(end - start));
        for (std::size_t i = start; i < end; ++i) out.push_back(static_cast<std::byte>(name[i]));
        if (dot == std::string_view::npos) break;
        start = dot + 1;
    }
    out.push_back(std::byte{0});
}

std::vector<std::byte> make_a_response(std::uint16_t id, std::string_view host,
                                       std::initializer_list<std::array<std::uint8_t, 4>> ips) {
    std::vector<std::byte> out;
    push_u16(out, id);
    push_u16(out, 0x8180);  // response, recursion available, no error
    push_u16(out, 1);       // questions
    push_u16(out, static_cast<std::uint16_t>(ips.size()));
    push_u16(out, 0);
    push_u16(out, 0);
    push_name(out, host);
    push_u16(out, 1);  // A
    push_u16(out, 1);  // IN
    for (const auto& ip : ips) {
        push_u16(out, 0xC00C);  // pointer to the question name
        push_u16(out, 1);       // A
        push_u16(out, 1);       // IN
        push_u32(out, 300);     // TTL
        push_u16(out, 4);       // RDLENGTH
        for (auto b : ip) out.push_back(static_cast<std::byte>(b));
    }
    return out;
}

} // namespace

int main() {
    "encode query"_test = [] {
        auto wire = encode_query("example.com", RecordType::A, 0x1234);
        expect(peek_id(wire).value() == 4660_u);  // 0x1234
        // header(12) + (1+7)+(1+3)+1 name + qtype(2) + qclass(2) == 29
        expect(wire.size() == 29_u);
        expect(wire[12] == std::byte{7});
    };

    "parse an A record"_test = [] {
        const auto wire = make_a_response(0xABCD, "example.com", {{{93, 184, 216, 34}}});
        auto parsed = parse_message(wire);
        expect(parsed.has_value());
        if (!parsed) return;

        expect(parsed->id == 43981_u);  // 0xABCD
        expect(parsed->is_response);
        expect(parsed->rcode == Rcode::NoError);
        expect(parsed->questions.size() == 1_u);
        expect(parsed->questions.front().name == std::string("example.com"));
        expect(parsed->answers.size() == 1_u);

        const auto& answer = parsed->answers.front();
        expect(answer.type == RecordType::A);
        expect(answer.ttl == 300_u);
        expect(answer.address.has_value());
        expect(answer.address_length == 4_u);
        expect((*answer.address)[0] == 93_u);
        expect((*answer.address)[3] == 34_u);
    };

    "parse multiple answers"_test = [] {
        const auto wire = make_a_response(1, "github.com", {{{1, 2, 3, 4}}, {{5, 6, 7, 8}}});
        auto parsed = parse_message(wire);
        expect(parsed.has_value());
        if (!parsed) return;
        expect(parsed->answers.size() == 2_u);
        expect((*parsed->answers[1].address)[0] == 5_u);
    };

    "truncated messages are rejected"_test = [] {
        const auto wire = make_a_response(1, "example.com", {{{1, 2, 3, 4}}});
        std::vector<std::byte> cut(wire.begin(), wire.begin() + 15);
        expect(!parse_message(cut).has_value());
    };

    "id mismatch is visible to the caller"_test = [] {
        const auto wire = encode_query("example.com", RecordType::AAAA, 42);
        expect(peek_id(wire).value() == 42_u);
    };

    return 0;
}
