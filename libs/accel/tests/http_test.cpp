import std;
import boost.ut;
import ghacc.accel.http.message;
import ghacc.accel.http.parser;
import ghacc.accel.http.writer;

using namespace boost::ut;
using namespace ghacc::accel;
using namespace ghacc::accel::http;

int main() {
    "request head parses"_test = [] {
        auto request = parse_request_head(
            "GET /repos HTTP/1.1\r\nHost: api.github.com\r\nAccept: */*\r\n");
        expect(request.has_value());
        if (!request) return;
        expect(request->method == "GET");
        expect(request->target == "/repos");
        expect(request->version == "HTTP/1.1");
        expect(request->headers.get("host").value_or("") == "api.github.com");
        expect(request->headers.get("HOST").value_or("") == "api.github.com");  // case-insensitive
        expect(request->headers.get("accept").value_or("") == "*/*");
    };

    "request head rejects garbage"_test = [] {
        expect(!parse_request_head("NOT A REQUEST LINE").has_value());
        expect(!parse_request_head("GET /only-two").has_value());
    };

    "response head parses"_test = [] {
        auto response = parse_response_head(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://x/\r\nContent-Length: 0\r\n");
        expect(response.has_value());
        if (!response) return;
        expect(response->status == 301);
        expect(response->reason == "Moved Permanently");
        expect(response->headers.get("location").value_or("") == "https://x/");
    };

    "content-length body framing"_test = [] {
        Request request;
        request.method = "POST";
        request.headers.set("Content-Length", "42");
        auto info = request_body_info(request);
        expect(info.has_value());
        if (info) {
            expect(info->framing == BodyFraming::ContentLength);
            expect(info->length == 42_u);
        }
    };

    "chunked body framing"_test = [] {
        Request request;
        request.headers.set("Transfer-Encoding", "chunked");
        auto info = request_body_info(request);
        expect(info.has_value());
        if (info) expect(info->framing == BodyFraming::Chunked);
    };

    "response framing rules"_test = [] {
        Request get;
        get.method = "GET";

        Request head;
        head.method = "HEAD";
        Response ok;
        ok.status = 200;
        ok.headers.set("Content-Length", "10");
        auto head_info = response_body_info(head, ok);
        expect(head_info.has_value());
        if (head_info) expect(head_info->framing == BodyFraming::None);

        Response no_content;
        no_content.status = 204;
        auto nc_info = response_body_info(get, no_content);
        expect(nc_info.has_value());
        if (nc_info) expect(nc_info->framing == BodyFraming::None);

        Response until_close;
        until_close.status = 200;
        auto uc_info = response_body_info(get, until_close);
        expect(uc_info.has_value());
        if (uc_info) expect(uc_info->framing == BodyFraming::UntilClose);
    };

    "chunked scanner consumes a whole body"_test = [] {
        const std::string body = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        ChunkedScanner scanner;
        std::size_t consumed = 0;
        // Feed one byte at a time to exercise state across boundaries.
        for (char c : body) {
            consumed += scanner.consume(std::string_view(&c, 1));
            expect(!scanner.failed());
        }
        expect(scanner.done());
        expect(consumed == body.size());
    };

    "chunked scanner handles extensions and trailers"_test = [] {
        const std::string body =
            "5;name=value\r\nhello\r\n0\r\nX-Trailer: yes\r\n\r\n";
        ChunkedScanner scanner;
        const std::size_t consumed = scanner.consume(body);
        expect(!scanner.failed());
        expect(scanner.done());
        expect(consumed == body.size());
    };

    "chunked scanner reports protocol errors"_test = [] {
        ChunkedScanner scanner;
        scanner.consume("zz\r\n");
        expect(scanner.failed());
    };

    "serialize round trips through parse"_test = [] {
        Request request;
        request.method = "POST";
        request.target = "/upload?x=1";
        request.headers.set("Host", "example.com");
        request.headers.set("Content-Length", "3");

        const std::string head = serialize_request(request);
        auto parsed = parse_request_head(
            std::string_view(head).substr(0, head.size() - 2));  // drop trailing CRLF
        expect(parsed.has_value());
        if (parsed) {
            expect(parsed->method == "POST");
            expect(parsed->target == "/upload?x=1");
            expect(parsed->headers.get("host").value_or("") == "example.com");
        }

        Response response;
        response.status = 200;
        response.reason = "OK";
        response.headers.set("Content-Length", "0");
        const std::string out = serialize_response(response);
        expect(out.find("HTTP/1.1 200 OK\r\n") == 0);
    };

    return 0;
}
