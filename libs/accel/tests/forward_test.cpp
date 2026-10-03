#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

import std;
import boost.ut;
import asio;
import ghacc.accel;

using namespace boost::ut;
using namespace ghacc::accel;

namespace {

using tcp = asio::ip::tcp;
constexpr std::size_t npos = std::string::npos;

/// Install a PEM certificate/key pair onto a server context (asio's exported
/// context surface lacks the file-format enumerators).
void install_leaf(asio::ssl::context& context, const std::string& certificate_pem,
                  const std::string& key_pem) {
    SSL_CTX* raw = context.native_handle();
    BIO* cert_bio =
        BIO_new_mem_buf(certificate_pem.data(), static_cast<int>(certificate_pem.size()));
    X509* certificate = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);
    BIO* key_bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);
    if (certificate != nullptr) {
        SSL_CTX_use_certificate(raw, certificate);
        X509_free(certificate);
    }
    if (key != nullptr) {
        SSL_CTX_use_PrivateKey(raw, key);
        EVP_PKEY_free(key);
    }
}

std::shared_ptr<tcp::acceptor> make_listener(asio::io_context& io, std::uint16_t& port) {
    auto acceptor = std::make_shared<tcp::acceptor>(io);
    std::error_code ec;
    const tcp::endpoint endpoint(asio::ip::make_address("127.0.0.1"), 0);
    acceptor->open(endpoint.protocol(), ec);
    acceptor->set_option(asio::socket_base::reuse_address(true), ec);
    acceptor->bind(endpoint, ec);
    acceptor->listen(asio::socket_base::max_listen_connections, ec);
    port = acceptor->local_endpoint().port();
    return acceptor;
}

std::string ok_response(std::string_view body) {
    return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + std::string(body);
}

template <class Stream>
asio::awaitable<bool> read_head(Stream& stream) {
    std::string buffer;
    std::array<char, 4096> chunk{};
    for (;;) {
        if (buffer.find("\r\n\r\n") != npos) co_return true;
        std::error_code ec;
        const std::size_t n = co_await stream.async_read_some(
            asio::buffer(chunk), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0) co_return false;
        buffer.append(chunk.data(), n);
    }
}

template <class Stream>
asio::awaitable<void> serve_one(Stream& stream, std::string body) {
    if (!co_await read_head(stream)) co_return;
    std::error_code ec;
    co_await asio::async_write(stream, asio::buffer(ok_response(body)),
                               asio::redirect_error(asio::use_awaitable, ec));
}

asio::awaitable<void> plain_upstream(std::shared_ptr<tcp::acceptor> acceptor, std::string body) {
    for (;;) {
        std::error_code ec;
        auto socket = co_await acceptor->async_accept(asio::redirect_error(asio::use_awaitable, ec));
        if (ec) co_return;
        asio::co_spawn(acceptor->get_executor(),
                       [](tcp::socket s, std::string b) -> asio::awaitable<void> {
                           co_await serve_one(s, std::move(b));
                       }(std::move(socket), body),
                       asio::detached);
    }
}

asio::awaitable<void> tls_upstream(std::shared_ptr<tcp::acceptor> acceptor,
                                   std::shared_ptr<asio::ssl::context> context, std::string body) {
    for (;;) {
        std::error_code ec;
        auto socket = co_await acceptor->async_accept(asio::redirect_error(asio::use_awaitable, ec));
        if (ec) co_return;
        asio::co_spawn(acceptor->get_executor(),
                       [](tcp::socket s, std::shared_ptr<asio::ssl::context> ctx,
                          std::string b) -> asio::awaitable<void> {
                           asio::ssl::stream<tcp::socket> stream(std::move(s), *ctx);
                           std::error_code ec;
                           co_await stream.async_handshake(
                               asio::ssl::stream_base::server,
                               asio::redirect_error(asio::use_awaitable, ec));
                           if (ec) co_return;
                           co_await serve_one(stream, std::move(b));
                           std::error_code shutdown_ec;
                           co_await stream.async_shutdown(
                               asio::redirect_error(asio::use_awaitable, shutdown_ec));
                       }(std::move(socket), context, body),
                       asio::detached);
    }
}

// --- blocking clients -----------------------------------------------------

void connect_to(tcp::socket& socket, std::uint16_t port, std::error_code& ec) {
    socket.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
}

std::string blocking_request(std::uint16_t port, const std::string& request) {
    asio::io_context io;
    tcp::socket socket(io);
    std::error_code ec;
    connect_to(socket, port, ec);
    if (ec) return "<connect-error:" + ec.message() + ">";
    asio::write(socket, asio::buffer(request), ec);
    std::string response;
    std::array<char, 4096> chunk{};
    for (;;) {
        const std::size_t n = socket.read_some(asio::buffer(chunk), ec);
        if (n > 0) response.append(chunk.data(), n);
        if (ec || n == 0) break;
    }
    return response;
}

std::string read_head_only(tcp::socket& socket, std::error_code& ec) {
    std::string head;
    std::array<char, 1024> chunk{};
    while (head.find("\r\n\r\n") == npos) {
        const std::size_t n = socket.read_some(asio::buffer(chunk), ec);
        if (ec || n == 0) break;
        head.append(chunk.data(), n);
    }
    return head;
}

std::string connect_tunnel(std::uint16_t proxy_port, const std::string& authority,
                           const std::string& after) {
    asio::io_context io;
    tcp::socket socket(io);
    std::error_code ec;
    connect_to(socket, proxy_port, ec);
    if (ec) return "<connect-error:" + ec.message() + ">";
    const std::string connect_request =
        "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n";
    asio::write(socket, asio::buffer(connect_request), ec);
    const std::string head = read_head_only(socket, ec);
    if (head.find("200") == npos || after.empty()) return head;

    asio::write(socket, asio::buffer(after), ec);
    std::string response;
    std::array<char, 4096> chunk{};
    for (;;) {
        const std::size_t n = socket.read_some(asio::buffer(chunk), ec);
        if (n > 0) response.append(chunk.data(), n);
        if (ec || n == 0) break;
    }
    return head + "\n---\n" + response;
}

std::string connect_mitm(std::uint16_t proxy_port, const std::string& authority,
                         const std::string& sni, const std::filesystem::path& ca_file,
                         const std::string& request) {
    asio::io_context io;
    tcp::socket socket(io);
    std::error_code ec;
    connect_to(socket, proxy_port, ec);
    if (ec) return "<connect-error:" + ec.message() + ">";
    const std::string connect_request =
        "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n";
    asio::write(socket, asio::buffer(connect_request), ec);
    const std::string head = read_head_only(socket, ec);
    if (head.find("200") == npos) return head;

    asio::ssl::context context(asio::ssl::context::tls_client);
    context.load_verify_file(ca_file.string(), ec);
    if (ec) return "<ca-load-error:" + ec.message() + ">";
    asio::ssl::stream<tcp::socket> stream(std::move(socket), context);
    SSL_set_tlsext_host_name(stream.native_handle(), sni.c_str());
    stream.set_verify_callback(asio::ssl::host_name_verification(sni));
    stream.handshake(asio::ssl::stream_base::client, ec);
    if (ec) return "<handshake-error:" + ec.message() + ">";

    asio::write(stream, asio::buffer(request), ec);
    std::string response;
    std::array<char, 4096> chunk{};
    for (;;) {
        const std::size_t n = stream.read_some(asio::buffer(chunk), ec);
        if (n > 0) response.append(chunk.data(), n);
        if (ec || n == 0) break;
    }
    return response;
}

} // namespace

int main() {
    const auto directory = std::filesystem::temp_directory_path() / "ghacc-forward-test";
    std::error_code ec;
    std::filesystem::remove_all(directory, ec);

    auto ca = CertificateAuthority::load_or_create(directory / "ca");
    if (!ca) {
        std::println(std::cerr, "CA error: {}", ca.error());
        return 1;
    }

    asio::io_context io;
    FlowAnalyzer flow;
    RequestLog requests;

    std::uint16_t plain_port = 0;
    auto plain_acceptor = make_listener(io, plain_port);
    asio::co_spawn(io, plain_upstream(plain_acceptor, "hello-plain"), asio::detached);

    std::uint16_t tls_port = 0;
    auto tls_acceptor = make_listener(io, tls_port);
    auto tls_context = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server);
    auto leaf = ca->leaf_for("test.local");
    if (!leaf) {
        std::println(std::cerr, "leaf error: {}", leaf.error());
        return 1;
    }
    install_leaf(*tls_context, (*leaf)->certificate_pem, (*leaf)->private_key_pem);
    asio::co_spawn(io, tls_upstream(tls_acceptor, tls_context, "hello-tls"), asio::detached);

    RuleSet rules;
    {
        DomainRule mitm;
        mitm.pattern = "test.local";
        mitm.ip = "127.0.0.1";
        rules.add(mitm);

        DomainRule blocked;
        blocked.pattern = "blocked.local";
        blocked.action = RuleAction::Block;
        rules.add(blocked);
    }

    EngineOptions options;
    options.listen_address = "127.0.0.1";
    options.enable_http = false;
    options.enable_https = false;
    options.enable_forward = true;
    options.enable_pac = true;
    options.proxy_port = 0;
    options.upstream_http_port = plain_port;
    options.upstream_https_port = tls_port;
    options.upstream_tls_verify = false;
    options.dns.doh.clear();  // stay offline: system resolver only

    ProxyEngine engine(io, options, std::move(rules), *ca, flow, requests);
    engine.start();
    const auto ports = engine.listening_ports();
    if (ports.size() != 1) {
        std::println(std::cerr, "unexpected listener count: {}", ports.size());
        return 1;
    }
    const std::uint16_t proxy_port = ports[0];

    std::thread io_thread([&io] { io.run(); });

    "absolute-URI http is forwarded"_test = [&] {
        const std::string response = blocking_request(
            proxy_port, "GET http://127.0.0.1:" + std::to_string(plain_port) +
                            "/hello HTTP/1.1\r\nHost: 127.0.0.1:" +
                            std::to_string(plain_port) + "\r\nConnection: close\r\n\r\n");
        expect(response.find("200 OK") != npos);
        expect(response.find("hello-plain") != npos);
    };

    "CONNECT creates a plain tunnel"_test = [&] {
        const std::string response = connect_tunnel(
            proxy_port, "127.0.0.1:" + std::to_string(plain_port),
            "GET /tunnel HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        expect(response.find("200 Connection Established") != npos);
        expect(response.find("hello-plain") != npos);
    };

    "CONNECT + TLS interception forwards with a trusted leaf"_test = [&] {
        const std::string response =
            connect_mitm(proxy_port, "test.local:" + std::to_string(tls_port), "test.local",
                         ca->ca_certificate_path(),
                         "GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n");
        expect(response.find("200 OK") != npos) << response;
        expect(response.find("hello-tls") != npos);
    };

    "block rule returns 403 through the proxy"_test = [&] {
        const std::string response = blocking_request(
            proxy_port,
            "GET http://blocked.local/ HTTP/1.1\r\nHost: blocked.local\r\nConnection: close\r\n\r\n");
        expect(response.find("403") != npos);
        expect(response.find("hello") == npos);
    };

    "pac is served with the bound proxy port"_test = [&] {
        const std::string response = blocking_request(
            proxy_port, "GET /pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        expect(response.find("application/x-ns-proxy-autoconfig") != npos);
        expect(response.find("FindProxyForURL") != npos);
        expect(response.find("PROXY 127.0.0.1:" + std::to_string(proxy_port)) != npos);
    };

    "forwarded requests are recorded"_test = [&] {
        const auto records = requests.tail(32);
        bool saw_mitm = false;
        bool saw_plain = false;
        for (const auto& record : records) {
            if (record.host == "test.local" && record.status == 200 && record.accelerated) {
                saw_mitm = true;
            }
            if (record.status == 200 && !record.accelerated) saw_plain = true;
        }
        expect(saw_mitm);
        expect(saw_plain);
    };

    engine.request_stop();
    io.stop();
    io_thread.join();
    std::filesystem::remove_all(directory, ec);
    return 0;
}
