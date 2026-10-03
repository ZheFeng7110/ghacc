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

using asio::ip::tcp;

/// Install a PEM certificate/key pair onto a server context via OpenSSL
/// (asio's exported `context` surface does not expose file-format enumerators).
void install_leaf(asio::ssl::context& context, const std::string& certificate_pem,
                  const std::string& key_pem) {
    SSL_CTX* raw = context.native_handle();
    BIO* cert_bio = BIO_new_mem_buf(certificate_pem.data(), static_cast<int>(certificate_pem.size()));
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

template <class Stream>
asio::awaitable<std::string> read_request_head(Stream& stream) {
    std::string buffer;
    std::array<char, 4096> chunk{};
    for (;;) {
        const auto end = buffer.find("\r\n\r\n");
        if (end != std::string::npos) co_return buffer.substr(0, end);
        std::error_code ec;
        const std::size_t n = co_await stream.async_read_some(
            asio::buffer(chunk), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0) co_return buffer;
        buffer.append(chunk.data(), n);
    }
}

std::string ok_response(std::string_view body) {
    return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + std::string(body);
}

asio::awaitable<void> serve_plain_upstream(std::shared_ptr<tcp::acceptor> acceptor,
                                           std::string body, std::atomic<bool>* served) {
    std::error_code ec;
    auto socket = co_await acceptor->async_accept(asio::redirect_error(asio::use_awaitable, ec));
    if (ec) co_return;
    co_await read_request_head(socket);
    const std::string response = ok_response(body);
    co_await asio::async_write(socket, asio::buffer(response),
                               asio::redirect_error(asio::use_awaitable, ec));
    served->store(true);
}

asio::awaitable<void> serve_tls_upstream(std::shared_ptr<tcp::acceptor> acceptor,
                                         std::shared_ptr<asio::ssl::context> context,
                                         std::string body, std::atomic<bool>* served) {
    std::error_code ec;
    auto socket = co_await acceptor->async_accept(asio::redirect_error(asio::use_awaitable, ec));
    if (ec) co_return;
    asio::ssl::stream<tcp::socket> stream(std::move(socket), *context);
    co_await stream.async_handshake(asio::ssl::stream_base::server,
                                    asio::redirect_error(asio::use_awaitable, ec));
    if (ec) co_return;
    co_await read_request_head(stream);
    const std::string response = ok_response(body);
    co_await asio::async_write(stream, asio::buffer(response),
                               asio::redirect_error(asio::use_awaitable, ec));
    served->store(true);
    std::error_code shutdown_ec;
    co_await stream.async_shutdown(asio::redirect_error(asio::use_awaitable, shutdown_ec));
}

std::string plain_request(std::uint16_t port, const std::string& host, const std::string& path) {
    asio::io_context io;
    tcp::socket socket(io);
    std::error_code ec;
    socket.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    if (ec) return "<connect-error:" + ec.message() + ">";
    const std::string request =
        "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
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

std::string tls_request(std::uint16_t port, const std::string& sni, const std::string& host,
                        const std::string& path, const std::filesystem::path& ca_file) {
    asio::io_context io;
    asio::ssl::context context(asio::ssl::context::tls_client);
    std::error_code ec;
    context.load_verify_file(ca_file.string(), ec);
    if (ec) return "<ca-load-error:" + ec.message() + ">";
    asio::ssl::stream<tcp::socket> stream(io, context);
    SSL_set_tlsext_host_name(stream.native_handle(), sni.c_str());
    stream.set_verify_callback(asio::ssl::host_name_verification(sni));
    stream.next_layer().connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    if (ec) return "<connect-error:" + ec.message() + ">";
    stream.handshake(asio::ssl::stream_base::client, ec);
    if (ec) return "<handshake-error:" + ec.message() + ">";
    const std::string request =
        "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
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
    const auto directory = std::filesystem::temp_directory_path() / "ghacc-engine-test";
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

    // Plain-text upstream.
    std::uint16_t plain_port = 0;
    auto plain_acceptor = make_listener(io, plain_port);
    std::atomic<bool> plain_served{false};
    asio::co_spawn(io, serve_plain_upstream(plain_acceptor, "hello-plain", &plain_served),
                   asio::detached);

    // TLS upstream presenting a leaf signed by our CA.
    std::uint16_t tls_port = 0;
    auto tls_acceptor = make_listener(io, tls_port);
    auto tls_context = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server);
    auto leaf = ca->leaf_for("localhost");
    if (!leaf) {
        std::println(std::cerr, "leaf error: {}", leaf.error());
        return 1;
    }
    install_leaf(*tls_context, (*leaf)->certificate_pem, (*leaf)->private_key_pem);
    std::atomic<bool> tls_served{false};
    asio::co_spawn(io, serve_tls_upstream(tls_acceptor, tls_context, "hello-tls", &tls_served),
                   asio::detached);

    RuleSet rules;
    {
        DomainRule proxy;
        proxy.pattern = "test.local";
        proxy.ip = "127.0.0.1";
        rules.add(proxy);

        DomainRule mitm;
        mitm.pattern = "github.com";
        mitm.ip = "127.0.0.1";
        rules.add(mitm);

        DomainRule blocked;
        blocked.pattern = "blocked.local";
        blocked.action = RuleAction::Block;
        rules.add(blocked);
    }

    EngineOptions options;
    options.listen_address = "127.0.0.1";
    options.http_port = 0;
    options.https_port = 0;
    options.upstream_http_port = plain_port;
    options.upstream_https_port = tls_port;
    options.upstream_tls_verify = false;

    ProxyEngine engine(io, options, std::move(rules), *ca, flow, requests);
    engine.start();
    const auto ports = engine.listening_ports();
    if (ports.size() != 2) {
        std::println(std::cerr, "unexpected listener count: {}", ports.size());
        return 1;
    }
    const std::uint16_t http_port = ports[0];
    const std::uint16_t https_port = ports[1];

    std::thread io_thread([&io] { io.run(); });

    "plain reverse proxy forwards the response"_test = [&] {
        const std::string response = plain_request(http_port, "test.local", "/");
        expect(response.find("200 OK") != std::string::npos);
        expect(response.find("hello-plain") != std::string::npos);
        expect(plain_served.load());
    };

    "block rule returns 403 without contacting upstream"_test = [&] {
        const std::string response = plain_request(http_port, "blocked.local", "/");
        expect(response.find("403") != std::string::npos);
        expect(response.find("hello-plain") == std::string::npos);
    };

    "TLS MITM issues a trusted leaf certificate and forwards"_test = [&] {
        const std::string response =
            tls_request(https_port, "github.com", "github.com", "/", ca->ca_certificate_path());
        expect(response.find("200 OK") != std::string::npos);
        expect(response.find("hello-tls") != std::string::npos);
        expect(tls_served.load());
    };

    "proxied requests are recorded"_test = [&] {
        const auto records = requests.tail(16);
        bool saw_plain = false;
        bool saw_mitm = false;
        for (const auto& record : records) {
            if (record.host == "test.local" && record.status == 200) saw_plain = true;
            if (record.host == "github.com" && record.status == 200) saw_mitm = true;
        }
        expect(saw_plain);
        expect(saw_mitm);
    };

    engine.request_stop();
    io.stop();
    io_thread.join();
    std::filesystem::remove_all(directory, ec);
    return 0;
}
