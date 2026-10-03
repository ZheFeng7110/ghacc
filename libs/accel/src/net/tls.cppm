export module ghacc.accel.net.tls;

import std;
import asio;
import ghacc.accel.ca.authority;

export namespace ghacc::accel {

/// Server-side TLS context for TLS interception (MITM).
///
/// Configured for TLS 1.2+, advertising ALPN `http/1.1`, with an SNI callback
/// that asks the `CertificateAuthority` for a per-host leaf certificate and
/// installs it on the handshaking connection.
class TlsServerContext {
public:
    explicit TlsServerContext(const CertificateAuthority& ca);
    TlsServerContext(TlsServerContext&&) noexcept;
    TlsServerContext& operator=(TlsServerContext&&) noexcept;
    TlsServerContext(const TlsServerContext&) = delete;
    TlsServerContext& operator=(const TlsServerContext&) = delete;
    ~TlsServerContext();

    [[nodiscard]] asio::ssl::context& context() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Load the platform's trusted roots into `context` for upstream verification.
void load_system_ca(asio::ssl::context& context);

} // namespace ghacc::accel
