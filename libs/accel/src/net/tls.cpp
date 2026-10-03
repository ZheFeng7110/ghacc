module;
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

module ghacc.accel.net.tls;

import std;
import asio;
import ghacc.accel.ca.authority;

namespace ghacc::accel {

namespace {

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

X509Ptr parse_certificate(std::string_view pem) {
    if (pem.empty()) return {nullptr, &X509_free};
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) return {nullptr, &X509_free};
    X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {certificate, &X509_free};
}

KeyPtr parse_private_key(std::string_view pem) {
    if (pem.empty()) return {nullptr, &EVP_PKEY_free};
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) return {nullptr, &EVP_PKEY_free};
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {key, &EVP_PKEY_free};
}

bool install_on_ssl(SSL* ssl, const CertificatePair& pair) {
    auto certificate = parse_certificate(pair.certificate_pem);
    auto key = parse_private_key(pair.private_key_pem);
    if (!certificate || !key) return false;
    return SSL_use_certificate(ssl, certificate.get()) == 1 &&
           SSL_use_PrivateKey(ssl, key.get()) == 1;
}

} // namespace

struct TlsServerContext::Impl {
    asio::ssl::context context{asio::ssl::context::tls_server};
    const CertificateAuthority* ca = nullptr;

    static int servername_callback(SSL* ssl, int* alert, void* arg) {
        auto* self = static_cast<Impl*>(arg);
        if (self->ca == nullptr) {
            if (alert != nullptr) *alert = SSL_AD_INTERNAL_ERROR;
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        const std::string_view host = name != nullptr && *name != '\0' ? name : "localhost";
        auto leaf = self->ca->leaf_for(host);
        if (!leaf || !install_on_ssl(ssl, **leaf)) {
            if (alert != nullptr) *alert = SSL_AD_INTERNAL_ERROR;
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        return SSL_TLSEXT_ERR_OK;
    }

    static int alpn_select_callback(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                                    const unsigned char* in, unsigned int inlen, void* /*arg*/) {
        static constexpr unsigned char http11[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
        if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, http11,
                                  static_cast<unsigned int>(sizeof(http11)), in, inlen) ==
            OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_OK;
        }
        return SSL_TLSEXT_ERR_NOACK;
    }
};

TlsServerContext::TlsServerContext(const CertificateAuthority& ca) : impl_(std::make_unique<Impl>()) {
    impl_->ca = &ca;

    asio::error_code ec;
    impl_->context.set_options(asio::ssl::context::default_workarounds |
                                   asio::ssl::context::no_sslv2 |
                                   asio::ssl::context::no_sslv3 |
                                   asio::ssl::context::no_tlsv1 |
                                   asio::ssl::context::no_tlsv1_1,
                               ec);

    SSL_CTX* ctx = impl_->context.native_handle();
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_tlsext_servername_callback(ctx, &Impl::servername_callback);
    SSL_CTX_set_tlsext_servername_arg(ctx, impl_.get());
    SSL_CTX_set_alpn_select_cb(ctx, &Impl::alpn_select_callback, nullptr);

    // Fallback certificate for clients that send no SNI.
    if (auto fallback = ca.leaf_for("localhost")) {
        auto certificate = parse_certificate((*fallback)->certificate_pem);
        auto key = parse_private_key((*fallback)->private_key_pem);
        if (certificate && key) {
            SSL_CTX_use_certificate(ctx, certificate.get());
            SSL_CTX_use_PrivateKey(ctx, key.get());
        }
    }
}

TlsServerContext::TlsServerContext(TlsServerContext&&) noexcept = default;
TlsServerContext& TlsServerContext::operator=(TlsServerContext&&) noexcept = default;
TlsServerContext::~TlsServerContext() = default;

asio::ssl::context& TlsServerContext::context() noexcept { return impl_->context; }

void load_system_ca(asio::ssl::context& context) {
    std::error_code ec;
#if defined(__APPLE__)
    const char* candidates[] = {"/etc/ssl/cert.pem"};
#elif defined(_WIN32)
    const char* candidates[] = {nullptr};
#else
    const char* candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
    };
#endif
    for (const char* candidate : candidates) {
        if (candidate == nullptr) break;
        if (!std::filesystem::exists(candidate, ec)) continue;
        context.load_verify_file(candidate, ec);
        if (!ec) return;
    }
    context.set_default_verify_paths(ec);
}

} // namespace ghacc::accel
