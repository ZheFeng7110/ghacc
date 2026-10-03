module;
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

module ghacc.accel.ca.authority;

import std;

namespace ghacc::accel {

namespace {

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

std::string openssl_error() {
    std::string out;
    unsigned long code = 0;
    char buffer[256];
    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, buffer, sizeof(buffer));
        if (!out.empty()) out += "; ";
        out += buffer;
    }
    return out.empty() ? std::string("unknown OpenSSL error") : out;
}

std::string encode_certificate(X509* certificate) {
    BioPtr bio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!bio || PEM_write_bio_X509(bio.get(), certificate) != 1) return {};
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio.get(), &memory);
    return memory != nullptr ? std::string(memory->data, memory->length) : std::string{};
}

std::string encode_key(EVP_PKEY* key) {
    BioPtr bio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return {};
    }
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio.get(), &memory);
    return memory != nullptr ? std::string(memory->data, memory->length) : std::string{};
}

long random_serial() {
    static std::mt19937_64 rng{std::random_device{}()};
    return static_cast<long>(rng() & 0x7FFFFFFFFFFFFFFFULL);
}

bool add_extension(X509* certificate, X509* issuer, int nid, const std::string& value) {
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
    X509_EXTENSION* extension =
        X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value.c_str()));
    if (extension == nullptr) return false;
    const int ok = X509_add_ext(certificate, extension, -1);
    X509_EXTENSION_free(extension);
    return ok == 1;
}

void set_common_name(X509* certificate, const std::string& common_name) {
    X509_NAME* name = X509_get_subject_name(certificate);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(common_name.c_str()), -1, -1, 0);
}

std::string san_value(std::string_view host) {
    in_addr v4{};
    in6_addr v6{};
    const std::string text(host);
    if (inet_pton(AF_INET, text.c_str(), &v4) == 1 || inet_pton(AF_INET6, text.c_str(), &v6) == 1) {
        return "IP:" + text;
    }
    return "DNS:" + text;
}

X509Ptr make_ca_certificate(EVP_PKEY*& key_out) {
    KeyPtr key(EVP_RSA_gen(2048), &EVP_PKEY_free);
    if (!key) return {nullptr, &X509_free};

    X509Ptr certificate(X509_new(), &X509_free);
    if (!certificate) return {nullptr, &X509_free};

    X509_set_version(certificate.get(), 2);  // X.509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), random_serial());
    X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 60L * 60 * 24 * 365 * 10);
    set_common_name(certificate.get(), "ghacc Root CA");
    X509_set_issuer_name(certificate.get(), X509_get_subject_name(certificate.get()));
    X509_set_pubkey(certificate.get(), key.get());

    add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
    add_extension(certificate.get(), certificate.get(), NID_key_usage,
                  "critical,keyCertSign,cRLSign");
    add_extension(certificate.get(), certificate.get(), NID_subject_key_identifier, "hash");

    if (X509_sign(certificate.get(), key.get(), EVP_sha256()) == 0) return {nullptr, &X509_free};

    key_out = key.release();
    return certificate;
}

X509Ptr make_leaf_certificate(X509* issuer, EVP_PKEY* issuer_key, std::string_view host,
                              EVP_PKEY*& key_out) {
    KeyPtr key(EVP_RSA_gen(2048), &EVP_PKEY_free);
    if (!key) return {nullptr, &X509_free};

    X509Ptr certificate(X509_new(), &X509_free);
    if (!certificate) return {nullptr, &X509_free};

    X509_set_version(certificate.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), random_serial());
    X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60L * 60 * 24);       // yesterday
    X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 60L * 60 * 24 * 365);   // one year
    set_common_name(certificate.get(), std::string(host));
    X509_set_issuer_name(certificate.get(), X509_get_subject_name(issuer));
    X509_set_pubkey(certificate.get(), key.get());

    add_extension(certificate.get(), issuer, NID_basic_constraints, "critical,CA:FALSE");
    add_extension(certificate.get(), issuer, NID_key_usage,
                  "critical,digitalSignature,keyEncipherment");
    add_extension(certificate.get(), issuer, NID_ext_key_usage, "serverAuth");
    add_extension(certificate.get(), issuer, NID_subject_alt_name, san_value(host));
    add_extension(certificate.get(), issuer, NID_authority_key_identifier, "keyid,issuer");

    if (X509_sign(certificate.get(), issuer_key, EVP_sha256()) == 0) return {nullptr, &X509_free};

    key_out = key.release();
    return certificate;
}

} // namespace

class CertificateAuthorityImpl {
public:
    std::filesystem::path directory;
    X509Ptr certificate{nullptr, &X509_free};
    KeyPtr key{nullptr, &EVP_PKEY_free};
    mutable std::mutex mutex;
    mutable std::unordered_map<std::string, std::shared_ptr<const CertificatePair>> cache;
};

CertificateAuthority::CertificateAuthority(std::unique_ptr<CertificateAuthorityImpl> impl)
    : impl_(std::move(impl)) {}
CertificateAuthority::CertificateAuthority(CertificateAuthority&&) noexcept = default;
CertificateAuthority& CertificateAuthority::operator=(CertificateAuthority&&) noexcept = default;
CertificateAuthority::~CertificateAuthority() = default;

std::expected<CertificateAuthority, std::string> CertificateAuthority::load_or_create(
    const std::filesystem::path& directory) {
    auto impl = std::make_unique<CertificateAuthorityImpl>();
    impl->directory = directory;

    const auto cert_path = directory / "ca.crt";
    const auto key_path = directory / "ca.key";

    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec) return std::unexpected("cannot create CA directory: " + directory.string());

    if (std::filesystem::exists(cert_path, ec) && std::filesystem::exists(key_path, ec)) {
        BioPtr cert_bio(BIO_new_file(cert_path.string().c_str(), "r"), &BIO_free);
        BioPtr key_bio(BIO_new_file(key_path.string().c_str(), "r"), &BIO_free);
        if (!cert_bio || !key_bio) return std::unexpected("cannot open existing CA files");
        impl->certificate.reset(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
        impl->key.reset(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
        if (!impl->certificate || !impl->key) {
            return std::unexpected("cannot parse existing CA: " + openssl_error());
        }
        return CertificateAuthority(std::move(impl));
    }

    EVP_PKEY* raw_ca_key = nullptr;
    impl->certificate = make_ca_certificate(raw_ca_key);
    impl->key.reset(raw_ca_key);
    if (!impl->certificate || !impl->key) {
        return std::unexpected("cannot generate CA: " + openssl_error());
    }

    const std::string cert_pem = encode_certificate(impl->certificate.get());
    const std::string key_pem = encode_key(impl->key.get());
    if (cert_pem.empty() || key_pem.empty()) {
        return std::unexpected("cannot encode CA: " + openssl_error());
    }

    {
        std::ofstream cert_out(cert_path, std::ios::binary | std::ios::trunc);
        cert_out << cert_pem;
    }
    {
        std::ofstream key_out(key_path, std::ios::binary | std::ios::trunc);
        key_out << key_pem;
    }
    std::filesystem::permissions(key_path,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);

    return CertificateAuthority(std::move(impl));
}

std::string CertificateAuthority::ca_certificate_pem() const {
    return encode_certificate(impl_->certificate.get());
}

std::string CertificateAuthority::ca_private_key_pem() const {
    return encode_key(impl_->key.get());
}

const std::filesystem::path& CertificateAuthority::directory() const noexcept {
    return impl_->directory;
}

std::filesystem::path CertificateAuthority::ca_certificate_path() const {
    return impl_->directory / "ca.crt";
}

std::filesystem::path CertificateAuthority::ca_private_key_path() const {
    return impl_->directory / "ca.key";
}

std::expected<std::shared_ptr<const CertificatePair>, std::string>
CertificateAuthority::leaf_for(std::string_view host) const {
    std::string key(host);
    std::ranges::transform(key, key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    {
        std::lock_guard lock(impl_->mutex);
        if (auto it = impl_->cache.find(key); it != impl_->cache.end()) return it->second;
    }

    EVP_PKEY* raw_leaf_key = nullptr;
    X509Ptr leaf = make_leaf_certificate(impl_->certificate.get(), impl_->key.get(), host,
                                         raw_leaf_key);
    KeyPtr leaf_key(raw_leaf_key, &EVP_PKEY_free);
    if (!leaf || !leaf_key) return std::unexpected("cannot issue leaf for " + key + ": " + openssl_error());

    auto pair = std::make_shared<CertificatePair>();
    pair->certificate_pem = encode_certificate(leaf.get());
    pair->private_key_pem = encode_key(leaf_key.get());
    if (pair->certificate_pem.empty() || pair->private_key_pem.empty()) {
        return std::unexpected("cannot encode leaf for " + key);
    }

    {
        std::lock_guard lock(impl_->mutex);
        impl_->cache[key] = pair;
    }
    return pair;
}

std::expected<void, std::string> CertificateAuthority::export_certificate(
    const std::filesystem::path& path) const {
    std::error_code ec;
    if (auto parent = path.parent_path(); !parent.empty()) std::filesystem::create_directories(parent, ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return std::unexpected("cannot write certificate: " + path.string());
    out << ca_certificate_pem();
    return {};
}

} // namespace ghacc::accel
