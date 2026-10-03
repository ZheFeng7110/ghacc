export module ghacc.accel.ca.authority;

import std;

export namespace ghacc::accel {

/// A PEM-encoded certificate with its private key.
struct CertificatePair {
    std::string certificate_pem;
    std::string private_key_pem;
};

/// Local certificate authority used for TLS interception (MITM).
///
/// The root certificate and key live in `<dir>/ca.crt` and `<dir>/ca.key`
/// (0600). Per-host leaf certificates are signed on demand and cached.
class CertificateAuthority {
public:
    static std::expected<CertificateAuthority, std::string> load_or_create(
        const std::filesystem::path& directory);

    CertificateAuthority(CertificateAuthority&&) noexcept;
    CertificateAuthority& operator=(CertificateAuthority&&) noexcept;
    CertificateAuthority(const CertificateAuthority&) = delete;
    CertificateAuthority& operator=(const CertificateAuthority&) = delete;
    ~CertificateAuthority();

    [[nodiscard]] std::string ca_certificate_pem() const;
    [[nodiscard]] std::string ca_private_key_pem() const;
    [[nodiscard]] const std::filesystem::path& directory() const noexcept;

    /// PEM files written next to the CA (for `ghacc ca export`).
    [[nodiscard]] std::filesystem::path ca_certificate_path() const;
    [[nodiscard]] std::filesystem::path ca_private_key_path() const;

    /// Issue (or fetch from cache) a leaf certificate for `host`.
    [[nodiscard]] std::expected<std::shared_ptr<const CertificatePair>, std::string> leaf_for(
        std::string_view host) const;

    /// Write the CA certificate to `path`.
    [[nodiscard]] std::expected<void, std::string> export_certificate(
        const std::filesystem::path& path) const;

private:
    explicit CertificateAuthority(std::unique_ptr<class CertificateAuthorityImpl> impl);

    std::unique_ptr<class CertificateAuthorityImpl> impl_;
};

} // namespace ghacc::accel
