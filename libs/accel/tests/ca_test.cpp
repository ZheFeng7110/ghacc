import std;
import boost.ut;
import ghacc.accel.ca.authority;

using namespace boost::ut;
using namespace ghacc::accel;

int main() {
    const auto directory = std::filesystem::temp_directory_path() / "ghacc-ca-test";
    std::error_code ec;
    std::filesystem::remove_all(directory, ec);

    auto ca = CertificateAuthority::load_or_create(directory);
    expect(ca.has_value());
    if (!ca) {
        std::println(std::cerr, "CA error: {}", ca.error());
        return 1;
    }

    "ca certificate is pem"_test = [&] {
        const std::string pem = ca->ca_certificate_pem();
        expect(pem.find("BEGIN CERTIFICATE") != std::string::npos);
        expect(pem.find("END CERTIFICATE") != std::string::npos);
    };

    "leaf is issued for a host"_test = [&] {
        auto leaf = ca->leaf_for("github.com");
        expect(leaf.has_value());
        if (!leaf) {
            std::println(std::cerr, "leaf error: {}", leaf.error());
            return;
        }
        expect((*leaf)->certificate_pem.find("BEGIN CERTIFICATE") != std::string::npos);
        expect((*leaf)->private_key_pem.find("PRIVATE KEY") != std::string::npos);
    };

    "leaf certificates are cached"_test = [&] {
        auto first = ca->leaf_for("github.com");
        auto second = ca->leaf_for("GitHub.com");  // case-insensitive
        expect(first.has_value() && second.has_value());
        if (first && second) expect(first->get() == second->get());
    };

    "distinct hosts get distinct leaves"_test = [&] {
        auto github = ca->leaf_for("github.com");
        auto steam = ca->leaf_for("store.steampowered.com");
        expect(github.has_value() && steam.has_value());
        if (github && steam) expect(github->get() != steam->get());
    };

    "reloading reuses the same ca"_test = [&] {
        auto again = CertificateAuthority::load_or_create(directory);
        expect(again.has_value());
        if (again) expect(again->ca_certificate_pem() == ca->ca_certificate_pem());
    };

    std::filesystem::remove_all(directory, ec);
    return 0;
}
