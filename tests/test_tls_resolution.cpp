// resolve_tls_cert must resolve each listener's certificate independently from
// the ACME cert-on-disk for its OWN FQDN — the private listener's cert
// (private.<seip>) must never be the public SEIP cert. Certificates are always
// ACME-issued (public CA on the forced SEIP FQDN); there is no manual-cert path.

#include <LemonadeNexus/Core/ServerIdentity.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace nexus;

namespace {
void write_cert(const fs::path& dir, const char* body) {
    fs::create_directories(dir);
    { std::ofstream f(dir / "fullchain.pem"); f << body << "-cert"; }
    { std::ofstream f(dir / "privkey.pem");   f << body << "-key"; }
}
}  // namespace

TEST(TlsResolution, PublicAndPrivateResolveIndependently) {
    auto root = fs::temp_directory_path() / ("nexus_tlsres_" + std::to_string(getpid()));
    fs::remove_all(root);
    const std::string pub_fqdn  = "server-abc.eu-west.seip.lemonade-nexus.io";
    const std::string priv_fqdn = "private." + pub_fqdn;
    write_cert(root / "certs" / pub_fqdn,  "PUBLIC");
    write_cert(root / "certs" / priv_fqdn, "PRIVATE");

    auto pub  = core::resolve_tls_cert(root, pub_fqdn);
    auto priv = core::resolve_tls_cert(root, priv_fqdn);

    // Each listener gets its OWN on-disk ACME cert, and they never cross.
    EXPECT_NE(pub.cert_path, priv.cert_path);
    EXPECT_NE(pub.cert_path.find(pub_fqdn), std::string::npos);
    EXPECT_NE(priv.cert_path.find(priv_fqdn), std::string::npos);
    // The public resolution must NOT be the private cert (the reported bug).
    EXPECT_EQ(pub.cert_path.find("private."), std::string::npos);
    EXPECT_FALSE(pub.needs_acme_background);
    EXPECT_FALSE(priv.needs_acme_background);

    fs::remove_all(root);
}

TEST(TlsResolution, NoCertOnDiskRequestsBackground) {
    auto r = core::resolve_tls_cert(
        fs::temp_directory_path() / "nexus_no_such_dir_zzz", "no.such.fqdn.example");
    EXPECT_TRUE(r.cert_path.empty());
    EXPECT_TRUE(r.needs_acme_background);
}
