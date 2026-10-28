#pragma once

// A self-signed "localhost" certificate for stand-in HTTPS servers. Listed in
// SSL_CERT_FILE it is a trust anchor, so the SDK's always-on certificate
// verification accepts the test server. The platform's default trust follows
// SSL_CERT_FILE on Linux; the macOS keychain ignores it, so tests probe first.

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <filesystem>

namespace test_support {

inline bool write_pem(const std::filesystem::path& path, const X509* cert, const EVP_PKEY* key) {
    FILE* f = std::fopen(path.string().c_str(), "wb");
    if (!f) return false;
    const bool ok = cert ? PEM_write_X509(f, cert)
                         : PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
    std::fclose(f);
    return ok;
}

/// Write a self-signed certificate for "localhost" (CN and SAN) valid for one
/// hour to `cert_p`, and its RSA key to `key_p`.
inline bool make_localhost_cert(const std::filesystem::path& cert_p,
                                const std::filesystem::path& key_p) {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    if (!key) return false;
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    for (const char* spec : {"critical,CA:TRUE", "DNS:localhost"}) {
        const int nid = spec[0] == 'D' ? NID_subject_alt_name : NID_basic_constraints;
        if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, nid, spec)) {
            X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    bool ok = X509_sign(x, key, EVP_sha256()) != 0;
    ok = ok && write_pem(cert_p, x, nullptr) && write_pem(key_p, nullptr, key);
    X509_free(x);
    EVP_PKEY_free(key);
    return ok;
}

}  // namespace test_support
