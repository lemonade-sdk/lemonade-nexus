#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdio>
#include <memory>

namespace nexus::security {

namespace {

template <typename T, void (*F)(T*)>
struct Free { void operator()(T* p) const { if (p) F(p); } };

using X509Ptr      = std::unique_ptr<X509, Free<X509, X509_free>>;
using StorePtr     = std::unique_ptr<X509_STORE, Free<X509_STORE, X509_STORE_free>>;
using StoreCtxPtr  = std::unique_ptr<X509_STORE_CTX, Free<X509_STORE_CTX, X509_STORE_CTX_free>>;
using StackPtr     = std::unique_ptr<STACK_OF(X509), Free<STACK_OF(X509), [](STACK_OF(X509)* s) { sk_X509_free(s); }>>;
using SigPtr       = std::unique_ptr<ECDSA_SIG, Free<ECDSA_SIG, ECDSA_SIG_free>>;
using MdCtxPtr     = std::unique_ptr<EVP_MD_CTX, Free<EVP_MD_CTX, EVP_MD_CTX_free>>;
using BioPtr       = std::unique_ptr<BIO, Free<BIO, BIO_free_all>>;

/// OPENSSL_free is a macro, so it cannot be named in a decltype deleter.
struct OpenSslFree {
    void operator()(unsigned char* p) const { OPENSSL_free(p); }
};

SnpVerifyResult fail(std::string why) { return {false, std::move(why)}; }
SnpVerifyResult pass() { return {true, {}}; }

/// AMD Root Key, Milan (EPYC 7003 / Zen 3). Self-signed, valid to 2045.
/// SHA-256 fingerprint 69:D0:63:B4:53:44:D2:6A:2E:94:E1:F4:21:0D:E4:9E:
///                     F5:55:30:82:87:D4:C1:74:44:5C:95:63:9A:54:0B:CD
/// Compiled in on purpose: a root fetched at runtime is not a root.
constexpr std::string_view kArkMilan = R"(-----BEGIN CERTIFICATE-----
MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy
MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg
W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta
1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2
SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0
60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05
gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg
bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs
+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi
Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ
eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18
fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j
WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI
rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel
ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw
STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK
dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq
zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp
KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e
pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq
HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh
3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn
JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH
CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4
AFZEAwoKCQ==
-----END CERTIFICATE-----
)";

std::vector<X509Ptr> parse_pem_chain(std::string_view pem) {
    std::vector<X509Ptr> out;
    BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    if (!bio) return out;
    while (X509* c = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) {
        out.emplace_back(c);
    }
    return out;
}

/// SNP stores r and s little-endian, zero-padded to 72 bytes. OpenSSL wants DER.
SigPtr ecdsa_sig_from_snp(std::span<const uint8_t> sig_field) {
    if (sig_field.size() < 2 * kSnpSigCompLen) return nullptr;

    auto to_bn = [](std::span<const uint8_t> le) -> BIGNUM* {
        std::vector<uint8_t> be(le.rbegin(), le.rend());
        return BN_bin2bn(be.data(), static_cast<int>(be.size()), nullptr);
    };

    BIGNUM* r = to_bn(sig_field.subspan(0, kSnpSigCompLen));
    BIGNUM* s = to_bn(sig_field.subspan(kSnpSigCompLen, kSnpSigCompLen));
    if (!r || !s) { BN_free(r); BN_free(s); return nullptr; }

    SigPtr sig{ECDSA_SIG_new()};
    if (!sig) { BN_free(r); BN_free(s); return nullptr; }
    ECDSA_SIG_set0(sig.get(), r, s);  // takes ownership
    return sig;
}

bool same_cert(X509* a, X509* b) { return a && b && X509_cmp(a, b) == 0; }

}  // namespace

std::string_view pinned_amd_root(std::string_view product) {
    if (product == "Milan") return kArkMilan;
    return {};  // Genoa/Turin roots get added when we have silicon to test against
}

std::string vcek_kds_url(const SnpReport& report, std::string_view product) {
    char buf[320];
    std::snprintf(buf, sizeof(buf),
                  "https://kdsintf.amd.com/vcek/v1/%.*s/%s"
                  "?blSPL=%u&teeSPL=%u&snpSPL=%u&ucodeSPL=%u",
                  static_cast<int>(product.size()), product.data(),
                  report.chip_id_hex().c_str(),
                  report.reported_tcb.bootloader, report.reported_tcb.tee,
                  report.reported_tcb.snp, report.reported_tcb.microcode);
    return buf;
}

SnpVerifyResult verify_snp_signature(const SnpReport& report,
                                      std::span<const uint8_t> vcek_der,
                                      std::string_view chain_pem) {
    if (report.raw.size() < kSnpReportSize) return fail("report truncated");
    if (report.signature_algo != 1) {
        return fail("unexpected signature algorithm " + std::to_string(report.signature_algo) +
                    " (only ECDSA P-384/SHA-384 is defined)");
    }
    if (vcek_der.empty()) return fail("no VCEK supplied");

    // --- leaf ---------------------------------------------------------------
    const unsigned char* p = vcek_der.data();
    X509Ptr vcek{d2i_X509(nullptr, &p, static_cast<long>(vcek_der.size()))};
    if (!vcek) return fail("VCEK is not a DER certificate");

    // --- chain: expect ASK then ARK ----------------------------------------
    auto chain = parse_pem_chain(chain_pem);
    if (chain.size() < 2) return fail("certificate chain must carry ASK and ARK");
    X509* ask = chain[0].get();
    X509* ark = chain[1].get();

    auto pinned = parse_pem_chain(pinned_amd_root("Milan"));
    if (pinned.empty()) return fail("no compiled-in AMD root for this product");
    if (!same_cert(ark, pinned[0].get())) {
        return fail("chain root is not the compiled-in AMD root key");
    }

    StorePtr store{X509_STORE_new()};
    if (!store || X509_STORE_add_cert(store.get(), ark) != 1) {
        return fail("could not build a trust store for the AMD root");
    }
    StackPtr untrusted{sk_X509_new_null()};
    if (!untrusted || sk_X509_push(untrusted.get(), ask) <= 0) {
        return fail("could not stage the AMD signing key");
    }
    StoreCtxPtr ctx{X509_STORE_CTX_new()};
    if (!ctx || X509_STORE_CTX_init(ctx.get(), store.get(), vcek.get(), untrusted.get()) != 1) {
        return fail("could not initialise chain verification");
    }
    if (X509_verify_cert(ctx.get()) != 1) {
        const int err = X509_STORE_CTX_get_error(ctx.get());
        return fail(std::string("VCEK does not chain to the AMD root: ") +
                    X509_verify_cert_error_string(err));
    }

    // --- the report signature itself ---------------------------------------
    auto sig = ecdsa_sig_from_snp(
        std::span<const uint8_t>(report.raw).subspan(kSnpSigOffset));
    if (!sig) return fail("malformed signature field");

    unsigned char* der = nullptr;
    const int der_len = i2d_ECDSA_SIG(sig.get(), &der);
    if (der_len <= 0 || !der) return fail("could not encode the signature");
    std::unique_ptr<unsigned char, OpenSslFree> der_guard{der};

    EVP_PKEY* pub = X509_get0_pubkey(vcek.get());  // borrowed
    if (!pub) return fail("VCEK carries no public key");

    MdCtxPtr md{EVP_MD_CTX_new()};
    if (!md || EVP_DigestVerifyInit(md.get(), nullptr, EVP_sha384(), nullptr, pub) != 1) {
        return fail("could not initialise signature verification");
    }
    const int rc = EVP_DigestVerify(md.get(), der, static_cast<std::size_t>(der_len),
                                    report.raw.data(), kSnpSignedLen);
    if (rc != 1) return fail("attestation report signature is not valid under the VCEK");

    return pass();
}

SnpVerifyResult verify_snp_policy(const SnpReport& report, const SnpPolicyRequirements& req) {
    if (req.require_debug_disabled && report.policy.debug) {
        return fail("guest policy allows DEBUG — the hypervisor can read guest memory");
    }
    if (req.require_no_migration_agent && report.policy.migrate_ma) {
        return fail("guest policy allows a migration agent — the guest can be moved "
                    "out of its encryption boundary");
    }
    if (req.require_vmpl0 && report.vmpl != 0) {
        return fail("report was requested at VMPL " + std::to_string(report.vmpl) +
                    ", expected VMPL 0");
    }
    if (!report.reported_tcb.at_least(req.min_tcb)) {
        return fail("platform TCB [" + report.reported_tcb.to_string() +
                    "] is below the required floor [" + req.min_tcb.to_string() + "]");
    }
    if (!req.expected_measurement_hex.empty() &&
        req.expected_measurement_hex != report.measurement_hex()) {
        return fail("launch measurement " + report.measurement_hex().substr(0, 16) +
                    "... does not match the pinned value");
    }
    return pass();
}

}  // namespace nexus::security
