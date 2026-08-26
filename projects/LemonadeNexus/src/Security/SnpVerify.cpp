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

/// AMD SEV Signing Key, Milan. Issued by the ARK above, and the only intermediate
/// any Milan VCEK chains through — the same bytes for every Milan chip. Pinning it
/// beside the root means the chain never has to travel with the evidence (it cost
/// 4.6 KB of a 65 KB gossip budget) and one more input stops coming off the wire.
constexpr std::string_view kAskMilan = R"(-----BEGIN CERTIFICATE-----
MIIGiTCCBDigAwIBAgIDAQABMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTgyNDIwWhcNNDUxMDIy
MTgyNDIwWjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJU0VWLU1pbGFuMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEAnU2drrNTfbhNQIllf+W2y+ROCbSzId1aKZft
2T9zjZQOzjGccl17i1mIKWl7NTcB0VYXt3JxZSzOZjsjLNVAEN2MGj9TiedL+Qew
KZX0JmQEuYjm+WKksLtxgdLp9E7EZNwNDqV1r0qRP5tB8OWkyQbIdLeu4aCz7j/S
l1FkBytev9sbFGzt7cwnjzi9m7noqsk+uRVBp3+In35QPdcj8YflEmnHBNvuUDJh
LCJMW8KOjP6++Phbs3iCitJcANEtW4qTNFoKW3CHlbcSCjTM8KsNbUx3A8ek5EVL
jZWH1pt9E3TfpR6XyfQKnY6kl5aEIPwdW3eFYaqCFPrIo9pQT6WuDSP4JCYJbZne
KKIbZjzXkJt3NQG32EukYImBb9SCkm9+fS5LZFg9ojzubMX3+NkBoSXI7OPvnHMx
jup9mw5se6QUV7GqpCA2TNypolmuQ+cAaxV7JqHE8dl9pWf+Y3arb+9iiFCwFt4l
AlJw5D0CTRTC1Y5YWFDBCrA/vGnmTnqG8C+jjUAS7cjjR8q4OPhyDmJRPnaC/ZG5
uP0K0z6GoO/3uen9wqshCuHegLTpOeHEJRKrQFr4PVIwVOB0+ebO5FgoyOw43nyF
D5UKBDxEB4BKo/0uAiKHLRvvgLbORbU8KARIs1EoqEjmF8UtrmQWV2hUjwzqwvHF
ei8rPxMCAwEAAaOBozCBoDAdBgNVHQ4EFgQUO8ZuGCrD/T1iZEib47dHLLT8v/gw
HwYDVR0jBBgwFoAUhawa0UP3yKxV1MUdQUir1XhK1FMwEgYDVR0TAQH/BAgwBgEB
/wIBADAOBgNVHQ8BAf8EBAMCAQQwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cHM6Ly9r
ZHNpbnRmLmFtZC5jb20vdmNlay92MS9NaWxhbi9jcmwwRgYJKoZIhvcNAQEKMDmg
DzANBglghkgBZQMEAgIFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIFAKID
AgEwowMCAQEDggIBAIgeUQScAf3lDYqgWU1VtlDbmIN8S2dC5kmQzsZ/HtAjQnLE
PI1jh3gJbLxL6gf3K8jxctzOWnkYcbdfMOOr28KT35IaAR20rekKRFptTHhe+DFr
3AFzZLDD7cWK29/GpPitPJDKCvI7A4Ug06rk7J0zBe1fz/qe4i2/F12rvfwCGYhc
RxPy7QF3q8fR6GCJdB1UQ5SlwCjFxD4uezURztIlIAjMkt7DFvKRh+2zK+5plVGG
FsjDJtMz2ud9y0pvOE4j3dH5IW9jGxaSGStqNrabnnpF236ETr1/a43b8FFKL5QN
mt8Vr9xnXRpznqCRvqjr+kVrb6dlfuTlliXeQTMlBoRWFJORL8AcBJxGZ4K2mXft
l1jU5TLeh5KXL9NW7a/qAOIUs2FiOhqrtzAhJRg9Ij8QkQ9Pk+cKGzw6El3T3kFr
Eg6zkxmvMuabZOsdKfRkWfhH2ZKcTlDfmH1H0zq0Q2bG3uvaVdiCtFY1LlWyB38J
S2fNsR/Py6t5brEJCFNvzaDky6KeC4ion/cVgUai7zzS3bGQWzKDKU35SqNU2WkP
I8xCZ00WtIiKKFnXWUQxvlKmmgZBIYPe01zD0N8atFxmWiSnfJl690B9rJpNR/fI
ajxCW3Seiws6r1Zm+tCuVbMiNtpS9ThjNX4uve5thyfE2DgoxRFvY1CsoF5M
-----END CERTIFICATE-----
)";

/// AMD Root Key, Genoa (EPYC 9004 / Zen 4). Self-signed, valid to 2047.
/// SHA-256 fingerprint 4C:65:98:D1:9C:18:71:9C:5D:FD:4A:7D:33:5F:67:4E:
///                     5B:FE:1D:8F:80:0C:EA:2C:F2:70:C1:0D:10:3D:B2:F1
/// Compiled in on purpose: a root fetched at runtime is not a root.
constexpr std::string_view kArkGenoa = R"(-----BEGIN CERTIFICATE-----
MIIGYzCCBBKgAwIBAgIDAgAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstR2Vub2EwHhcNMjIwMTI2MTUzNDM3WhcNNDcwMTI2
MTUzNDM3WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLUdlbm9hMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA3Cd95S/uFOuRIskW9vz9VDBF69NDQF79oRhL
/L2PVQGhK3YdfEBgpF/JiwWFBsT/fXDhzA01p3LkcT/7LdjcRfKXjHl+0Qq/M4dZ
kh6QDoUeKzNBLDcBKDDGWo3v35NyrxbA1DnkYwUKU5AAk4P94tKXLp80oxt84ahy
HoLmc/LqsGsp+oq1Bz4PPsYLwTG4iMKVaaT90/oZ4I8oibSru92vJhlqWO27d/Rx
c3iUMyhNeGToOvgx/iUo4gGpG61NDpkEUvIzuKcaMx8IdTpWg2DF6SwF0IgVMffn
vtJmA68BwJNWo1E4PLJdaPfBifcJpuBFwNVQIPQEVX3aP89HJSp8YbY9lySS6PlV
EqTBBtaQmi4ATGmMR+n2K/e+JAhU2Gj7jIpJhOkdH9firQDnmlA2SFfJ/Cc0mGNz
W9RmIhyOUnNFoclmkRhl3/AQU5Ys9Qsan1jT/EiyT+pCpmnA+y9edvhDCbOG8F2o
xHGRdTBkylungrkXJGYiwGrR8kaiqv7NN8QhOBMqYjcbrkEr0f8QMKklIS5ruOfq
lLMCBw8JLB3LkjpWgtD7OpxkzSsohN47Uom86RY6lp72g8eXHP1qYrnvhzaG1S70
vw6OkbaaC9EjiH/uHgAJQGxon7u0Q7xgoREWA/e7JcBQwLg80Hq/sbRuqesxz7wB
WSY254cCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSfXfn+Ddjz
WtAzGiXvgSlPvjGoWzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvR2Vub2EvY3JsMEYGCSqG
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQAdIlPBC7DQmvH7kjlOznFx3i21SzOPDs5L
7SgFjMC9rR07292GQCA7Z7Ulq97JQaWeD2ofGGse5swj4OQfKfVv/zaJUFjvosZO
nfZ63epu8MjWgBSXJg5QE/Al0zRsZsp53DBTdA+Uv/s33fexdenT1mpKYzhIg/cK
tz4oMxq8JKWJ8Po1CXLzKcfrTphjlbkh8AVKMXeBd2SpM33B1YP4g1BOdk013kqb
7bRHZ1iB2JHG5cMKKbwRCSAAGHLTzASgDcXr9Fp7Z3liDhGu/ci1opGmkp12QNiJ
uBbkTU+xDZHm5X8Jm99BX7NEpzlOwIVR8ClgBDyuBkBC2ljtr3ZSaUIYj2xuyWN9
5KFY49nWxcz90CFa3Hzmy4zMQmBe9dVyls5eL5p9bkXcgRMDTbgmVZiAf4afe8DL
dmQcYcMFQbHhgVzMiyZHGJgcCrQmA7MkTwEIds1wx/HzMcwU4qqNBAoZV7oeIIPx
dqFXfPqHqiRlEbRDfX1TG5NFVaeByX0GyH6jzYVuezETzruaky6fp2bl2bczxPE8
HdS38ijiJmm9vl50RGUeOAXjSuInGR4bsRufeGPB9peTa9BcBOeTWzstqTUB/F/q
aZCIZKr4X6TyfUuSDz/1JDAGl+lxdM0P9+lLaP9NahQjHCVf0zf1c1salVuGFk2w
/wMz1R1BHg==
-----END CERTIFICATE-----
)";

/// AMD SEV Signing Key, Genoa. Issued by the ARK above; the only intermediate
/// a Genoa VCEK chains through.
constexpr std::string_view kAskGenoa = R"(-----BEGIN CERTIFICATE-----
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
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

std::span<const std::string_view> pinned_amd_products() {
    // Turin joins this list when we have silicon to test against.
    static constexpr std::string_view kProducts[] = {"Milan", "Genoa"};
    return kProducts;
}

std::string_view pinned_amd_root(std::string_view product) {
    if (product == "Milan") return kArkMilan;
    if (product == "Genoa") return kArkGenoa;
    return {};
}

std::string pinned_amd_chain(std::string_view product) {
    if (product == "Milan") return std::string(kAskMilan) + std::string(kArkMilan);
    if (product == "Genoa") return std::string(kAskGenoa) + std::string(kArkGenoa);
    return {};
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
    // An empty chain means "use the pinned ones", which is the normal case: both
    // certificates are fixed per product, so shipping them with every piece of
    // evidence spends bandwidth to deliver something we already refuse to trust
    // on arrival.
    //
    // The report never names its silicon generation, so the product is resolved
    // by matching the root rather than by trusting a claim. A supplied chain
    // must root in one of the compiled-in AMD roots; an empty chain tries each
    // pinned pair. Either way the root comes from this binary, so an unknown
    // generation fails closed instead of widening what is trusted.
    std::vector<X509Ptr> chain;
    if (chain_pem.empty()) {
        for (const auto product : pinned_amd_products()) {
            auto candidate = parse_pem_chain(pinned_amd_chain(product));
            if (candidate.size() >= 2 && X509_check_issued(candidate[0].get(),
                                                            vcek.get()) == X509_V_OK) {
                chain = std::move(candidate);
                break;
            }
        }
        if (chain.size() < 2) {
            return fail("no compiled-in AMD chain issued this VCEK");
        }
    } else {
        chain = parse_pem_chain(chain_pem);
    }
    if (chain.size() < 2) return fail("certificate chain must carry ASK and ARK");
    X509* ask = chain[0].get();
    X509* ark = chain[1].get();

    bool root_is_pinned = false;
    for (const auto product : pinned_amd_products()) {
        auto pinned = parse_pem_chain(pinned_amd_root(product));
        if (!pinned.empty() && same_cert(ark, pinned[0].get())) {
            root_is_pinned = true;
            break;
        }
    }
    if (!root_is_pinned) {
        return fail("chain root is not a compiled-in AMD root key");
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
