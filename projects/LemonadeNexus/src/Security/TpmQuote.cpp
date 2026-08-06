#include <LemonadeNexus/Security/TpmQuote.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstring>
#include <memory>

namespace nexus::security {

namespace {

/// Big-endian reader over the TPM wire format.
struct Reader {
    const uint8_t* p{nullptr};
    std::size_t    n{0};
    std::size_t    off{0};

    [[nodiscard]] bool need(std::size_t k) const { return off + k <= n; }
    bool u8(uint8_t& v) {
        if (!need(1)) return false;
        v = p[off++];
        return true;
    }
    bool u16(uint16_t& v) {
        if (!need(2)) return false;
        v = static_cast<uint16_t>((p[off] << 8) | p[off + 1]);
        off += 2;
        return true;
    }
    bool u32(uint32_t& v) {
        if (!need(4)) return false;
        v = (uint32_t(p[off]) << 24) | (uint32_t(p[off + 1]) << 16) |
            (uint32_t(p[off + 2]) << 8) | uint32_t(p[off + 3]);
        off += 4;
        return true;
    }
    bool skip(std::size_t k) {
        if (!need(k)) return false;
        off += k;
        return true;
    }
    /// TPM2B: uint16 size prefix, then that many bytes.
    bool blob(std::vector<uint8_t>& out) {
        uint16_t len = 0;
        if (!u16(len) || !need(len)) return false;
        out.assign(p + off, p + off + len);
        off += len;
        return true;
    }
};

const EVP_MD* md_for(uint16_t hash_alg) {
    switch (hash_alg) {
        case kTpmAlgSha1:   return EVP_sha1();
        case kTpmAlgSha256: return EVP_sha256();
        case kTpmAlgSha384: return EVP_sha384();
        case kTpmAlgSha512: return EVP_sha512();
        default:            return nullptr;
    }
}

struct PkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;

/// Build an RSA EVP_PKEY from raw big-endian modulus/exponent.
PkeyPtr rsa_from_raw(std::span<const uint8_t> modulus, std::span<const uint8_t> exponent) {
    if (modulus.empty() || exponent.empty()) return nullptr;

    BIGNUM* n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
    BIGNUM* e = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr);
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;

    if (n && e && bld &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1 &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1) {
        params = OSSL_PARAM_BLD_to_param(bld);
        if (params) {
            ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
            if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) {
                if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
                    pkey = nullptr;
                }
            }
        }
    }

    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (params) OSSL_PARAM_free(params);
    if (bld) OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    return PkeyPtr{pkey};
}

bool fail(std::string* out, std::string why) {
    if (out) *out = std::move(why);
    return false;
}

}  // namespace

std::size_t tpm_digest_size(uint16_t hash_alg) {
    switch (hash_alg) {
        case kTpmAlgSha1:   return 20;
        case kTpmAlgSha256: return 32;
        case kTpmAlgSha384: return 48;
        case kTpmAlgSha512: return 64;
        default:            return 0;
    }
}

std::optional<TpmQuote> parse_tpm_quote(std::span<const uint8_t> tpms_attest) {
    Reader r{tpms_attest.data(), tpms_attest.size()};

    uint32_t magic = 0;
    uint16_t type = 0;
    if (!r.u32(magic) || magic != kTpmGeneratedValue) return std::nullopt;
    if (!r.u16(type) || type != kTpmStAttestQuote) return std::nullopt;

    TpmQuote q;
    if (!r.blob(q.qualified_signer)) return std::nullopt;
    if (!r.blob(q.extra_data)) return std::nullopt;

    // TPMS_CLOCK_INFO (clock 8, resetCount 4, restartCount 4, safe 1) then
    // firmwareVersion (8). Opaque to us — the AK's own hierarchy owns them.
    if (!r.skip(17 + 8)) return std::nullopt;

    // TPMS_QUOTE_INFO: TPML_PCR_SELECTION, then TPM2B_DIGEST pcrDigest.
    uint32_t sel_count = 0;
    if (!r.u32(sel_count)) return std::nullopt;
    if (sel_count > 16) return std::nullopt;  // TPM2 allows at most a handful of banks
    for (uint32_t i = 0; i < sel_count; ++i) {
        TpmPcrSelection sel;
        uint8_t size_of_select = 0;
        if (!r.u16(sel.hash_alg) || !r.u8(size_of_select)) return std::nullopt;
        if (!r.need(size_of_select)) return std::nullopt;
        for (uint8_t byte = 0; byte < size_of_select; ++byte) {
            const uint8_t bits = r.p[r.off + byte];
            for (int bit = 0; bit < 8; ++bit) {
                if (bits & (1u << bit)) {
                    sel.pcrs.push_back(static_cast<uint32_t>(byte) * 8 + static_cast<uint32_t>(bit));
                }
            }
        }
        r.off += size_of_select;
        q.selections.push_back(std::move(sel));
    }
    if (!r.blob(q.pcr_digest)) return std::nullopt;
    if (q.pcr_digest.empty()) return std::nullopt;

    return q;
}

bool quote_pcr_digest_matches(const TpmQuote& quote, std::span<const uint8_t> pcr_values,
                              uint16_t hash_alg) {
    const EVP_MD* md = md_for(hash_alg);
    if (!md) return false;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    if (EVP_Digest(pcr_values.data(), pcr_values.size(), digest, &len, md, nullptr) != 1) {
        return false;
    }
    return quote.pcr_digest.size() == len &&
           std::memcmp(quote.pcr_digest.data(), digest, len) == 0;
}

std::optional<std::vector<uint8_t>> quote_pcr_value(const TpmQuote& quote, uint16_t bank_hash_alg,
                                                     uint32_t pcr,
                                                     std::span<const uint8_t> pcr_values) {
    // Values arrive in selection order, PCRs ascending within a selection, each
    // one the digest length of that selection's bank.
    std::size_t cursor = 0;
    for (const auto& sel : quote.selections) {
        const std::size_t width = tpm_digest_size(sel.hash_alg);
        if (width == 0) return std::nullopt;  // an unknown bank makes every later offset a guess
        for (uint32_t idx : sel.pcrs) {
            if (cursor + width > pcr_values.size()) return std::nullopt;
            if (sel.hash_alg == bank_hash_alg && idx == pcr) {
                return std::vector<uint8_t>(pcr_values.begin() + static_cast<long>(cursor),
                                            pcr_values.begin() + static_cast<long>(cursor + width));
            }
            cursor += width;
        }
    }
    return std::nullopt;
}

std::optional<uint16_t> tpmt_signature_hash_alg(std::span<const uint8_t> tpmt_signature) {
    Reader r{tpmt_signature.data(), tpmt_signature.size()};
    uint16_t sig_alg = 0, hash_alg = 0;
    if (!r.u16(sig_alg) || !r.u16(hash_alg)) return std::nullopt;
    return hash_alg;
}

bool verify_quote_signature_rsa(std::span<const uint8_t> tpms_attest,
                                std::span<const uint8_t> tpmt_signature,
                                std::span<const uint8_t> modulus,
                                std::span<const uint8_t> exponent, std::string* failure) {
    Reader r{tpmt_signature.data(), tpmt_signature.size()};
    uint16_t sig_alg = 0, hash_alg = 0;
    std::vector<uint8_t> sig;
    if (!r.u16(sig_alg) || !r.u16(hash_alg) || !r.blob(sig)) {
        return fail(failure, "malformed TPMT_SIGNATURE");
    }
    if (sig_alg != kTpmAlgRsassa && sig_alg != kTpmAlgRsapss) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "quote is not RSA-signed (sigAlg 0x%04x)", sig_alg);
        return fail(failure, buf);
    }
    const EVP_MD* md = md_for(hash_alg);
    if (!md) return fail(failure, "unsupported quote hash algorithm");

    auto pkey = rsa_from_raw(modulus, exponent);
    if (!pkey) return fail(failure, "attestation key modulus/exponent did not load");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return fail(failure, "no digest context");

    bool ok = false;
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestVerifyInit(ctx, &pctx, md, nullptr, pkey.get()) == 1) {
        bool padding_ok = true;
        if (sig_alg == kTpmAlgRsapss) {
            // TPM RSAPSS uses the largest salt the key size allows.
            padding_ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                         EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_MAX) == 1;
        } else {
            padding_ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1;
        }
        if (padding_ok) {
            ok = EVP_DigestVerify(ctx, sig.data(), sig.size(), tpms_attest.data(),
                                  tpms_attest.size()) == 1;
        }
    }
    EVP_MD_CTX_free(ctx);

    if (!ok) return fail(failure, "quote signature does not verify under the attestation key");
    return true;
}

std::string rsa_spki_b64(std::span<const uint8_t> modulus, std::span<const uint8_t> exponent) {
    auto pkey = rsa_from_raw(modulus, exponent);
    if (!pkey) return {};
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(pkey.get(), &der);
    if (len <= 0 || !der) return {};
    std::string out = crypto::to_base64(
        std::span<const uint8_t>(der, static_cast<std::size_t>(len)));
    OPENSSL_free(der);
    return out;
}

}  // namespace nexus::security
