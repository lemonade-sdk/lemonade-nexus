#pragma once

// Synthetic TPM quote material for tests.
//
// A positive test of the whole snp-vtpm composition is not possible off
// platform: it needs a quote signed by the private half of a real blob's
// HCLAkPub, which only that vTPM holds. These helpers build quotes that are
// structurally indistinguishable from real ones under keys the test owns, which
// is what lets the substitution negatives be exact rather than approximate — a
// forged quote must fail because AMD never vouched for its key, not because it
// failed to parse.
//
// There is deliberately no helper that bypasses a verification step.

#include <LemonadeNexus/Security/TpmQuote.hpp>

#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace nexus_test {

inline std::vector<uint8_t> bytes_of(std::string_view s) { return {s.begin(), s.end()}; }

inline std::vector<uint8_t> sha256_of(const std::vector<uint8_t>& in) {
    std::vector<uint8_t> out(32);
    unsigned len = 0;
    EVP_Digest(in.data(), in.size(), out.data(), &len, EVP_sha256(), nullptr);
    return out;
}

inline void put_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

inline void put_u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

inline void put_tpm2b(std::vector<uint8_t>& v, const std::vector<uint8_t>& b) {
    put_u16(v, static_cast<uint16_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}

/// A spec-shaped TPMS_ATTEST quote over `pcr_bitmap` in the SHA-256 bank.
inline std::vector<uint8_t> build_quote(const std::vector<uint8_t>& extra_data,
                                        const std::vector<uint8_t>& pcr_digest,
                                        std::array<uint8_t, 3> pcr_bitmap) {
    using namespace nexus::security;
    std::vector<uint8_t> a;
    put_u32(a, kTpmGeneratedValue);
    put_u16(a, kTpmStAttestQuote);
    put_tpm2b(a, {});            // qualifiedSigner
    put_tpm2b(a, extra_data);
    a.insert(a.end(), 17, 0);    // clockInfo
    a.insert(a.end(), 8, 0);     // firmwareVersion
    put_u32(a, 1);               // one TPML_PCR_SELECTION entry
    put_u16(a, kTpmAlgSha256);
    a.push_back(3);              // sizeofSelect
    a.insert(a.end(), pcr_bitmap.begin(), pcr_bitmap.end());
    put_tpm2b(a, pcr_digest);
    return a;
}

/// The shape the prover actually emits: PCRs 0,1,4,7,10 in the SHA-256 bank and
/// PCR 10 in the SHA-1 bank, because which bank the IMA log replays into
/// depends on the guest kernel's ima_template_hash_algo.
inline std::vector<uint8_t> build_two_bank_quote(const std::vector<uint8_t>& extra_data,
                                                 const std::vector<uint8_t>& pcr_digest) {
    using namespace nexus::security;
    std::vector<uint8_t> a;
    put_u32(a, kTpmGeneratedValue);
    put_u16(a, kTpmStAttestQuote);
    put_tpm2b(a, {});
    put_tpm2b(a, extra_data);
    a.insert(a.end(), 17, 0);
    a.insert(a.end(), 8, 0);
    put_u32(a, 2);
    put_u16(a, kTpmAlgSha256);
    a.push_back(3);
    a.push_back(0x93); a.push_back(0x04); a.push_back(0x00);  // 0,1,4,7,10
    put_u16(a, kTpmAlgSha1);
    a.push_back(3);
    a.push_back(0x00); a.push_back(0x04); a.push_back(0x00);  // 10
    put_tpm2b(a, pcr_digest);
    return a;
}

/// An RSA-2048 keypair standing in for the paravisor's HCLAkPub.
struct RsaKey {
    EVP_PKEY*            pkey{nullptr};
    std::vector<uint8_t> modulus;
    std::vector<uint8_t> exponent;
    ~RsaKey() { if (pkey) EVP_PKEY_free(pkey); }
};

inline std::vector<uint8_t> bn_param(EVP_PKEY* k, const char* name) {
    BIGNUM* bn = nullptr;
    if (EVP_PKEY_get_bn_param(k, name, &bn) != 1 || !bn) return {};
    std::vector<uint8_t> out(static_cast<std::size_t>(BN_num_bytes(bn)));
    BN_bn2bin(bn, out.data());
    BN_free(bn);
    return out;
}

inline std::unique_ptr<RsaKey> gen_rsa_key() {
    auto k = std::make_unique<RsaKey>();
    k->pkey = EVP_RSA_gen(2048);
    EXPECT_NE(k->pkey, nullptr);
    k->modulus  = bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_N);
    k->exponent = bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_E);
    return k;
}

/// RSASSA(SHA-256) over `msg`, in the TPMT_SIGNATURE wire form the prover emits.
inline std::vector<uint8_t> sign_tpmt_rsa(EVP_PKEY* pkey, const std::vector<uint8_t>& msg) {
    using namespace nexus::security;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    std::size_t len = 0;
    EVP_DigestSign(ctx, nullptr, &len, msg.data(), msg.size());
    std::vector<uint8_t> sig(len);
    EVP_DigestSign(ctx, sig.data(), &len, msg.data(), msg.size());
    sig.resize(len);
    EVP_MD_CTX_free(ctx);

    std::vector<uint8_t> out;
    put_u16(out, kTpmAlgRsassa);
    put_u16(out, kTpmAlgSha256);
    put_tpm2b(out, sig);
    return out;
}

}  // namespace nexus_test
