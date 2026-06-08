// TPM 2.0 attestation tests.
//
// The verifier (TeeAttestationService::verify_tpm_report, reached here via the
// public verify_report) is pure OpenSSL, so we can exercise every branch WITHOUT
// a TPM by synthesizing quotes with an OpenSSL EC key — to the verifier this is
// indistinguishable from a real TPM quote. A swtpm-gated test covers the ESYS
// prover round-trip when a TPM/swtpm is actually present.

#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/TeeAttestation.hpp>
#include <LemonadeNexus/Core/TeeAttestationTpm.hpp>
#include <LemonadeNexus/Core/TrustPolicy.hpp>
#include <LemonadeNexus/Core/TrustTypes.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace nexus;

namespace {

constexpr uint16_t kAlgEcdsa  = 0x0018;
constexpr uint16_t kAlgSha256 = 0x000B;
constexpr uint32_t kGenerated = 0xff544347u;
constexpr uint16_t kStQuote   = 0x8018;

void put_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(uint8_t(x >> 8));
    v.push_back(uint8_t(x & 0xFF));
}
void put_u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t(x >> 24)); v.push_back(uint8_t(x >> 16));
    v.push_back(uint8_t(x >> 8));  v.push_back(uint8_t(x & 0xFF));
}
void put_tpm2b(std::vector<uint8_t>& v, const std::vector<uint8_t>& b) {
    put_u16(v, uint16_t(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}

std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& in) {
    std::array<uint8_t, 32> out{};
    unsigned int len = 0;
    EVP_Digest(in.data(), in.size(), out.data(), &len, EVP_sha256(), nullptr);
    return out;
}

// An OpenSSL EC P-256 keypair standing in for the TPM Attestation Key.
struct EcKey {
    EVP_PKEY* pkey{nullptr};
    std::string spki_b64;  // base64 DER SubjectPublicKeyInfo (what gets pinned in the cert)
    ~EcKey() { if (pkey) EVP_PKEY_free(pkey); }
};

std::unique_ptr<EcKey> gen_ec_key() {
    auto k = std::make_unique<EcKey>();
    k->pkey = EVP_EC_gen("P-256");
    EXPECT_NE(k->pkey, nullptr);
    unsigned char* der = nullptr;
    int n = i2d_PUBKEY(k->pkey, &der);
    if (n > 0) {
        k->spki_b64 = crypto::to_base64(std::span<const uint8_t>(der, size_t(n)));
        OPENSSL_free(der);
    }
    return k;
}

// ECDSA(SHA-256) sign `msg`, returned in TPMT_SIGNATURE wire form (what the prover
// emits and the verifier parses): u16 sigAlg, u16 hash, TPM2B r, TPM2B s.
std::vector<uint8_t> sign_tpmt(EVP_PKEY* pkey, const std::vector<uint8_t>& msg) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    size_t len = 0;
    EVP_DigestSign(ctx, nullptr, &len, msg.data(), msg.size());
    std::vector<uint8_t> der(len);
    EVP_DigestSign(ctx, der.data(), &len, msg.data(), msg.size());
    der.resize(len);
    EVP_MD_CTX_free(ctx);

    const unsigned char* p = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, long(der.size()));
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    std::vector<uint8_t> rb(BN_num_bytes(r)), sb(BN_num_bytes(s));
    BN_bn2bin(r, rb.data());
    BN_bn2bin(s, sb.data());
    ECDSA_SIG_free(sig);

    std::vector<uint8_t> out;
    put_u16(out, kAlgEcdsa);
    put_u16(out, kAlgSha256);
    put_tpm2b(out, rb);
    put_tpm2b(out, sb);
    return out;
}

// A minimal but spec-shaped TPMS_ATTEST quote. If `pcr_digest` is provided, the
// full TPMS_QUOTE_INFO (clockInfo/firmwareVersion/pcrSelect/pcrDigest) is appended.
std::vector<uint8_t> build_attest(const std::array<uint8_t, 32>& extra_data,
                                  const std::vector<uint8_t>* pcr_digest = nullptr) {
    std::vector<uint8_t> a;
    put_u32(a, kGenerated);
    put_u16(a, kStQuote);
    put_tpm2b(a, {});  // qualifiedSigner (empty TPM2B_NAME)
    put_tpm2b(a, std::vector<uint8_t>(extra_data.begin(), extra_data.end()));  // extraData
    if (pcr_digest) {
        a.insert(a.end(), 17, 0);  // clockInfo (opaque to verifier)
        a.insert(a.end(), 8, 0);   // firmwareVersion
        put_u32(a, 1);             // TPML_PCR_SELECTION count
        put_u16(a, kAlgSha256);    // hash
        a.push_back(3);            // sizeofSelect
        a.push_back(0x83); a.push_back(0x00); a.push_back(0x80);  // PCRs 0,1,7,23
        put_tpm2b(a, *pcr_digest); // pcrDigest
    }
    return a;
}

class TpmAttestTest : public ::testing::Test {
protected:
    crypto::SodiumCryptoService crypto_;
    std::unique_ptr<storage::FileStorageService> storage_;
    std::unique_ptr<core::BinaryAttestationService> bin_;
    std::unique_ptr<core::TeeAttestationService> tee_;
    crypto::Ed25519Keypair id_;            // server identity (Ed25519)
    std::string id_pub_b64_;
    std::string binary_hash_;              // hex SHA-256 of a registered "approved" binary
    fs::path tmp_;

    void SetUp() override {
        crypto_.start();
        tmp_ = fs::temp_directory_path() /
               ("tpmtest-" + std::to_string(getpid()) + "-" +
                std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(tmp_);
        storage_ = std::make_unique<storage::FileStorageService>(tmp_);
        storage_->start();
        bin_ = std::make_unique<core::BinaryAttestationService>(crypto_, *storage_);
        bin_->start();
        tee_ = std::make_unique<core::TeeAttestationService>(crypto_, *storage_, *bin_);
        tee_->start();  // no TPM in CI → platform None; irrelevant to verify_report

        id_ = crypto_.ed25519_keygen();
        id_pub_b64_ = crypto::to_base64(
            std::span<const uint8_t>(id_.public_key.data(), id_.public_key.size()));

        // Register a manifest so the running "binary" counts as approved.
        std::array<uint8_t, 32> h{};
        for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(0xA0 + i);
        binary_hash_ = crypto::to_hex(std::span<const uint8_t>(h.data(), h.size()));
        core::ReleaseManifest m;
        m.version = "1.0.0";
        m.platform = "test";
        m.binary_sha256 = binary_hash_;
        m.timestamp = 1;
        ASSERT_TRUE(bin_->add_manifest(m));
    }
    void TearDown() override {
        tee_->stop(); bin_->stop(); storage_->stop(); crypto_.stop();
        std::error_code ec; fs::remove_all(tmp_, ec);
    }

    // The qualifyingData the verifier will recompute for a report.
    std::array<uint8_t, 32> qual(const std::array<uint8_t, 32>& nonce,
                                 const std::string& server_pub_b64,
                                 const std::string& binhash) {
        std::vector<uint8_t> in(nonce.begin(), nonce.end());
        if (!server_pub_b64.empty()) {
            auto pk = crypto::from_base64(server_pub_b64);
            in.insert(in.end(), pk.begin(), pk.end());
        }
        if (!binhash.empty()) {
            auto b = crypto::from_hex(binhash);
            in.insert(in.end(), b.begin(), b.end());
        }
        return sha256(in);
    }

    // Build a fully-populated, Ed25519-signed Tpm2 report. `attest`/`sig` are the
    // raw TPM evidence; the report is signed with the identity key (id_).
    core::TeeAttestationReport make_report(const std::array<uint8_t, 32>& nonce,
                                           const std::vector<uint8_t>& attest,
                                           const std::vector<uint8_t>& sig,
                                           const std::string& ak_hint,
                                           const std::vector<uint8_t>& pcr_values = {}) {
        core::TeeAttestationReport r;
        r.platform = core::TeePlatform::Tpm2;
        r.nonce = nonce;
        r.timestamp = uint64_t(std::time(nullptr));
        r.server_pubkey = id_pub_b64_;
        r.binary_hash = binary_hash_;
        r.tpms_attest = attest;
        r.tpm_signature = sig;
        r.ak_pubkey = ak_hint;
        r.pcr_values = pcr_values;
        auto canonical = core::canonical_attestation_json(r);
        std::vector<uint8_t> cb(canonical.begin(), canonical.end());
        auto s = crypto_.ed25519_sign(id_.private_key, cb);
        r.signature = crypto::to_base64(std::span<const uint8_t>(s.data(), s.size()));
        return r;
    }
};

std::array<uint8_t, 32> fixed_nonce(uint8_t seed) {
    std::array<uint8_t, 32> n{};
    for (auto& b : n) b = seed;
    return n;
}

} // namespace

// --- Happy path -------------------------------------------------------------

TEST_F(TpmAttestTest, ValidQuoteVerifiesAgainstPinnedAk) {
    auto ak = gen_ec_key();
    auto nonce = fixed_nonce(0x11);
    auto qd = qual(nonce, id_pub_b64_, binary_hash_);
    auto attest = build_attest(qd);
    auto sig = sign_tpmt(ak->pkey, attest);
    auto report = make_report(nonce, attest, sig, ak->spki_b64);

    EXPECT_TRUE(tee_->verify_report(report, nonce, ak->spki_b64));
}

// --- The anti-injection core: extraData must equal qualifyingData -----------

TEST_F(TpmAttestTest, TamperedExtraDataRejected) {
    auto ak = gen_ec_key();
    auto nonce = fixed_nonce(0x22);
    // Bake a DIFFERENT qualifyingData into the (correctly ECDSA-signed) quote.
    auto wrong_qd = qual(fixed_nonce(0x99), id_pub_b64_, binary_hash_);
    auto attest = build_attest(wrong_qd);
    auto sig = sign_tpmt(ak->pkey, attest);
    auto report = make_report(nonce, attest, sig, ak->spki_b64);

    EXPECT_FALSE(tee_->verify_report(report, nonce, ak->spki_b64));
}

// --- The trust anchor: signature must verify against the CERT-PINNED AK ------

TEST_F(TpmAttestTest, AkMismatchRejected) {
    auto signer = gen_ec_key();   // quote signed by this key
    auto pinned = gen_ec_key();   // but cert pins a DIFFERENT key
    auto nonce = fixed_nonce(0x33);
    auto qd = qual(nonce, id_pub_b64_, binary_hash_);
    auto attest = build_attest(qd);
    auto sig = sign_tpmt(signer->pkey, attest);
    // ak_pubkey hint = signer (self-asserted), but we verify against the pinned key.
    auto report = make_report(nonce, attest, sig, signer->spki_b64);

    EXPECT_FALSE(tee_->verify_report(report, nonce, pinned->spki_b64));
}

TEST_F(TpmAttestTest, EmptyTrustedAkRejected) {
    auto ak = gen_ec_key();
    auto nonce = fixed_nonce(0x44);
    auto qd = qual(nonce, id_pub_b64_, binary_hash_);
    auto attest = build_attest(qd);
    auto sig = sign_tpmt(ak->pkey, attest);
    auto report = make_report(nonce, attest, sig, ak->spki_b64);

    EXPECT_FALSE(tee_->verify_report(report, nonce, /*trusted_ak=*/""));
}

// --- Freshness / nonce / signature gates in do_verify_report ----------------

TEST_F(TpmAttestTest, WrongNonceRejected) {
    auto ak = gen_ec_key();
    auto nonce = fixed_nonce(0x55);
    auto qd = qual(nonce, id_pub_b64_, binary_hash_);
    auto attest = build_attest(qd);
    auto sig = sign_tpmt(ak->pkey, attest);
    auto report = make_report(nonce, attest, sig, ak->spki_b64);

    EXPECT_FALSE(tee_->verify_report(report, fixed_nonce(0x56), ak->spki_b64));
}

TEST_F(TpmAttestTest, EmptyReportSignatureRejected) {
    auto ak = gen_ec_key();
    auto nonce = fixed_nonce(0x66);
    auto qd = qual(nonce, id_pub_b64_, binary_hash_);
    auto attest = build_attest(qd);
    auto sig = sign_tpmt(ak->pkey, attest);
    auto report = make_report(nonce, attest, sig, ak->spki_b64);
    report.signature.clear();  // mandatory signature missing

    EXPECT_FALSE(tee_->verify_report(report, nonce, ak->spki_b64));
}

// --- Binary measurement gate (unconditional) --------------------------------

TEST_F(TpmAttestTest, UnapprovedBinaryRejected) {
    auto ak = gen_ec_key();
    auto nonce = fixed_nonce(0x77);
    auto report_hash_unknown = std::string(64, 'f');  // not in any manifest

    std::vector<uint8_t> in(nonce.begin(), nonce.end());
    auto pk = crypto::from_base64(id_pub_b64_);
    in.insert(in.end(), pk.begin(), pk.end());
    auto b = crypto::from_hex(report_hash_unknown);
    in.insert(in.end(), b.begin(), b.end());
    auto qd = sha256(in);

    auto attest = build_attest(qd);
    auto sig = sign_tpmt(ak->pkey, attest);
    // Build report with the unknown binary hash.
    core::TeeAttestationReport r;
    r.platform = core::TeePlatform::Tpm2;
    r.nonce = nonce;
    r.timestamp = uint64_t(std::time(nullptr));
    r.server_pubkey = id_pub_b64_;
    r.binary_hash = report_hash_unknown;
    r.tpms_attest = attest;
    r.tpm_signature = sig;
    r.ak_pubkey = ak->spki_b64;
    auto canonical = core::canonical_attestation_json(r);
    std::vector<uint8_t> cb(canonical.begin(), canonical.end());
    auto s = crypto_.ed25519_sign(id_.private_key, cb);
    r.signature = crypto::to_base64(std::span<const uint8_t>(s.data(), s.size()));

    EXPECT_FALSE(tee_->verify_report(r, nonce, ak->spki_b64));
}

// --- PCR digest binding ------------------------------------------------------

TEST_F(TpmAttestTest, PcrValuesMatchingDigestAccepted) {
    auto ak = gen_ec_key();
    auto nonce = fixed_nonce(0x88);
    auto qd = qual(nonce, id_pub_b64_, binary_hash_);
    std::vector<uint8_t> pcr_values(128, 0xCD);  // 4 PCRs * 32 bytes
    auto digest = sha256(pcr_values);
    std::vector<uint8_t> dvec(digest.begin(), digest.end());
    auto attest = build_attest(qd, &dvec);
    auto sig = sign_tpmt(ak->pkey, attest);
    auto report = make_report(nonce, attest, sig, ak->spki_b64, pcr_values);

    EXPECT_TRUE(tee_->verify_report(report, nonce, ak->spki_b64));
}

TEST_F(TpmAttestTest, PcrValuesMismatchedDigestRejected) {
    auto ak = gen_ec_key();
    auto nonce = fixed_nonce(0x89);
    auto qd = qual(nonce, id_pub_b64_, binary_hash_);
    std::vector<uint8_t> bogus_digest(32, 0x01);  // != SHA256(pcr_values)
    auto attest = build_attest(qd, &bogus_digest);
    auto sig = sign_tpmt(ak->pkey, attest);
    std::vector<uint8_t> pcr_values(128, 0xCD);
    auto report = make_report(nonce, attest, sig, ak->spki_b64, pcr_values);

    EXPECT_FALSE(tee_->verify_report(report, nonce, ak->spki_b64));
}

// --- TrustPolicy strict-mode enforcement ------------------------------------

TEST_F(TpmAttestTest, StrictModeChallengeResponsePromotesToTier1) {
    core::TrustPolicyService tp(*tee_, *bin_, crypto_);
    tp.set_require_tpm(true);
    tp.start();

    auto ak = gen_ec_key();
    const std::string pk = "peer-pubkey-b64";
    auto nonce = tp.challenge_peer(pk);
    auto qd = qual(nonce, id_pub_b64_, binary_hash_);
    auto attest = build_attest(qd);
    auto sig = sign_tpmt(ak->pkey, attest);
    auto report = make_report(nonce, attest, sig, ak->spki_b64);

    EXPECT_TRUE(tp.handle_challenge_response(pk, report, ak->spki_b64));
    EXPECT_EQ(tp.peer_tier(pk), core::TrustTier::Tier1);
    tp.stop();
}

TEST_F(TpmAttestTest, StrictModeRejectsNonTpmChallengeResponse) {
    core::TrustPolicyService tp(*tee_, *bin_, crypto_);
    tp.set_require_tpm(true);
    tp.start();

    const std::string pk = "peer-legacy";
    auto nonce = tp.challenge_peer(pk);
    core::TeeAttestationReport r;
    r.platform = core::TeePlatform::AmdSevSnp;  // legacy structural backend
    r.nonce = nonce;
    r.timestamp = uint64_t(std::time(nullptr));
    EXPECT_FALSE(tp.handle_challenge_response(pk, r, "some-ak"));
    EXPECT_NE(tp.peer_tier(pk), core::TrustTier::Tier1);
    tp.stop();
}

TEST_F(TpmAttestTest, StrictModeTokenAloneDoesNotPromote) {
    core::TrustPolicyService tp(*tee_, *bin_, crypto_);
    tp.set_require_tpm(true);
    tp.start();

    // A perfectly valid, signed Tpm2 token (verify_token passes) must NOT by
    // itself promote an un-challenged peer to Tier 1.
    core::AttestationToken token;
    token.server_pubkey = id_pub_b64_;
    token.platform = core::TeePlatform::Tpm2;
    token.binary_hash = binary_hash_;
    token.timestamp = uint64_t(std::time(nullptr));
    token.attestation_timestamp = token.timestamp;
    auto canonical = core::canonical_token_json(token);
    std::vector<uint8_t> cb(canonical.begin(), canonical.end());
    auto s = crypto_.ed25519_sign(id_.private_key, cb);
    token.signature = crypto::to_base64(std::span<const uint8_t>(s.data(), s.size()));

    auto tier = tp.verify_and_update(id_pub_b64_, token);
    EXPECT_NE(tier, core::TrustTier::Tier1);
    tp.stop();
}

// --- swtpm / real-TPM round trip (skipped when no TPM is available) ---------

TEST_F(TpmAttestTest, SwtpmRoundTripIfAvailable) {
    if (!core::tpm::tpm_available()) {
        GTEST_SKIP() << "no TPM/swtpm available (set TSS2_TCTI=swtpm:... to run)";
    }
    auto ak = core::tpm::export_ak_pubkey_b64();
    ASSERT_TRUE(ak.has_value());
    ASSERT_FALSE(ak->empty());

    // Tell the prover its identity, then generate a real quote and verify it
    // against the AK we just exported (the value an admin would pin at enrollment).
    tee_->set_identity_pubkey(id_pub_b64_);
    auto nonce = fixed_nonce(0xAB);
    auto report = tee_->generate_report(nonce);
    ASSERT_EQ(report.platform, core::TeePlatform::Tpm2);
    ASSERT_FALSE(report.tpms_attest.empty());
    ASSERT_FALSE(report.binary_hash.empty());

    // Approve the actually-running binary (the quote's qualifyingData is bound to
    // report.binary_hash, so we must NOT change it here) and set our identity (the
    // quote bound the identity we configured via set_identity_pubkey).
    core::ReleaseManifest m;
    m.version = "1.0.0";
    m.platform = "self";
    m.binary_sha256 = report.binary_hash;
    m.timestamp = 1;
    ASSERT_TRUE(bin_->add_manifest(m));

    // Sign as the gossip layer would, then verify end-to-end.
    report.server_pubkey = id_pub_b64_;
    auto canonical = core::canonical_attestation_json(report);
    std::vector<uint8_t> cb(canonical.begin(), canonical.end());
    auto s = crypto_.ed25519_sign(id_.private_key, cb);
    report.signature = crypto::to_base64(std::span<const uint8_t>(s.data(), s.size()));

    EXPECT_TRUE(tee_->verify_report(report, nonce, *ak));
}
