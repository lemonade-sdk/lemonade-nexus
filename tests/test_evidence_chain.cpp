// The snp-vtpm evidence chain, layer by layer.
//
// The AMD link is covered end-to-end in test_snp_evidence.cpp against a real
// captured blob. The links added on top of it — the quote under HCLAkPub, the
// evidence binding, and the IMA replay — are covered here.
//
// A positive test of the WHOLE composition is not possible off-platform: it would
// need a quote signed by the private half of the real blob's HCLAkPub, which only
// that Azure vTPM holds. So the quote and IMA layers get full positive coverage in
// isolation with synthetic keys and logs (indistinguishable from the real thing to
// the verifier), and the composed verifier gets negatives that pin the order the
// links are checked in. There is deliberately no test-only bypass to paper over it.

#include <gtest/gtest.h>

#include <LemonadeNexus/Security/EvidenceBinding.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace nexus::security;

namespace {

std::vector<uint8_t> bytes_of(std::string_view s) {
    return {s.begin(), s.end()};
}

std::vector<uint8_t> sha256_of(const std::vector<uint8_t>& in) {
    std::vector<uint8_t> out(32);
    unsigned len = 0;
    EVP_Digest(in.data(), in.size(), out.data(), &len, EVP_sha256(), nullptr);
    return out;
}

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

/// A spec-shaped TPMS_ATTEST quote over `pcr_bitmap` in the SHA-256 bank.
std::vector<uint8_t> build_quote(const std::vector<uint8_t>& extra_data,
                                 const std::vector<uint8_t>& pcr_digest,
                                 std::array<uint8_t, 3> pcr_bitmap) {
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
/// PCR 10 in the SHA-1 bank, because which bank the IMA log replays into depends
/// on the guest kernel's ima_template_hash_algo.
std::vector<uint8_t> build_two_bank_quote(const std::vector<uint8_t>& extra_data,
                                          const std::vector<uint8_t>& pcr_digest) {
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

std::vector<uint8_t> bn_param(EVP_PKEY* k, const char* name) {
    BIGNUM* bn = nullptr;
    if (EVP_PKEY_get_bn_param(k, name, &bn) != 1 || !bn) return {};
    std::vector<uint8_t> out(static_cast<std::size_t>(BN_num_bytes(bn)));
    BN_bn2bin(bn, out.data());
    BN_free(bn);
    return out;
}

std::unique_ptr<RsaKey> gen_rsa_key() {
    auto k = std::make_unique<RsaKey>();
    k->pkey = EVP_RSA_gen(2048);
    EXPECT_NE(k->pkey, nullptr);
    k->modulus  = bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_N);
    k->exponent = bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_E);
    return k;
}

/// RSASSA(SHA-256) over `msg`, in the TPMT_SIGNATURE wire form the prover emits.
std::vector<uint8_t> sign_tpmt_rsa(EVP_PKEY* pkey, const std::vector<uint8_t>& msg) {
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

}  // namespace

// ===========================================================================
// The evidence binding — one rule, shared by prover and verifier
// ===========================================================================

// Measured on the live Azure vTPM: TPM2_Quote takes a 32-byte qualifyingData and
// fails a 64-byte one with TPM2_RC_SIZE (0x1d5). Widening this again breaks every
// quote on the only hardware we actually run on.
TEST(EvidenceBindingTest, IsThirtyTwoBytesBecauseTheVtpmRejectsWider) {
    const auto b = evidence_binding(bytes_of("nonce"), bytes_of("id"), bytes_of("bin"));
    EXPECT_EQ(b.size(), 32u);
    EXPECT_EQ(b.size(), kEvidenceBindingSize);
}

TEST(EvidenceBindingTest, ReportDataFormIsTheBindingZeroExtendedToSixtyFour) {
    // The same rule the Azure paravisor uses for its own runtime-data digest:
    // REPORT_DATA[0:32] carries it and [32:64] is zero, as verified on the live blob.
    const auto b  = evidence_binding(bytes_of("n"), bytes_of("i"), bytes_of("m"));
    const auto rd = evidence_report_data(bytes_of("n"), bytes_of("i"), bytes_of("m"));
    ASSERT_EQ(rd.size(), 64u);
    EXPECT_TRUE(std::equal(b.begin(), b.end(), rd.begin()));
    for (std::size_t i = b.size(); i < rd.size(); ++i) EXPECT_EQ(rd[i], 0) << "byte " << i;
}

TEST(EvidenceBindingTest, IsDeterministic) {
    EXPECT_EQ(evidence_binding(bytes_of("n"), bytes_of("i"), bytes_of("b")),
              evidence_binding(bytes_of("n"), bytes_of("i"), bytes_of("b")));
}

TEST(EvidenceBindingTest, EveryInputChangesTheResult) {
    const auto base = evidence_binding(bytes_of("n"), bytes_of("i"), bytes_of("b"));
    EXPECT_NE(base, evidence_binding(bytes_of("N"), bytes_of("i"), bytes_of("b")));
    EXPECT_NE(base, evidence_binding(bytes_of("n"), bytes_of("I"), bytes_of("b")));
    EXPECT_NE(base, evidence_binding(bytes_of("n"), bytes_of("i"), bytes_of("B")));
}

TEST(EvidenceBindingTest, FieldsCannotBeShiftedAcrossTheBoundary) {
    // Length-prefixed, so ("ab","c") and ("a","bc") are different messages. Plain
    // concatenation would collide here and let a peer move bytes between the
    // identity and the measurement.
    EXPECT_NE(evidence_binding(bytes_of("x"), bytes_of("ab"), bytes_of("c")),
              evidence_binding(bytes_of("x"), bytes_of("a"), bytes_of("bc")));
}

TEST(EvidenceBindingTest, EmptyFieldsAreStillDistinguished) {
    EXPECT_NE(evidence_binding(bytes_of("n"), {}, bytes_of("b")),
              evidence_binding(bytes_of("n"), bytes_of("b"), {}));
}

// ===========================================================================
// TPM quote parsing and signature verification
// ===========================================================================

class TpmQuoteTest : public ::testing::Test {
protected:
    std::vector<uint8_t> extra_{32, 0xAB};
    // PCRs 0, 1, 4, 7, 10 in a 3-byte bitmap.
    std::array<uint8_t, 3> bitmap_{0x93, 0x04, 0x00};
    std::vector<uint8_t> pcr_values_{};

    void SetUp() override {
        // Five SHA-256 PCR values, each filled with its own index so slicing errors
        // are visible rather than silently plausible.
        for (uint8_t idx : {0, 1, 4, 7, 10}) {
            pcr_values_.insert(pcr_values_.end(), 32, idx);
        }
    }
};

TEST_F(TpmQuoteTest, ParsesSelectionInAscendingPcrOrder) {
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    auto q = parse_tpm_quote(attest);
    ASSERT_TRUE(q.has_value());
    ASSERT_EQ(q->selections.size(), 1u);
    EXPECT_EQ(q->selections[0].hash_alg, kTpmAlgSha256);
    EXPECT_EQ(q->selections[0].pcrs, (std::vector<uint32_t>{0, 1, 4, 7, 10}));
    EXPECT_EQ(q->extra_data, extra_);
}

TEST_F(TpmQuoteTest, RejectsWrongMagicAndWrongStructureType) {
    auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    auto bad_magic = attest;
    bad_magic[0] ^= 0xFF;
    EXPECT_FALSE(parse_tpm_quote(bad_magic).has_value());

    auto bad_type = attest;
    bad_type[4] = 0x80;
    bad_type[5] = 0x17;  // ATTEST_CERTIFY, not ATTEST_QUOTE
    EXPECT_FALSE(parse_tpm_quote(bad_type).has_value());
}

TEST_F(TpmQuoteTest, RejectsTruncation) {
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    for (std::size_t cut : {std::size_t{4}, std::size_t{10}, std::size_t{30}, attest.size() - 5}) {
        EXPECT_FALSE(parse_tpm_quote(
            std::span<const uint8_t>(attest).first(cut)).has_value()) << "cut at " << cut;
    }
}

TEST_F(TpmQuoteTest, PcrDigestBindsTheSuppliedValues) {
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    auto q = parse_tpm_quote(attest);
    ASSERT_TRUE(q.has_value());

    EXPECT_TRUE(quote_pcr_digest_matches(*q, pcr_values_, kTpmAlgSha256));

    auto tampered = pcr_values_;
    tampered[0] ^= 0x01;
    EXPECT_FALSE(quote_pcr_digest_matches(*q, tampered, kTpmAlgSha256));
}

TEST_F(TpmQuoteTest, ExtractsTheRequestedPcrFromTheConcatenatedValues) {
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    auto q = parse_tpm_quote(attest);
    ASSERT_TRUE(q.has_value());

    auto pcr10 = quote_pcr_value(*q, kTpmAlgSha256, kImaPcr, pcr_values_);
    ASSERT_TRUE(pcr10.has_value());
    EXPECT_EQ(*pcr10, std::vector<uint8_t>(32, 10));

    auto pcr4 = quote_pcr_value(*q, kTpmAlgSha256, 4, pcr_values_);
    ASSERT_TRUE(pcr4.has_value());
    EXPECT_EQ(*pcr4, std::vector<uint8_t>(32, 4));
}

TEST_F(TpmQuoteTest, UnquotedPcrAndWrongBankYieldNothing) {
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    auto q = parse_tpm_quote(attest);
    ASSERT_TRUE(q.has_value());

    EXPECT_FALSE(quote_pcr_value(*q, kTpmAlgSha256, 23, pcr_values_).has_value());
    EXPECT_FALSE(quote_pcr_value(*q, kTpmAlgSha1, kImaPcr, pcr_values_).has_value());
}

TEST_F(TpmQuoteTest, ShortValueBlobIsRejectedRatherThanReadPastTheEnd) {
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    auto q = parse_tpm_quote(attest);
    ASSERT_TRUE(q.has_value());

    std::vector<uint8_t> short_values(64, 0);  // room for two PCRs, five were quoted
    EXPECT_FALSE(quote_pcr_value(*q, kTpmAlgSha256, kImaPcr, short_values).has_value());
}

TEST_F(TpmQuoteTest, SlicesValuesCorrectlyAcrossTwoBanksOfDifferentWidths) {
    // Five 32-byte SHA-256 values then one 20-byte SHA-1 value. Getting the widths
    // wrong here would silently hand back a window straddling two PCRs.
    std::vector<uint8_t> values = pcr_values_;
    values.insert(values.end(), 20, 0xE1);

    const auto attest = build_two_bank_quote(extra_, sha256_of(values));
    auto q = parse_tpm_quote(attest);
    ASSERT_TRUE(q.has_value());
    ASSERT_EQ(q->selections.size(), 2u);
    EXPECT_EQ(q->selections[0].pcrs, (std::vector<uint32_t>{0, 1, 4, 7, 10}));
    EXPECT_EQ(q->selections[1].pcrs, (std::vector<uint32_t>{10}));

    auto sha256_pcr10 = quote_pcr_value(*q, kTpmAlgSha256, kImaPcr, values);
    ASSERT_TRUE(sha256_pcr10.has_value());
    EXPECT_EQ(*sha256_pcr10, std::vector<uint8_t>(32, 10));

    auto sha1_pcr10 = quote_pcr_value(*q, kTpmAlgSha1, kImaPcr, values);
    ASSERT_TRUE(sha1_pcr10.has_value());
    EXPECT_EQ(*sha1_pcr10, std::vector<uint8_t>(20, 0xE1));

    EXPECT_TRUE(quote_pcr_digest_matches(*q, values, kTpmAlgSha256));
}

TEST_F(TpmQuoteTest, SignatureVerifiesUnderTheKeyThatSignedIt) {
    auto ak = gen_rsa_key();
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    const auto sig = sign_tpmt_rsa(ak->pkey, attest);

    std::string why;
    EXPECT_TRUE(verify_quote_signature_rsa(attest, sig, ak->modulus, ak->exponent, &why)) << why;
}

TEST_F(TpmQuoteTest, TamperedQuoteIsRejected) {
    auto ak = gen_rsa_key();
    auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    const auto sig = sign_tpmt_rsa(ak->pkey, attest);

    attest[20] ^= 0x01;
    EXPECT_FALSE(verify_quote_signature_rsa(attest, sig, ak->modulus, ak->exponent, nullptr));
}

TEST_F(TpmQuoteTest, AnotherKeysSignatureIsRejected) {
    // This is the whole point of the hop: only the key AMD vouched for counts.
    auto real = gen_rsa_key();
    auto impostor = gen_rsa_key();
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    const auto sig = sign_tpmt_rsa(impostor->pkey, attest);

    EXPECT_FALSE(verify_quote_signature_rsa(attest, sig, real->modulus, real->exponent, nullptr));
}

TEST_F(TpmQuoteTest, NonRsaSchemeIsRejectedRatherThanIgnored) {
    auto ak = gen_rsa_key();
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    auto sig = sign_tpmt_rsa(ak->pkey, attest);
    sig[0] = uint8_t(kTpmAlgEcdsa >> 8);
    sig[1] = uint8_t(kTpmAlgEcdsa & 0xFF);

    std::string why;
    EXPECT_FALSE(verify_quote_signature_rsa(attest, sig, ak->modulus, ak->exponent, &why));
    EXPECT_NE(why.find("not RSA-signed"), std::string::npos) << why;
}

TEST_F(TpmQuoteTest, SignatureHashAlgorithmIsReadable) {
    auto ak = gen_rsa_key();
    const auto attest = build_quote(extra_, sha256_of(pcr_values_), bitmap_);
    const auto sig = sign_tpmt_rsa(ak->pkey, attest);

    auto alg = tpmt_signature_hash_alg(sig);
    ASSERT_TRUE(alg.has_value());
    EXPECT_EQ(*alg, kTpmAlgSha256);
}

TEST(TpmQuoteSpkiTest, RsaSpkiIsStableAndNonEmpty) {
    auto ak = gen_rsa_key();
    const auto a = rsa_spki_b64(ak->modulus, ak->exponent);
    const auto b = rsa_spki_b64(ak->modulus, ak->exponent);
    EXPECT_FALSE(a.empty());
    EXPECT_EQ(a, b);
    EXPECT_NE(a, rsa_spki_b64(gen_rsa_key()->modulus, ak->exponent));
}

TEST(TpmQuoteSpkiTest, EmptyKeyMaterialYieldsNoSpki) {
    EXPECT_TRUE(rsa_spki_b64({}, {}).empty());
}

// ===========================================================================
// The IMA measurement log
// ===========================================================================

namespace {

std::string ima_line(const std::string& template_hash_hex, const std::string& file_hash_hex,
                     const std::string& path, const char* tmpl = "ima-ng") {
    return "10 " + template_hash_hex + " " + tmpl + " sha256:" + file_hash_hex + " " + path;
}

std::string hex_rep(uint8_t byte, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0F]);
    }
    return out;
}

}  // namespace

TEST(ImaLogTest, ParsesTheAsciiFormat) {
    const std::string log = ima_line(hex_rep(0x11, 32), hex_rep(0xAA, 32), "/usr/bin/foo") +
                            "\n" +
                            ima_line(hex_rep(0x22, 32), hex_rep(0xBB, 32), "/usr/bin/bar") + "\n";
    auto parsed = parse_ima_ascii(log);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->entries.size(), 2u);

    EXPECT_EQ(parsed->entries[0].pcr, 10u);
    EXPECT_EQ(parsed->entries[0].template_name, "ima-ng");
    EXPECT_EQ(parsed->entries[0].file_hash_algo, "sha256");
    EXPECT_EQ(parsed->entries[0].file_hash_hex, hex_rep(0xAA, 32));
    EXPECT_EQ(parsed->entries[0].path, "/usr/bin/foo");
    EXPECT_EQ(parsed->entries[1].path, "/usr/bin/bar");
    EXPECT_EQ(parsed->template_hash_size(), 32u);
}

TEST(ImaLogTest, RejectsTextThatIsNotAMeasurementLog) {
    EXPECT_FALSE(parse_ima_ascii("this is not an ima log\n").has_value());
    EXPECT_FALSE(parse_ima_ascii("10 zzzz ima-ng sha256:aa /x\n").has_value());
}

TEST(ImaLogTest, HandlesPathsContainingSpaces) {
    const std::string log =
        ima_line(hex_rep(0x11, 32), hex_rep(0xAA, 32), "/opt/my app/bin") + "\n";
    auto parsed = parse_ima_ascii(log);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->entries.size(), 1u);
    EXPECT_EQ(parsed->entries[0].path, "/opt/my app/bin");
}

TEST(ImaLogTest, ReplayMatchesAnIndependentlyComputedExtendChain) {
    const auto h1 = hex_rep(0x11, 32);
    const auto h2 = hex_rep(0x22, 32);
    const std::string log = ima_line(h1, hex_rep(0xAA, 32), "/a") + "\n" +
                            ima_line(h2, hex_rep(0xBB, 32), "/b") + "\n";
    auto parsed = parse_ima_ascii(log);
    ASSERT_TRUE(parsed.has_value());

    // PCR = H(H(0^32 ‖ h1) ‖ h2), written out here rather than reusing the code
    // under test.
    std::vector<uint8_t> step(32, 0);
    for (const auto& h : {h1, h2}) {
        std::vector<uint8_t> in = step;
        for (std::size_t i = 0; i < h.size(); i += 2) {
            in.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
        }
        step = sha256_of(in);
    }

    EXPECT_EQ(replay_ima_pcr(*parsed, kImaPcr, kTpmAlgSha256), step);
}

TEST(ImaLogTest, BankIsChosenByTheLogsTemplateDigestWidth) {
    const std::string sha1_log = ima_line(hex_rep(0x33, 20), hex_rep(0xCC, 32), "/a") + "\n";
    auto sha1_parsed = parse_ima_ascii(sha1_log);
    ASSERT_TRUE(sha1_parsed.has_value());
    EXPECT_EQ(sha1_parsed->template_hash_size(), 20u);
    EXPECT_EQ(ima_replay_bank(*sha1_parsed), kTpmAlgSha1);

    const std::string sha256_log = ima_line(hex_rep(0x33, 32), hex_rep(0xCC, 32), "/a") + "\n";
    auto sha256_parsed = parse_ima_ascii(sha256_log);
    ASSERT_TRUE(sha256_parsed.has_value());
    EXPECT_EQ(ima_replay_bank(*sha256_parsed), kTpmAlgSha256);
}

// Measured on the live Azure box (kernel 6.8, default ima_template_hash_algo):
// replaying the ASCII log's SHA-1 template digests reproduced the SHA-1 bank's
// PCR 10 exactly, while the SHA-256 bank held a completely different value. Since
// ~4.20 the kernel computes a SEPARATE template digest per bank and the ASCII log
// only ever shows one of them, so no zero-extension rule bridges the two. Replaying
// a SHA-1 log into the SHA-256 bank must therefore produce nothing rather than a
// plausible-looking wrong answer.
TEST(ImaLogTest, ASha1LogDoesNotReplayIntoTheSha256Bank) {
    const std::string log = ima_line(hex_rep(0x33, 20), hex_rep(0xCC, 32), "/a") + "\n";
    auto parsed = parse_ima_ascii(log);
    ASSERT_TRUE(parsed.has_value());

    EXPECT_TRUE(replay_ima_pcr(*parsed, kImaPcr, kTpmAlgSha256).empty());

    std::vector<uint8_t> in(20, 0);
    in.insert(in.end(), 20, 0x33);
    std::vector<uint8_t> expect(20);
    unsigned len = 0;
    EVP_Digest(in.data(), in.size(), expect.data(), &len, EVP_sha1(), nullptr);
    EXPECT_EQ(replay_ima_pcr(*parsed, kImaPcr, kTpmAlgSha1), expect);
}

TEST(ImaLogTest, TemplateHashOfTheWrongWidthIsRefused) {
    const std::string log = ima_line(hex_rep(0x44, 48), hex_rep(0xDD, 32), "/a") + "\n";
    auto parsed = parse_ima_ascii(log);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(replay_ima_pcr(*parsed, kImaPcr, kTpmAlgSha256).empty());
    EXPECT_TRUE(replay_ima_pcr(*parsed, kImaPcr, kTpmAlgSha1).empty());
}

TEST(ImaLogTest, EntriesForOtherPcrsDoNotAffectTheReplay) {
    const auto h = hex_rep(0x55, 32);
    std::string log = ima_line(h, hex_rep(0xEE, 32), "/a") + "\n";
    log += "11 " + hex_rep(0x66, 32) + " ima-ng sha256:" + hex_rep(0xFF, 32) + " /other\n";
    auto parsed = parse_ima_ascii(log);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->entries.size(), 2u);

    std::vector<uint8_t> in(32, 0);
    in.insert(in.end(), 32, 0x55);
    EXPECT_EQ(replay_ima_pcr(*parsed, kImaPcr, kTpmAlgSha256), sha256_of(in));
}

TEST(ImaLogTest, LastMeasurementOfAPathWins) {
    // A file re-measured after modification appears again; the newest line is what
    // is actually running, so an earlier benign entry must not shadow it.
    const std::string log = ima_line(hex_rep(0x11, 32), hex_rep(0xAA, 32), "/bin/x") + "\n" +
                            ima_line(hex_rep(0x22, 32), hex_rep(0xBB, 32), "/bin/x") + "\n";
    auto parsed = parse_ima_ascii(log);
    ASSERT_TRUE(parsed.has_value());

    auto e = ima_entry_for_path(*parsed, "/bin/x");
    ASSERT_TRUE(e.has_value());
    EXPECT_EQ(e->file_hash_hex, hex_rep(0xBB, 32));
    EXPECT_FALSE(ima_entry_for_path(*parsed, "/bin/absent").has_value());
}

// ===========================================================================
// The composed verifier
// ===========================================================================

namespace {

fs::path fixture_dir() {
    if (const char* d = std::getenv("NEXUS_TEST_FIXTURES")) return fs::path(d);
    return fs::path(NEXUS_TEST_FIXTURE_DIR);
}

std::vector<uint8_t> real_hcl_blob() {
    std::ifstream f(fixture_dir() / "azure_snp_hcl.bin", std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

std::string read_fixture_text(const char* name) {
    std::ifstream f(fixture_dir() / name);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

std::vector<uint8_t> read_fixture_bytes(const char* name) {
    std::ifstream f(fixture_dir() / name, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

/// The real platform blob and AMD material, with a synthetic quote on top. The
/// quote cannot verify — only the real vTPM holds that key — which is exactly what
/// the negatives below assert.
SnpVtpmEvidence evidence_with_real_platform() {
    SnpVtpmEvidence ev;
    ev.hcl_blob      = real_hcl_blob();
    ev.vcek_der      = read_fixture_bytes("vcek_milan.der");
    ev.amd_chain_pem = read_fixture_text("amd_milan_cert_chain.pem");
    ev.binary_path   = "/usr/bin/lemonade-nexus";
    ev.binary_sha256 = hex_rep(0x77, 32);
    return ev;
}

}  // namespace

TEST(EvidenceVerifyTest, WireFormRoundTrips) {
    auto ev = evidence_with_real_platform();
    ev.tpms_attest   = {1, 2, 3};
    ev.tpm_signature = {4, 5};
    ev.pcr_values    = {6, 7, 8};
    ev.ima_log       = "10 aa ima-ng sha256:bb /x\n";

    auto back = decode_snp_vtpm_evidence(encode_snp_vtpm_evidence(ev));
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back->hcl_blob, ev.hcl_blob);
    EXPECT_EQ(back->vcek_der, ev.vcek_der);
    EXPECT_EQ(back->amd_chain_pem, ev.amd_chain_pem);
    EXPECT_EQ(back->tpms_attest, ev.tpms_attest);
    EXPECT_EQ(back->tpm_signature, ev.tpm_signature);
    EXPECT_EQ(back->pcr_values, ev.pcr_values);
    EXPECT_EQ(back->ima_log, ev.ima_log);
    EXPECT_EQ(back->binary_path, ev.binary_path);
    EXPECT_EQ(back->binary_sha256, ev.binary_sha256);
}

TEST(EvidenceVerifyTest, RejectsSomethingThatIsNotAnEvidenceBundle) {
    EXPECT_FALSE(decode_snp_vtpm_evidence("").has_value());
    EXPECT_FALSE(decode_snp_vtpm_evidence("{}").has_value());
    EXPECT_FALSE(decode_snp_vtpm_evidence(R"({"profile":"snp-direct"})").has_value());
    EXPECT_FALSE(decode_snp_vtpm_evidence("not json at all").has_value());
}

TEST(EvidenceVerifyTest, MalformedBlobFailsBeforeAnythingElse) {
    SnpVtpmEvidence ev;
    ev.hcl_blob = {1, 2, 3};
    const std::array<uint8_t, 32> nonce{};
    auto v = verify_snp_vtpm_evidence(ev, nonce, bytes_of("id"), {});
    EXPECT_FALSE(v.ok);
    EXPECT_NE(v.failure.find("malformed"), std::string::npos) << v.failure;
}

TEST(EvidenceVerifyTest, ReportsTheAmdVouchedKeyAndMeasurementEvenWhenTheQuoteFails) {
    // The verdict carries what an operator pins, so a failing run is still
    // diagnosable rather than opaque.
    auto ev = evidence_with_real_platform();
    const std::array<uint8_t, 32> nonce{};
    auto v = verify_snp_vtpm_evidence(ev, nonce, bytes_of("id"), {});

    EXPECT_FALSE(v.ok);
    EXPECT_FALSE(v.measurement_hex.empty());
    EXPECT_FALSE(v.ak_spki_b64.empty());
    EXPECT_FALSE(v.chip_id_hex.empty());
}

TEST(EvidenceVerifyTest, AMissingQuoteIsRejected) {
    auto ev = evidence_with_real_platform();
    const std::array<uint8_t, 32> nonce{};
    auto v = verify_snp_vtpm_evidence(ev, nonce, bytes_of("id"), {});
    EXPECT_FALSE(v.ok);
    EXPECT_NE(v.failure.find("well-formed"), std::string::npos) << v.failure;
}

TEST(EvidenceVerifyTest, AQuoteNotSignedByHclAkPubIsRejected) {
    // A structurally perfect quote under an attacker's own key. This is the forgery
    // the whole chain exists to stop: without the AMD-vouched key, nothing.
    auto ev = evidence_with_real_platform();
    auto impostor = gen_rsa_key();
    const std::array<uint8_t, 32> nonce{};
    const auto binding = evidence_binding(nonce, bytes_of("id"), {});
    ev.binary_sha256 = "";
    ev.tpms_attest = build_quote(std::vector<uint8_t>(binding.begin(), binding.end()),
                                 sha256_of({}), {0x00, 0x04, 0x00});
    ev.tpm_signature = sign_tpmt_rsa(impostor->pkey, ev.tpms_attest);

    auto v = verify_snp_vtpm_evidence(ev, nonce, bytes_of("id"), {});
    EXPECT_FALSE(v.ok);
    EXPECT_NE(v.failure.find("not signed by HCLAkPub"), std::string::npos) << v.failure;
}

TEST(EvidenceVerifyTest, MeasurementPinMismatchIsRejectedBeforeTheQuoteIsLookedAt) {
    auto ev = evidence_with_real_platform();
    EvidenceRequirements req;
    req.expected_measurement_hex = std::string(96, 'a');
    const std::array<uint8_t, 32> nonce{};

    auto v = verify_snp_vtpm_evidence(ev, nonce, bytes_of("id"), req);
    EXPECT_FALSE(v.ok);
    EXPECT_NE(v.failure.find("policy check failed"), std::string::npos) << v.failure;
}

TEST(EvidenceVerifyTest, AnAkOtherThanTheOnePinnedAtEnrollmentIsRejected) {
    auto ev = evidence_with_real_platform();
    EvidenceRequirements req;
    req.expected_ak_spki_b64 = "a-different-vtpms-key";
    const std::array<uint8_t, 32> nonce{};

    auto v = verify_snp_vtpm_evidence(ev, nonce, bytes_of("id"), req);
    EXPECT_FALSE(v.ok);
    EXPECT_NE(v.failure.find("pinned at enrollment"), std::string::npos) << v.failure;
}

// An absent chain means "use the compiled-in ASK + ARK". Both are fixed per
// product, so shipping them with every bundle spent 4.6 KB of a 65 KB datagram
// budget to deliver material the verifier re-pins on arrival anyway.
TEST(EvidenceVerifyTest, AbsentChainFallsBackToThePinnedAskAndArk) {
    auto ev = evidence_with_real_platform();
    ev.amd_chain_pem.clear();
    const std::array<uint8_t, 32> nonce{};

    auto v = verify_snp_vtpm_evidence(ev, nonce, bytes_of("id"), {});
    EXPECT_FALSE(v.ok);
    // The AMD link passed on the pinned chain; the run stops later, at the quote.
    EXPECT_EQ(v.failure.find("AMD signature check failed"), std::string::npos) << v.failure;
    EXPECT_NE(v.failure.find("well-formed"), std::string::npos) << v.failure;
}

TEST(EvidenceVerifyTest, PinnedChainMatchesTheOneAmdPublishes) {
    // If AMD ever rotates an ASK this fails loudly rather than quietly falling
    // back to whatever a peer sends. Both generations we hold material for are
    // compared against the bytes the AMD key server published.
    auto strip = [](std::string s) {
        std::string out;
        for (char c : s) if (c != '\n' && c != '\r' && c != ' ') out.push_back(c);
        return out;
    };

    const auto milan = pinned_amd_chain("Milan");
    ASSERT_FALSE(milan.empty());
    EXPECT_EQ(strip(milan), strip(read_fixture_text("amd_milan_cert_chain.pem")));

    const auto genoa = pinned_amd_chain("Genoa");
    ASSERT_FALSE(genoa.empty());
    EXPECT_EQ(strip(genoa), strip(read_fixture_text("amd_genoa_cert_chain.pem")));

    // A generation we hold no root for stays empty, so it fails closed instead
    // of borrowing another generation's root.
    EXPECT_TRUE(pinned_amd_chain("Turin").empty());
}

TEST(EvidenceVerifyTest, ASuppliedChainWithAForgedRootIsStillRejected) {
    // Supplying a chain is still allowed, and still has to root in the pinned ARK.
    auto ev = evidence_with_real_platform();
    const auto first_end = ev.amd_chain_pem.find("-----END CERTIFICATE-----");
    ASSERT_NE(first_end, std::string::npos);
    const std::string ask = ev.amd_chain_pem.substr(0, first_end + 25) + "\n";
    ev.amd_chain_pem = ask + ask;  // the ASK standing in for the root
    const std::array<uint8_t, 32> nonce{};

    auto v = verify_snp_vtpm_evidence(ev, nonce, bytes_of("id"), {});
    EXPECT_FALSE(v.ok);
    EXPECT_NE(v.failure.find("AMD signature check failed"), std::string::npos) << v.failure;
}
