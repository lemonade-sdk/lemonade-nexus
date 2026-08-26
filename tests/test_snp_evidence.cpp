// SEV-SNP evidence: parsing, the AMD signature chain, and guest policy.
//
// Everything here runs against a REAL attestation blob captured from the live Azure
// DCasv5 genesis (NexusTier1), plus the real VCEK and AMD certificate chain fetched
// from AMD KDS for that chip and TCB. No hardware is needed to run it, so the whole
// chain is covered on Windows and macOS CI as well as Linux.
//
// The measured values asserted below came off the box; if AMD or Microsoft rotate
// something, these tests are supposed to fail loudly rather than adapt.

#include <gtest/gtest.h>

#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/SnpReport.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace nexus::security;

namespace {

// Ground truth measured on NexusTier1 (23.101.203.10), an Azure Standard_DC2as_v5
// confidential VM on a 3rd-gen EPYC (family 19h model 01h, Milan).
constexpr std::size_t kBlobSize   = 2600;
constexpr uint64_t    kPolicyRaw  = 0x3001f;
constexpr const char* kMeasurement =
    "5b0ce64ad1c1f6375dbda5f760b98526ca1bcf91b8195091afc28e7b024251d6"
    "8fe32e05af34048d6607678cd23283ff";
constexpr const char* kIdKeyDigest =
    "942fd93ebde6ea7a96efadeafc60f1c6b3d10e703b1dafd7555b92f7f3d32d0e"
    "006767648cba5b102af3d65756af4177";
constexpr const char* kChipId =
    "63b1f11d7936b929c96b7459a3d7cfcddfeceba0cbf21aaa2953f069e816e391"
    "4409baa53948718c14200f64857428c366d57ab6273fa32424bd58d0940b2922";

fs::path fixture_dir() {
    // Set by CMake so the tests are runnable from any working directory.
    if (const char* d = std::getenv("NEXUS_TEST_FIXTURES")) return fs::path(d);
    return fs::path(NEXUS_TEST_FIXTURE_DIR);
}

std::vector<uint8_t> read_bytes(const std::string& name) {
    std::ifstream f(fixture_dir() / name, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

std::string read_text(const std::string& name) {
    std::ifstream f(fixture_dir() / name);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

class SnpEvidenceTest : public ::testing::Test {
protected:
    std::vector<uint8_t> blob_;
    std::vector<uint8_t> vcek_;
    std::string          chain_;

    void SetUp() override {
        blob_  = read_bytes("azure_snp_hcl.bin");
        vcek_  = read_bytes("vcek_milan.der");
        chain_ = read_text("amd_milan_cert_chain.pem");
        ASSERT_EQ(blob_.size(), kBlobSize) << "fixture missing or truncated";
        ASSERT_FALSE(vcek_.empty());
        ASSERT_FALSE(chain_.empty());
    }

    HclReport parsed() {
        auto r = parse_hcl_blob(blob_);
        EXPECT_TRUE(r.has_value());
        return r.value_or(HclReport{});
    }
};

// --- structure ---------------------------------------------------------------

TEST_F(SnpEvidenceTest, ParsesTheLiveAzureBlob) {
    auto h = parsed();
    EXPECT_EQ(h.snp.version, 5u);
    EXPECT_EQ(h.snp.signature_algo, 1u);  // ECDSA P-384 / SHA-384
    EXPECT_EQ(h.snp.measurement_hex(), kMeasurement);
    EXPECT_EQ(h.snp.chip_id_hex(), kChipId);
    EXPECT_EQ(hex_of(h.snp.id_key_digest), kIdKeyDigest);
    EXPECT_EQ(h.snp.reported_tcb.bootloader, 4);
    EXPECT_EQ(h.snp.reported_tcb.tee, 0);
    EXPECT_EQ(h.snp.reported_tcb.snp, 28);
    EXPECT_EQ(h.snp.reported_tcb.microcode, 222);
}

TEST_F(SnpEvidenceTest, ReportWasRequestedAtVmpl0) {
    // Our guest runs at VMPL2 and cannot issue a guest request at all, so a 0 here
    // is the cleanest evidence that the paravisor owns the SNP channel.
    EXPECT_EQ(parsed().snp.vmpl, 0u);
}

TEST_F(SnpEvidenceTest, PolicyHasDebugAndMigrationDisabled) {
    auto p = parsed().snp.policy;
    EXPECT_EQ(p.raw, kPolicyRaw);
    EXPECT_FALSE(p.debug);       // the bit that makes "dump the VM's memory" fail
    EXPECT_FALSE(p.migrate_ma);
    EXPECT_TRUE(p.smt);          // known, accepted: co-resident hyperthread
}

TEST_F(SnpEvidenceTest, HostDataIsEmptyOnAzure) {
    // Azure binds nothing at SNP_LAUNCH_FINISH — no check may depend on this field.
    auto h = parsed();
    EXPECT_EQ(hex_of(h.snp.host_data), std::string(64, '0'));
}

// --- the AK binding ----------------------------------------------------------

TEST_F(SnpEvidenceTest, ReportDataBindsTheRuntimeKeySet) {
    auto h = parsed();
    EXPECT_TRUE(h.report_data_binds_runtime);
    EXPECT_EQ(h.ak.kid, "HCLAkPub");
    EXPECT_EQ(h.ak.modulus.size(), 256u);                       // RSA-2048
    EXPECT_EQ(h.ak.exponent, (std::vector<uint8_t>{0x01, 0x00, 0x01}));

    // Only the first 32 bytes of REPORT_DATA carry the digest; the rest is zero,
    // which is what tells you this report is frozen at boot and cannot carry a
    // verifier nonce. Freshness has to come from the quote instead.
    for (std::size_t i = 32; i < h.snp.report_data.size(); ++i) {
        EXPECT_EQ(h.snp.report_data[i], 0) << "byte " << i;
    }
}

TEST_F(SnpEvidenceTest, TamperedRuntimeDataBreaksTheBinding) {
    auto bad = blob_;
    bad[1300] ^= 0x01;  // inside the runtime JSON
    EXPECT_FALSE(parse_hcl_blob(bad).has_value());
}

TEST_F(SnpEvidenceTest, RejectsBadMagicAndTruncation) {
    auto bad = blob_;
    bad[0] = 'X';
    EXPECT_FALSE(parse_hcl_blob(bad).has_value());

    EXPECT_FALSE(parse_hcl_blob(std::span<const uint8_t>(blob_).first(100)).has_value());
}

// --- the AMD signature chain -------------------------------------------------

TEST_F(SnpEvidenceTest, SignatureVerifiesUnderTheRealVcekAndAmdRoot) {
    auto h = parsed();
    auto r = verify_snp_signature(h.snp, vcek_, chain_);
    EXPECT_TRUE(r.ok) << r.failure;
}

TEST_F(SnpEvidenceTest, TamperedSignedRegionIsRejected) {
    auto h = parsed();
    h.snp.raw[0x100] ^= 0x01;  // inside [0, 0x2A0), the signed prefix
    auto r = verify_snp_signature(h.snp, vcek_, chain_);
    EXPECT_FALSE(r.ok);
}

TEST_F(SnpEvidenceTest, TamperedSignatureIsRejected) {
    auto h = parsed();
    h.snp.raw[kSnpSigOffset] ^= 0x01;
    EXPECT_FALSE(verify_snp_signature(h.snp, vcek_, chain_).ok);
}

TEST_F(SnpEvidenceTest, ChainNotRootedInThePinnedAmdKeyIsRejected) {
    auto h = parsed();
    // Drop the ARK: an attacker-supplied chain that stops at the ASK must not pass.
    const auto first_end = chain_.find("-----END CERTIFICATE-----");
    ASSERT_NE(first_end, std::string::npos);
    std::string ask_only = chain_.substr(0, first_end + 25) + "\n";

    auto r = verify_snp_signature(h.snp, vcek_, ask_only);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.failure.find("ASK and ARK"), std::string::npos) << r.failure;
}

TEST_F(SnpEvidenceTest, SelfSignedRootImpersonatingAmdIsRejected) {
    auto h = parsed();
    // The ASK, duplicated into the root slot. Structurally a chain; not AMD's root.
    const auto first_end = chain_.find("-----END CERTIFICATE-----");
    ASSERT_NE(first_end, std::string::npos);
    const std::string ask = chain_.substr(0, first_end + 25) + "\n";

    auto r = verify_snp_signature(h.snp, vcek_, ask + ask);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.failure.find("compiled-in AMD root"), std::string::npos) << r.failure;
}

TEST_F(SnpEvidenceTest, MissingVcekIsRejected) {
    EXPECT_FALSE(verify_snp_signature(parsed().snp, {}, chain_).ok);
}

// --- guest policy ------------------------------------------------------------

TEST_F(SnpEvidenceTest, LivePlatformSatisfiesTheTier1Bar) {
    SnpPolicyRequirements req;
    req.min_tcb = {4, 0, 28, 222};
    req.expected_measurement_hex = kMeasurement;
    auto r = verify_snp_policy(parsed().snp, req);
    EXPECT_TRUE(r.ok) << r.failure;
}

TEST_F(SnpEvidenceTest, DebugEnabledIsRejected) {
    auto h = parsed();
    h.snp.policy.debug = true;
    auto r = verify_snp_policy(h.snp, {});
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.failure.find("DEBUG"), std::string::npos) << r.failure;
}

TEST_F(SnpEvidenceTest, MigrationAgentIsRejected) {
    auto h = parsed();
    h.snp.policy.migrate_ma = true;
    EXPECT_FALSE(verify_snp_policy(h.snp, {}).ok);
}

// VMPL is a privilege level, not a quality score, and which level is correct
// depends on WHO requests the report. There is deliberately no default that is
// right everywhere: a paravisor or a native guest requests at VMPL0, while
// under an SVSM the SVSM holds VMPL0 and Linux runs above it. Demanding 0 of a
// guest-requested report there would reject exactly the shape Tier 1 wants.
TEST_F(SnpEvidenceTest, VmplPolicyIsProviderSpecific) {
    auto at_zero = parsed();
    at_zero.snp.vmpl = 0;
    auto above_zero = parsed();
    above_zero.snp.vmpl = 2;

    SnpPolicyRequirements paravisor;
    paravisor.vmpl_policy = VmplPolicy::RequireVmpl0;
    EXPECT_TRUE(verify_snp_policy(at_zero.snp, paravisor).ok);
    EXPECT_FALSE(verify_snp_policy(above_zero.snp, paravisor).ok);

    SnpPolicyRequirements under_svsm;
    under_svsm.vmpl_policy = VmplPolicy::RequireAboveVmpl0;
    EXPECT_TRUE(verify_snp_policy(above_zero.snp, under_svsm).ok);
    // A guest that holds VMPL0 has nothing more privileged beneath it, so no
    // SVSM was there.
    EXPECT_FALSE(verify_snp_policy(at_zero.snp, under_svsm).ok);

    // The default proves nothing about who asked, which is why a Tier 1 profile
    // must pin one of the two above.
    EXPECT_TRUE(verify_snp_policy(at_zero.snp, {}).ok);
    EXPECT_TRUE(verify_snp_policy(above_zero.snp, {}).ok);
    EXPECT_EQ(SnpPolicyRequirements{}.vmpl_policy, VmplPolicy::Unconstrained);
}

TEST_F(SnpEvidenceTest, TcbBelowFloorIsRejected) {
    SnpPolicyRequirements req;
    req.min_tcb = {4, 0, 28, 223};  // one microcode level above what the box reports
    auto r = verify_snp_policy(parsed().snp, req);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.failure.find("TCB"), std::string::npos) << r.failure;
}

TEST_F(SnpEvidenceTest, MeasurementMismatchIsRejected) {
    SnpPolicyRequirements req;
    req.expected_measurement_hex = std::string(96, 'a');
    EXPECT_FALSE(verify_snp_policy(parsed().snp, req).ok);
}

// --- KDS URL derivation ------------------------------------------------------

TEST_F(SnpEvidenceTest, DerivesTheVcekUrlThatActuallyServedThisCert) {
    const auto url = vcek_kds_url(parsed().snp, "Milan");
    EXPECT_NE(url.find(kChipId), std::string::npos);
    EXPECT_NE(url.find("blSPL=4"), std::string::npos);
    EXPECT_NE(url.find("teeSPL=0"), std::string::npos);
    EXPECT_NE(url.find("snpSPL=28"), std::string::npos);
    EXPECT_NE(url.find("ucodeSPL=222"), std::string::npos);
}

}  // namespace
