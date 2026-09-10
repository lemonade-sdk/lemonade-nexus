// Real SEV-SNP evidence from our own AMD host, verified end to end.
//
// Every other SNP test in this tree asserts a rejection. These assert
// acceptance, against bytes a real AMD PSP signed: the attestation report from
// `uwb-nx0-mesh-root` (EPYC 9354, Genoa) collected on 2026-08-26, and the VCEK
// AMD's key server issued for that chip and TCB.
//
// Two reports are pinned. Both come from the same running guest:
//   genoa_snp_report.bin            - `evidence` mode, REPORT_DATA = SHA-512(challenge)
//   genoa_snp_report_reference.bin  - `reference` mode, the collector's own challenge
// Same launch measurement, different REPORT_DATA, which is what a fresh
// challenge over an unchanged image must produce.
//
// The vTPM on that host sits outside the SEV-SNP boundary, so it contributes no
// evidence and appears nowhere here. See docs/attestation/test-host-capabilities.md.

#include <LemonadeNexus/Security/SnpReport.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace nexus::security;
namespace fs = std::filesystem;

namespace {

// The challenge passed to `nexus-attest-profile evidence` for this collection.
constexpr std::string_view kChallengeHex =
    "9d5d8d12d48b8abd98775e3cefed2ab7f888ca4dbf7c40333f513b0af0f4e9bb";

// Observed on the host and independently reproduced from the archived bytes.
constexpr std::string_view kLaunchMeasurement =
    "826de00d89da6a54ddc829c64aa871cc3409e50b19b7117aceccce9515e65050"
    "f689836a70777cd676f52f826394b8b5";

fs::path fixture_dir() {
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

std::vector<uint8_t> from_hex(std::string_view hex) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(std::string(hex.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

std::vector<uint8_t> sha512(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(64);
    unsigned len = 0;
    EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha512(), nullptr);
    out.resize(len);
    return out;
}

class GenoaSnpTest : public ::testing::Test {
protected:
    std::vector<uint8_t> report_bytes_;
    std::vector<uint8_t> vcek_;
    std::string chain_pem_;

    void SetUp() override {
        report_bytes_ = read_bytes("genoa_snp_report.bin");
        vcek_         = read_bytes("vcek_genoa.der");
        chain_pem_    = read_text("amd_genoa_cert_chain.pem");
        ASSERT_EQ(report_bytes_.size(), kSnpReportSize);
        ASSERT_FALSE(vcek_.empty());
    }

    SnpReport parsed() {
        auto r = parse_snp_report(report_bytes_);
        EXPECT_TRUE(r.has_value());
        return r.value_or(SnpReport{});
    }
};

}  // namespace

// --- Structure --------------------------------------------------------------

TEST_F(GenoaSnpTest, ParsesTheRealReport) {
    const auto r = parsed();
    EXPECT_EQ(r.version, 3u);
    EXPECT_EQ(r.signature_algo, 1u);   // ECDSA P-384 with SHA-384
    EXPECT_EQ(r.vmpl, 0u);
    EXPECT_EQ(r.measurement_hex(), kLaunchMeasurement);
    EXPECT_EQ(r.reported_tcb.bootloader, 9);
    EXPECT_EQ(r.reported_tcb.tee, 0);
    EXPECT_EQ(r.reported_tcb.snp, 23);
    EXPECT_EQ(r.reported_tcb.microcode, 72);
    EXPECT_FALSE(r.policy.debug);
    EXPECT_FALSE(r.policy.migrate_ma);
}

// The guest chooses REPORT_DATA, so this is what ties a report to one challenge
// and stops a captured report from answering a later one.
TEST_F(GenoaSnpTest, ReportDataBindsTheFreshChallenge) {
    const auto r = parsed();
    const auto expect = sha512(from_hex(kChallengeHex));
    ASSERT_EQ(expect.size(), r.report_data.size());
    EXPECT_TRUE(std::equal(expect.begin(), expect.end(), r.report_data.begin()));
}

// Same guest, same image, a different challenge: the measurement is stable and
// the binding is not. A report that reused REPORT_DATA would be replayable.
TEST_F(GenoaSnpTest, ReferenceRunSharesTheMeasurementButNotTheBinding) {
    const auto evidence = parsed();
    auto other = parse_snp_report(read_bytes("genoa_snp_report_reference.bin"));
    ASSERT_TRUE(other.has_value());
    EXPECT_EQ(other->measurement_hex(), evidence.measurement_hex());
    EXPECT_EQ(other->chip_id_hex(), evidence.chip_id_hex());
    EXPECT_NE(other->report_data, evidence.report_data);
}

// --- The AMD signature chain ------------------------------------------------

// The positive case: AMD hardware signed this report, and the VCEK chains to a
// root compiled into this binary.
TEST_F(GenoaSnpTest, AmdSignatureVerifiesWithThePinnedChain) {
    const auto r = parsed();
    const auto v = verify_snp_signature(r, vcek_, {});   // empty = use pinned material
    EXPECT_TRUE(v.ok) << v.failure;
}

TEST_F(GenoaSnpTest, AmdSignatureVerifiesWithTheSuppliedChain) {
    const auto r = parsed();
    const auto v = verify_snp_signature(r, vcek_, chain_pem_);
    EXPECT_TRUE(v.ok) << v.failure;
}

TEST_F(GenoaSnpTest, GenoaRootIsCompiledIn) {
    EXPECT_FALSE(pinned_amd_root("Genoa").empty());
    EXPECT_FALSE(pinned_amd_chain("Genoa").empty());
    const auto products = pinned_amd_products();
    EXPECT_NE(std::find(products.begin(), products.end(), "Genoa"), products.end());
    EXPECT_NE(std::find(products.begin(), products.end(), "Milan"), products.end());
}

// A generation we hold no root for must fail closed, not fall back to another.
TEST_F(GenoaSnpTest, UnknownProductHasNoPinnedMaterial) {
    EXPECT_TRUE(pinned_amd_root("Turin").empty());
    EXPECT_TRUE(pinned_amd_chain("Turin").empty());
    EXPECT_TRUE(pinned_amd_root("Nonsense").empty());
}

// The Milan chain must not vouch for a Genoa VCEK. Cross-generation acceptance
// would mean the root pin decides nothing.
TEST_F(GenoaSnpTest, MilanChainDoesNotVerifyAGenoaReport) {
    const auto r = parsed();
    const auto v = verify_snp_signature(r, vcek_, read_text("amd_milan_cert_chain.pem"));
    EXPECT_FALSE(v.ok);
}

TEST_F(GenoaSnpTest, TamperedReportBreaksTheSignature) {
    auto bytes = report_bytes_;
    bytes[snp_off::kMeasurement] ^= 0x01;   // one bit inside the signed prefix
    auto r = parse_snp_report(bytes);
    ASSERT_TRUE(r.has_value());
    const auto v = verify_snp_signature(*r, vcek_, {});
    EXPECT_FALSE(v.ok);
}

TEST_F(GenoaSnpTest, TamperedReportDataBreaksTheSignature) {
    auto bytes = report_bytes_;
    bytes[snp_off::kReportData] ^= 0xFF;   // forge the challenge binding
    auto r = parse_snp_report(bytes);
    ASSERT_TRUE(r.has_value());
    const auto v = verify_snp_signature(*r, vcek_, {});
    EXPECT_FALSE(v.ok);
}

TEST_F(GenoaSnpTest, WrongVcekDoesNotVerify) {
    const auto r = parsed();
    const auto v = verify_snp_signature(r, read_bytes("vcek_milan.der"), {});
    EXPECT_FALSE(v.ok);
}

TEST_F(GenoaSnpTest, MissingVcekIsRefused) {
    const auto r = parsed();
    const auto v = verify_snp_signature(r, {}, {});
    EXPECT_FALSE(v.ok);
    EXPECT_NE(v.failure.find("no VCEK"), std::string::npos);
}

// --- Guest policy -----------------------------------------------------------

// This host clears the Tier-1 policy bar: encryption a hypervisor with a
// debugger cannot defeat, and no migration agent to move the guest out of it.
TEST_F(GenoaSnpTest, PassesTheTier1PolicyBar) {
    const auto r = parsed();
    SnpPolicyRequirements req;   // defaults are the Tier-1 bar
    const auto v = verify_snp_policy(r, req);
    EXPECT_TRUE(v.ok) << v.failure;
}

TEST_F(GenoaSnpTest, PinnedMeasurementIsEnforced) {
    const auto r = parsed();
    SnpPolicyRequirements req;
    req.expected_measurement_hex = std::string(kLaunchMeasurement);
    EXPECT_TRUE(verify_snp_policy(r, req).ok);

    req.expected_measurement_hex = std::string(96, 'a');
    EXPECT_FALSE(verify_snp_policy(r, req).ok);
}

TEST_F(GenoaSnpTest, TcbFloorAboveThisPlatformIsRefused) {
    const auto r = parsed();
    SnpPolicyRequirements req;
    req.min_tcb = TcbVersion{9, 0, 23, 72};      // exactly this platform
    EXPECT_TRUE(verify_snp_policy(r, req).ok);

    req.min_tcb = TcbVersion{9, 0, 23, 73};      // one microcode level newer
    const auto v = verify_snp_policy(r, req);
    EXPECT_FALSE(v.ok);
    EXPECT_NE(v.failure.find("below the required floor"), std::string::npos);
}

// --- The KDS URL the verifier derives ---------------------------------------

TEST_F(GenoaSnpTest, DerivesTheVcekUrlThisVcekCameFrom) {
    const auto r = parsed();
    const auto url = vcek_kds_url(r, "Genoa");
    EXPECT_NE(url.find("/vcek/v1/Genoa/"), std::string::npos);
    EXPECT_NE(url.find(r.chip_id_hex()), std::string::npos);
    EXPECT_NE(url.find("blSPL=9"), std::string::npos);
    EXPECT_NE(url.find("snpSPL=23"), std::string::npos);
    EXPECT_NE(url.find("ucodeSPL=72"), std::string::npos);
}
