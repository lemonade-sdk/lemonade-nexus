// Which AMD silicon generation endorsed a report is derived, never configured.
//
// A hard-coded product is not a harmless default: the VCEK URL is per product,
// so naming the wrong generation fetches from a path AMD answers with 404 and
// the host produces no evidence at all. That failure is invisible until real
// silicon of the other generation tries to attest, because the VERIFIER accepts
// both products happily — it is only acquisition that guesses.
//
// These tests pin the derivation against real bytes from two generations:
//   Milan - the Azure paravisor blob (azure_snp_hcl.bin) and its VCEK
//   Genoa - our own EPYC 9354 report and its VCEK
//
// The acceptance test inside discovery is AMD's own signature under the
// product's pinned ASK/ARK, so these also cover the substitution that matters:
// a genuine certificate from the wrong generation must be refused.

#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/PlatformProbe.hpp>
#include <LemonadeNexus/Security/SnpReport.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <gtest/gtest.h>

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

fs::path fixture_dir() {
    if (const char* d = std::getenv("NEXUS_TEST_FIXTURES")) return fs::path(d);
    return fs::path(NEXUS_TEST_FIXTURE_DIR);
}

std::vector<uint8_t> read_bytes(const std::string& name) {
    std::ifstream f(fixture_dir() / name, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

/// The Milan report, carved out of the captured Azure paravisor blob.
SnpReport milan_report() {
    const auto blob = read_bytes("azure_snp_hcl.bin");
    auto hcl = parse_hcl_blob(blob);
    EXPECT_TRUE(hcl.has_value());
    return hcl ? hcl->snp : SnpReport{};
}

SnpReport genoa_report() {
    const auto raw = read_bytes("genoa_snp_report.bin");
    auto parsed = parse_snp_report(raw);
    EXPECT_TRUE(parsed.has_value());
    return parsed ? *parsed : SnpReport{};
}

/// A VcekSource that serves one fixed certificate whatever product is asked
/// for. Discovery must then decide on the certificate's own merits.
VcekSource always(std::vector<uint8_t> der) {
    return [der = std::move(der)](const SnpReport&, const std::string&) { return der; };
}

/// A VcekSource that answers only for `product`, the way AMD KDS does: the
/// wrong generation's URL 404s and yields nothing.
VcekSource only_for(std::string product, std::vector<uint8_t> der) {
    return [product = std::move(product), der = std::move(der)](
               const SnpReport&, const std::string& asked) {
        return asked == product ? der : std::vector<uint8_t>{};
    };
}

struct AmdProductDiscoveryTest : ::testing::Test {};

// --- the KDS path itself --------------------------------------------------

TEST_F(AmdProductDiscoveryTest, EachProductGetsItsOwnKdsPath) {
    const auto milan = milan_report();
    const auto genoa = genoa_report();

    const std::string milan_url = vcek_kds_url(milan, "Milan");
    const std::string genoa_url = vcek_kds_url(genoa, "Genoa");

    EXPECT_NE(milan_url.find("/vcek/v1/Milan/"), std::string::npos) << milan_url;
    EXPECT_NE(genoa_url.find("/vcek/v1/Genoa/"), std::string::npos) << genoa_url;
    // The chip and TCB are in the path, so two generations never collide.
    EXPECT_NE(milan_url.find(milan.chip_id_hex()), std::string::npos);
    EXPECT_NE(genoa_url.find(genoa.chip_id_hex()), std::string::npos);
    EXPECT_NE(milan_url, genoa_url);
}

// --- Milan host -> Milan ----------------------------------------------------

TEST_F(AmdProductDiscoveryTest, AMilanHostResolvesToMilan) {
    const auto report = milan_report();
    const auto endorsement =
        discover_amd_endorsement({}, report, /*allow_network=*/false,
                                 only_for("Milan", read_bytes("vcek_milan.der")));

    ASSERT_FALSE(endorsement.empty());
    EXPECT_EQ(endorsement.product, "Milan");
    EXPECT_EQ(endorsement.vcek_der, read_bytes("vcek_milan.der"));
}

// --- Genoa host -> Genoa ----------------------------------------------------

// The regression this whole change exists for: before discovery, a Genoa host
// asked AMD for a Milan VCEK, got a 404, and produced no evidence.
TEST_F(AmdProductDiscoveryTest, AGenoaHostResolvesToGenoa) {
    const auto report = genoa_report();
    const auto endorsement =
        discover_amd_endorsement({}, report, /*allow_network=*/false,
                                 only_for("Genoa", read_bytes("vcek_genoa.der")));

    ASSERT_FALSE(endorsement.empty());
    EXPECT_EQ(endorsement.product, "Genoa");
    EXPECT_EQ(endorsement.vcek_der, read_bytes("vcek_genoa.der"));
}

// Milan is tried before Genoa, so a Genoa host only resolves correctly because
// the Milan candidate is REFUSED on its merits rather than skipped for being
// absent. Serve the Milan certificate for every product to prove that.
TEST_F(AmdProductDiscoveryTest, AnEarlierProductsCertificateDoesNotWinByOrdering) {
    const auto report = genoa_report();
    const auto endorsement = discover_amd_endorsement(
        {}, report, false, always(read_bytes("vcek_milan.der")));

    // Nothing endorses it: the Milan cert cannot verify a Genoa report, and the
    // Genoa attempt is handed that same wrong certificate.
    EXPECT_TRUE(endorsement.empty());
}

// --- wrong product certificate -> refused -----------------------------------

TEST_F(AmdProductDiscoveryTest, TheWrongProductsCertificateIsRefusedByTheVerifier) {
    const auto genoa = genoa_report();
    const auto milan = milan_report();

    // Each certificate is genuine and AMD-issued. It is simply the other
    // generation's, so the report signature cannot verify under it.
    const auto genoa_under_milan =
        verify_snp_signature(genoa, read_bytes("vcek_milan.der"), pinned_amd_chain("Milan"));
    EXPECT_FALSE(genoa_under_milan.ok) << "a Milan VCEK must not verify a Genoa report";

    const auto milan_under_genoa =
        verify_snp_signature(milan, read_bytes("vcek_genoa.der"), pinned_amd_chain("Genoa"));
    EXPECT_FALSE(milan_under_genoa.ok) << "a Genoa VCEK must not verify a Milan report";

    // And the right pairing still verifies, so the refusals above mean
    // something.
    EXPECT_TRUE(
        verify_snp_signature(genoa, read_bytes("vcek_genoa.der"), pinned_amd_chain("Genoa")).ok);
    EXPECT_TRUE(
        verify_snp_signature(milan, read_bytes("vcek_milan.der"), pinned_amd_chain("Milan")).ok);
}

// A certificate served under the right product name but issued by the other
// generation's chain is refused too: the pinned root decides, not the label.
TEST_F(AmdProductDiscoveryTest, ACertificateFromAnotherChainDoesNotVerifyUnderThisRoot) {
    const auto genoa = genoa_report();
    const auto crossed =
        verify_snp_signature(genoa, read_bytes("vcek_genoa.der"), pinned_amd_chain("Milan"));
    EXPECT_FALSE(crossed.ok);
    EXPECT_NE(crossed.failure.find("AMD root"), std::string::npos) << crossed.failure;
}

// --- the live Azure Genoa host ---------------------------------------------

// The combination the Milan default actually broke: an Azure paravisor CVM on
// Genoa silicon. Captured from nexus01 (Standard_DC2as_v6, EPYC 9V74). Before
// the fix this host asked AMD for a Milan VCEK and got a 404, so it produced no
// evidence at all while every verifier-side check would have accepted it.
TEST_F(AmdProductDiscoveryTest, TheLiveAzureGenoaHostResolvesToGenoa) {
    const auto blob = read_bytes("azure_genoa_hcl.bin");
    auto hcl = parse_hcl_blob(blob);
    ASSERT_TRUE(hcl.has_value());
    // Azure shape: the AK is bound through REPORT_DATA, not asserted.
    EXPECT_TRUE(hcl->report_data_binds_runtime);
    EXPECT_EQ(hcl->ak.kid, "HCLAkPub");

    const auto vcek = read_bytes("vcek_azure_genoa.der");
    const auto endorsement = discover_amd_endorsement({}, hcl->snp, false, always(vcek));
    ASSERT_FALSE(endorsement.empty());
    EXPECT_EQ(endorsement.product, "Genoa");

    // And the KDS path it would have used is the Genoa one.
    EXPECT_NE(vcek_kds_url(hcl->snp, endorsement.product).find("/vcek/v1/Genoa/"),
              std::string::npos);
}

// The same host's evidence must NOT resolve under Milan, which is what the old
// hard-coded default asked for.
TEST_F(AmdProductDiscoveryTest, TheLiveAzureGenoaHostIsNotEndorsedByMilan) {
    auto hcl = parse_hcl_blob(read_bytes("azure_genoa_hcl.bin"));
    ASSERT_TRUE(hcl.has_value());
    const auto milan = verify_snp_signature(hcl->snp, read_bytes("vcek_milan.der"),
                                             pinned_amd_chain("Milan"));
    EXPECT_FALSE(milan.ok);
}

// --- the chip binding -------------------------------------------------------

// The VCEK is issued per chip. A valid certificate for a DIFFERENT chip of the
// same generation is named as such rather than surfacing as a bare signature
// failure.
TEST_F(AmdProductDiscoveryTest, AVcekForAnotherChipIsRefusedByName) {
    // Both fixtures are Milan-chain-rooted? No — use the pairing that shares a
    // root so the chain check passes and the HWID check is what refuses.
    const auto genoa = genoa_report();
    auto other_chip = genoa;
    other_chip.chip_id[0] ^= 0xFF;  // same report, a chip the VCEK does not name

    const auto verdict =
        verify_snp_signature(other_chip, read_bytes("vcek_genoa.der"), pinned_amd_chain("Genoa"));
    EXPECT_FALSE(verdict.ok);
    EXPECT_NE(verdict.failure.find("different chip"), std::string::npos) << verdict.failure;
}

// --- unknown product -> fail closed -----------------------------------------

TEST_F(AmdProductDiscoveryTest, SiliconWithNoPinnedRootFailsClosed) {
    // Turin has no compiled-in root in this release.
    EXPECT_TRUE(pinned_amd_chain("Turin").empty());
    EXPECT_TRUE(pinned_amd_root("Turin").empty());
    const auto products = pinned_amd_products();
    EXPECT_EQ(std::count(products.begin(), products.end(), std::string_view{"Turin"}), 0);

    // A report no pinned product endorses resolves to nothing — it does not
    // fall back to the first product in the list.
    auto unknown = genoa_report();
    unknown.chip_id[0] ^= 0xFF;
    unknown.chip_id[1] ^= 0xFF;
    const auto endorsement =
        discover_amd_endorsement({}, unknown, false, always(read_bytes("vcek_genoa.der")));
    EXPECT_TRUE(endorsement.empty());
}

TEST_F(AmdProductDiscoveryTest, NoCertificateAtAllFailsClosed) {
    const auto report = genoa_report();
    // KDS unreachable for every product.
    const auto endorsement = discover_amd_endorsement(
        {}, report, false,
        [](const SnpReport&, const std::string&) { return std::vector<uint8_t>{}; });
    EXPECT_TRUE(endorsement.empty());
    EXPECT_TRUE(endorsement.product.empty());
    EXPECT_TRUE(endorsement.vcek_der.empty());
}

// Discovery never invents a product outside the compiled-in list, whatever the
// source returns.
TEST_F(AmdProductDiscoveryTest, OnlyPinnedProductsAreEverAsked) {
    const auto report = genoa_report();
    std::vector<std::string> asked;
    const auto endorsement = discover_amd_endorsement(
        {}, report, false,
        [&asked](const SnpReport&, const std::string& product) {
            asked.push_back(product);
            return std::vector<uint8_t>{};
        });

    EXPECT_TRUE(endorsement.empty());
    const auto pinned = pinned_amd_products();
    ASSERT_EQ(asked.size(), pinned.size());
    for (const auto& product : asked) {
        EXPECT_NE(std::find(pinned.begin(), pinned.end(), std::string_view{product}),
                  pinned.end())
            << "discovery asked for an unpinned product: " << product;
    }
}

}  // namespace
