#include <gtest/gtest.h>

#include "support/tpm_quote_fixtures.hpp"

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationState.hpp>
#include <LemonadeNexus/Security/EvidenceBinding.hpp>
#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>

#include <openssl/ec.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {

using namespace nexus::security;

void put_le32(std::vector<uint8_t>& bytes, std::size_t offset, uint32_t value) {
    for (std::size_t i = 0; i != 4; ++i)
        bytes[offset + i] = static_cast<uint8_t>(value >> (8 * i));
}

void put_le64(std::vector<uint8_t>& bytes, std::size_t offset, uint64_t value) {
    for (std::size_t i = 0; i != 8; ++i)
        bytes[offset + i] = static_cast<uint8_t>(value >> (8 * i));
}

using nexus_test::binary_entry;
using nexus_test::rsa_public;

std::vector<uint8_t> rsa_public_with_modulus(std::span<const uint8_t> modulus) {
    using nexus_test::put_u16;
    using nexus_test::put_u32;
    std::vector<uint8_t> out;
    put_u16(out, 0x0001);
    put_u16(out, kTpmAlgSha256);
    put_u32(out, 0x00050072u);
    put_u16(out, 0);
    put_u16(out, 0x0010);
    put_u16(out, kTpmAlgRsassa);
    put_u16(out, kTpmAlgSha256);
    put_u16(out, static_cast<uint16_t>(modulus.size() * 8));
    put_u32(out, 0);
    put_u16(out, static_cast<uint16_t>(modulus.size()));
    out.insert(out.end(), modulus.begin(), modulus.end());
    return out;
}

struct P384Key {
    EVP_PKEY* key{EVP_EC_gen("P-384")};
    ~P384Key() { EVP_PKEY_free(key); }
};

void sign_report(std::vector<uint8_t>& raw, EVP_PKEY* key) {
    std::fill(raw.begin() + static_cast<long>(kSnpSigOffset), raw.end(), 0);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(EVP_DigestSignInit(ctx, nullptr, EVP_sha384(), nullptr, key), 1);
    std::size_t size = 0;
    ASSERT_EQ(EVP_DigestSign(ctx, nullptr, &size, raw.data(), kSnpSignedLen), 1);
    std::vector<uint8_t> der(size);
    ASSERT_EQ(EVP_DigestSign(ctx, der.data(), &size, raw.data(), kSnpSignedLen), 1);
    EVP_MD_CTX_free(ctx);
    der.resize(size);
    ASSERT_LT(der.size() + 2, raw.size() - kSnpSigOffset);
    raw[kSnpSigOffset] = static_cast<uint8_t>(der.size());
    raw[kSnpSigOffset + 1] = static_cast<uint8_t>(der.size() >> 8);
    std::copy(der.begin(), der.end(), raw.begin() + static_cast<long>(kSnpSigOffset + 2));
}

SnpVerifyResult verify_test_signature(EVP_PKEY* key, const SnpReport& report) {
    if (report.raw.size() != kSnpReportSize) return {false, "wrong report size"};
    const std::size_t size = report.raw[kSnpSigOffset] |
                             (static_cast<std::size_t>(report.raw[kSnpSigOffset + 1]) << 8);
    if (size == 0 || kSnpSigOffset + 2 + size > report.raw.size())
        return {false, "missing test signature"};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {false, "no digest context"};
    const bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha384(), nullptr, key) == 1 &&
                    EVP_DigestVerify(ctx, report.raw.data() + kSnpSigOffset + 2, size,
                                     report.raw.data(), kSnpSignedLen) == 1;
    EVP_MD_CTX_free(ctx);
    return {ok, ok ? std::string{} : std::string{"P-384 signature mismatch"}};
}

std::array<uint8_t, 64> service_report_data(const Digest& challenge,
                                             std::span<const uint8_t> manifest) {
    const auto nonce = svsm_report_nonce(challenge);
    std::array<uint8_t, 64> out{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EXPECT_NE(ctx, nullptr);
    unsigned size = 0;
    EXPECT_EQ(EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr), 1);
    EXPECT_EQ(EVP_DigestUpdate(ctx, nonce.data(), nonce.size()), 1);
    EXPECT_EQ(EVP_DigestUpdate(ctx, manifest.data(), manifest.size()), 1);
    EXPECT_EQ(EVP_DigestFinal_ex(ctx, out.data(), &size), 1);
    EXPECT_EQ(size, out.size());
    EVP_MD_CTX_free(ctx);
    return out;
}

std::vector<uint8_t> report(uint32_t vmpl, uint8_t measurement, uint8_t chip,
                            std::span<const uint8_t> report_data, EVP_PKEY* key) {
    std::vector<uint8_t> raw(kSnpReportSize);
    put_le32(raw, snp_off::kVersion, 2);
    put_le64(raw, snp_off::kPolicy, 0x0000000000030000ULL);
    put_le32(raw, snp_off::kVmpl, vmpl);
    put_le32(raw, snp_off::kSigAlgo, 1);
    std::copy(report_data.begin(), report_data.end(), raw.begin() + snp_off::kReportData);
    std::fill_n(raw.begin() + snp_off::kMeasurement, 48, measurement);
    raw[snp_off::kReportedTcb] = 9;
    raw[snp_off::kReportedTcb + 1] = 0;
    raw[snp_off::kReportedTcb + 6] = 23;
    raw[snp_off::kReportedTcb + 7] = 72;
    std::fill_n(raw.begin() + snp_off::kChipId, 64, chip);
    sign_report(raw, key);
    return raw;
}

struct SignedFixture {
    P384Key signer;
    Digest challenge{};
    SnpSvsmVtpmEvidence evidence;
    SvsmEvidenceRequirements requirements;

    SignedFixture() {
        challenge.fill(0x31);
        evidence.ek_manifest = rsa_public(0xa5, true);
        evidence.ak_public = rsa_public(0xb6, false);
        const auto service_data = service_report_data(challenge, evidence.ek_manifest);
        const auto guest_data = svsm_report_nonce(challenge);
        evidence.svsm_report = report(0, 0x44, 0x55, service_data, signer.key);
        evidence.guest_report = report(2, 0x44, 0x55, guest_data, signer.key);
        requirements.expected_measurements_hex = {std::string(96, '4')};
        requirements.policy.min_tcb = {9, 0, 23, 72};
        requirements.signature_verifier = [this](const SnpReport& value,
                                                  std::span<const uint8_t>,
                                                  std::string_view) {
            return verify_test_signature(signer.key, value);
        };
    }

    void resign_service() { sign_report(evidence.svsm_report, signer.key); }
    void resign_guest() { sign_report(evidence.guest_report, signer.key); }
    SvsmEvidenceFailure failure() const {
        std::array<uint8_t, 32> identity{};
        return verify_snp_svsm_vtpm_evidence(evidence, challenge, identity, requirements)
            .svsm_failure;
    }
};

struct SignedTpmFixture : SignedFixture {
    std::unique_ptr<nexus_test::RsaKey> ak{nexus_test::gen_rsa_key()};
    std::array<uint8_t, 32> identity{};

    SignedTpmFixture() {
        identity.fill(0x28);
        evidence.ak_public = rsa_public_with_modulus(ak->modulus);
        const auto ek_public = parse_tpmt_public_rsa(evidence.ek_manifest);
        const auto ak_public = parse_tpmt_public_rsa(evidence.ak_public);
        EXPECT_TRUE(ek_public.has_value());
        EXPECT_TRUE(ak_public.has_value());
        if (!ek_public || !ak_public) return;
        requirements.expected_ek_name_hex = hex_of(ek_public->name);
        requirements.expected_ak_name_hex = hex_of(ak_public->name);
        requirements.expected_ak_spki_b64 = ak_public->spki_b64;
        requirements.expected_ak_ek_binding =
            ak_ek_binding_digest(ek_public->name, ak_public->name);

        evidence.binary_path = "/usr/bin/nexus-attestd";
        evidence.binary_sha256 = std::string(64, '7');
        evidence.ima_binary_log = binary_entry(evidence.binary_path, 0x77);
        const auto log = parse_ima_binary(evidence.ima_binary_log);
        EXPECT_TRUE(log.has_value());
        std::array<uint8_t, 32> zero{};
        const auto replay = log ? replay_ima_binary_from(*log, 0, zero) : std::nullopt;
        EXPECT_TRUE(replay.has_value());
        if (!replay) return;

        requirements.approved_paths = {evidence.binary_path};
        requirements.evidence_collector_path = evidence.binary_path;
        for (uint32_t index : kSvsmEvidencePcrs) {
            std::array<uint8_t, 32> value{};
            value.fill(static_cast<uint8_t>(index + 1));
            if (index == kImaPcr)
                std::copy(replay->pcr10.begin(), replay->pcr10.end(), value.begin());
            evidence.pcr_values.insert(evidence.pcr_values.end(), value.begin(), value.end());
            if (index != kImaPcr)
                requirements.expected_pcrs.emplace_back(index, hex_of(value));
        }
        set_quote(evidence_binding(challenge, identity,
                                   nexus::crypto::from_hex(evidence.binary_sha256)));
    }

    void set_quote(std::span<const uint8_t> extra_data) {
        const auto pcr_digest = nexus_test::sha256_of(evidence.pcr_values);
        const std::vector<uint8_t> extra{extra_data.begin(), extra_data.end()};
        evidence.tpms_attest = nexus_test::build_quote(
            extra, pcr_digest, {0x93, 0x07, 0x00});
        evidence.tpm_signature = nexus_test::sign_tpmt_rsa(ak->pkey, evidence.tpms_attest);
    }

    SvsmEvidenceFailure full_failure() const {
        return verify_snp_svsm_vtpm_evidence(evidence, challenge, identity, requirements)
            .svsm_failure;
    }
};

TEST(SvsmSignedMutations, BaselinePassesBothCryptographicAndSemanticReportLayers) {
    SignedFixture fixture;
    EXPECT_EQ(fixture.failure(), SvsmEvidenceFailure::EkMismatch);
}

TEST(SvsmSignedMutations, ServiceReportMatrixHasExactTypedFailures) {
    {
        SignedFixture f;
        put_le32(f.evidence.svsm_report, snp_off::kVmpl, 1);
        f.resign_service();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceVmplInvalid);
    }
    {
        SignedFixture f;
        f.evidence.svsm_report[snp_off::kReportData] ^= 1;
        f.resign_service();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceReportDataInvalid);
    }
    {
        SignedFixture f;
        // Still validly signed, but for the original challenge's service nonce.
        f.challenge[0] ^= 1;
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceReportDataInvalid);
    }
    {
        SignedFixture f;
        f.evidence.ek_manifest[8] ^= 1;
        const auto data = service_report_data(f.challenge, f.evidence.ek_manifest);
        std::copy(data.begin(), data.end(),
                  f.evidence.svsm_report.begin() + snp_off::kReportData);
        f.resign_service();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceManifestInvalid);
    }
    {
        SignedFixture f;
        f.evidence.svsm_report[snp_off::kChipId] ^= 1;
        f.resign_service();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::PairChipMismatch);
    }
    {
        SignedFixture f;
        f.evidence.svsm_report[snp_off::kMeasurement] ^= 1;
        f.resign_service();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceMeasurementInvalid);
    }
    {
        SignedFixture f;
        put_le64(f.evidence.svsm_report, snp_off::kPolicy,
                 0x0000000000030000ULL | (1ULL << 19));
        f.resign_service();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceDebugEnabled);
    }
    {
        SignedFixture f;
        put_le64(f.evidence.svsm_report, snp_off::kPolicy,
                 0x0000000000030000ULL | (1ULL << 18));
        f.resign_service();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceMigrationEnabled);
    }
    {
        SignedFixture f;
        f.evidence.svsm_report[snp_off::kReportedTcb + 6] = 22;
        f.resign_service();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceTcbTooOld);
    }
}

TEST(SvsmSignedMutations, GuestReportMatrixHasExactTypedFailures) {
    {
        SignedFixture f;
        put_le32(f.evidence.guest_report, snp_off::kVmpl, 0);
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::GuestVmplInvalid);
    }
    {
        SignedFixture f;
        f.evidence.guest_report[snp_off::kReportData] ^= 1;
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::GuestNonceInvalid);
    }
    {
        SignedFixture f;
        f.evidence.guest_report[snp_off::kChipId] ^= 1;
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::PairChipMismatch);
    }
    {
        SignedFixture f;
        f.evidence.guest_report[snp_off::kMeasurement] ^= 1;
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::GuestMeasurementInvalid);
    }
    {
        SignedFixture f;
        put_le64(f.evidence.guest_report, snp_off::kPolicy,
                 0x0000000000030000ULL | (1ULL << 19));
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::GuestDebugEnabled);
    }
    {
        SignedFixture f;
        put_le64(f.evidence.guest_report, snp_off::kPolicy,
                 0x0000000000030000ULL | (1ULL << 18));
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::GuestMigrationEnabled);
    }
    {
        SignedFixture f;
        f.evidence.guest_report[snp_off::kReportedTcb + 7] = 71;
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::GuestTcbTooOld);
    }
}

TEST(SvsmSignedMutations, IndependentlySignedReportsMustStillPair) {
    {
        SignedFixture f;
        f.evidence.guest_report[snp_off::kChipId] ^= 1;
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::PairChipMismatch);
    }
    {
        // Both measurements are release-approved shapes, so only the pairing
        // rule can reject: one bundle must not span two launches.
        SignedFixture f;
        f.requirements.expected_measurements_hex = {std::string(96, '4'),
                                                    std::string(96, '6')};
        std::fill_n(f.evidence.guest_report.begin() + snp_off::kMeasurement, 48, 0x66);
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::PairMeasurementMismatch);
    }
}

TEST(SvsmSignedMutations, TheReleaseMeasurementSetIsExactMatchAny) {
    {
        // Two approved shapes: a bundle from either one clears the measurement
        // stage (the baseline then stops at enrollment, as in Baseline*).
        SignedFixture f;
        f.requirements.expected_measurements_hex = {std::string(96, '4'),
                                                    std::string(96, '6')};
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::EkMismatch);
    }
    {
        SignedFixture f;
        f.requirements.expected_measurements_hex = {std::string(96, '4'),
                                                    std::string(96, '6')};
        std::fill_n(f.evidence.svsm_report.begin() + snp_off::kMeasurement, 48, 0x66);
        std::fill_n(f.evidence.guest_report.begin() + snp_off::kMeasurement, 48, 0x66);
        f.resign_service();
        f.resign_guest();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::EkMismatch);
    }
    {
        // A third shape is not in the set, however validly signed.
        SignedFixture f;
        f.requirements.expected_measurements_hex = {std::string(96, '5'),
                                                    std::string(96, '6')};
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceMeasurementInvalid);
    }
    {
        // An empty set approves nothing; it never degrades into "skip".
        SignedFixture f;
        f.requirements.expected_measurements_hex.clear();
        EXPECT_EQ(f.failure(), SvsmEvidenceFailure::ServiceMeasurementInvalid);
    }
}

TEST(SvsmSignedMutations, AnUnsignedSemanticMutationStopsAtSignatureVerification) {
    SignedFixture fixture;
    fixture.evidence.guest_report[snp_off::kChipId] ^= 1;
    EXPECT_EQ(fixture.failure(), SvsmEvidenceFailure::GuestSignatureInvalid);
}

TEST(SvsmSignedMutations, TpmAndActivationMatrixHasExactTypedFailures) {
    {
        SignedTpmFixture f;
        EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::None);
    }
    {
        SignedTpmFixture f;
        f.evidence.ek_manifest = rsa_public(0xc7, true);
        const auto data = service_report_data(f.challenge, f.evidence.ek_manifest);
        std::copy(data.begin(), data.end(),
                  f.evidence.svsm_report.begin() + snp_off::kReportData);
        f.resign_service();
        EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::EkMismatch);
    }
    {
        SignedTpmFixture f;
        auto other = nexus_test::gen_rsa_key();
        f.evidence.ak_public = rsa_public_with_modulus(other->modulus);
        EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::AkMismatch);
    }
    {
        SignedTpmFixture f;
        f.requirements.expected_ak_ek_binding[0] ^= 1;
        EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::ActivationReceiptInvalid);
    }
    {
        SignedTpmFixture f;
        std::array<uint8_t, 32> wrong{};
        wrong.fill(0xee);
        f.set_quote(wrong);
        EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::QuoteNonceInvalid);
    }
    {
        SignedTpmFixture f;
        f.evidence.pcr_values[0] ^= 1;
        EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::QuotePcrDigestInvalid);
    }
    {
        SignedTpmFixture f;
        f.evidence.pcr_values[f.evidence.pcr_values.size() - 1] ^= 1;
        f.set_quote(evidence_binding(f.challenge, f.identity,
                                    nexus::crypto::from_hex(f.evidence.binary_sha256)));
        EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::ImaPcr10Mismatch);
    }
    {
        SignedTpmFixture f;
        ASSERT_FALSE(f.evidence.tpm_signature.empty());
        f.evidence.tpm_signature.back() ^= 1;
        EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::QuoteSignatureInvalid);
    }
}

TEST(SvsmSignedMutations, ResumeUsesCheckpointPcr10InsteadOfAStaticReleasePin) {
    SignedTpmFixture f;
    const auto prefix_bytes = binary_entry(f.evidence.binary_path, 0x66);
    const auto prefix_log = parse_ima_binary(prefix_bytes);
    ASSERT_TRUE(prefix_log);
    std::array<uint8_t, 32> zero{};
    const auto prefix = replay_ima_binary_from(*prefix_log, 0, zero);
    ASSERT_TRUE(prefix);

    AttestationCheckpoint checkpoint;
    checkpoint.profile_id = AttestationProfileId::SnpSvsmVtpm;
    checkpoint.profile_ruleset = kAttestationProfileRulesetVersion;
    checkpoint.ek_name = parse_tpmt_public_rsa(f.evidence.ek_manifest)->name;
    checkpoint.ak_name = parse_tpmt_public_rsa(f.evidence.ak_public)->name;
    checkpoint.ima_bank = kTpmAlgSha256;
    checkpoint.event_count = prefix->event_count;
    ASSERT_EQ(prefix->pcr10.size(), checkpoint.pcr10.size());
    std::copy(prefix->pcr10.begin(), prefix->pcr10.end(), checkpoint.pcr10.begin());
    checkpoint.required_paths = {{f.evidence.binary_path, std::string(64, '6')}};
    checkpoint.checkpoint_digest = attestation_checkpoint_digest(checkpoint);
    ASSERT_TRUE(attestation_checkpoint_valid(checkpoint));

    f.requirements.ima_mode = ImaEvidenceMode::Resume;
    f.requirements.checkpoint = &checkpoint;
    f.evidence.ima_binary_log = binary_entry(f.evidence.binary_path, 0x77);
    const auto suffix_log = parse_ima_binary(f.evidence.ima_binary_log);
    ASSERT_TRUE(suffix_log);
    const std::vector<ImaBinaryPathState> prior_paths{
        {f.evidence.binary_path, std::string(64, '6')}};
    const auto resumed = replay_ima_binary_from(
        *suffix_log, checkpoint.event_count, checkpoint.pcr10, prior_paths);
    ASSERT_TRUE(resumed);
    std::copy(resumed->pcr10.begin(), resumed->pcr10.end(),
              f.evidence.pcr_values.end() - 32);
    f.set_quote(evidence_binding(f.challenge, f.identity,
                                nexus::crypto::from_hex(f.evidence.binary_sha256)));
    EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::None);

    checkpoint.pcr10[0] ^= 1;
    checkpoint.checkpoint_digest = attestation_checkpoint_digest(checkpoint);
    EXPECT_EQ(f.full_failure(), SvsmEvidenceFailure::ImaPcr10Mismatch);
}

}  // namespace
