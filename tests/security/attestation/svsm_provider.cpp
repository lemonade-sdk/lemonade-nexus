#include <gtest/gtest.h>

#include <LemonadeNexus/Security/Attestation/PlatformEvidence.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationState.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/AzureSnpVtpmProvider.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/SnpSvsmVtpmProvider.hpp>
#include <LemonadeNexus/Security/Attestation/SvsmAkEnrollment.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>

#include "support/tpm_quote_fixtures.hpp"

#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

namespace {

using namespace nexus::security;
using nexus_test::binary_entry;
using nexus_test::rsa_public;

std::vector<uint8_t> digest(const EVP_MD* md, std::span<const uint8_t> bytes) {
    std::vector<uint8_t> out(EVP_MD_get_size(md));
    unsigned size = 0;
    EXPECT_EQ(EVP_Digest(bytes.data(), bytes.size(), out.data(), &size, md, nullptr), 1);
    out.resize(size);
    return out;
}

std::vector<uint8_t> read_file(const char* path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

TEST(SvsmManifest, ParsesRawTpmtPublicAndComputesTheTpmName) {
    const auto raw = rsa_public(0xa5, true);
    const auto parsed = parse_tpmt_public_rsa(raw);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->type, 1);
    EXPECT_EQ(parsed->name_alg, kTpmAlgSha256);
    EXPECT_EQ(parsed->object_attributes, 0x000300b2u);
    EXPECT_TRUE(is_svsm_vtpm_ek(*parsed));
    EXPECT_FALSE(is_nexus_quote_ak(*parsed));
    EXPECT_EQ(parsed->exponent, 65537u);
    ASSERT_EQ(parsed->name.size(), 34u);
    EXPECT_EQ(parsed->name[0], 0);
    EXPECT_EQ(parsed->name[1], kTpmAlgSha256);
    const auto expected = digest(EVP_sha256(), raw);
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), parsed->name.begin() + 2));
    EXPECT_FALSE(parsed->spki_b64.empty());
}

TEST(SvsmManifest, EnforcesDistinctEkAndQuoteAkObjectRoles) {
    const auto ek = parse_tpmt_public_rsa(rsa_public(0xa5, true));
    const auto ak = parse_tpmt_public_rsa(rsa_public(0xb6, false));
    ASSERT_TRUE(ek);
    ASSERT_TRUE(ak);
    EXPECT_TRUE(is_svsm_vtpm_ek(*ek));
    EXPECT_FALSE(is_nexus_quote_ak(*ek));
    EXPECT_TRUE(is_nexus_quote_ak(*ak));
    EXPECT_FALSE(is_svsm_vtpm_ek(*ak));

    auto relabelled = *ek;
    relabelled.object_attributes |= 1u << 18;  // SIGN_ENCRYPT on an EK
    EXPECT_FALSE(is_svsm_vtpm_ek(relabelled));
}

TEST(SvsmManifest, ParsesAnOptInLiveServiceManifest) {
    const char* path = std::getenv("NEXUS_SVSM_LIVE_MANIFEST");
    if (!path || *path == '\0') GTEST_SKIP() << "set NEXUS_SVSM_LIVE_MANIFEST";
    std::ifstream file(path, std::ios::binary);
    ASSERT_TRUE(file) << path;
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),
                                     std::istreambuf_iterator<char>()};
    const auto ek = parse_tpmt_public_rsa(bytes);
    ASSERT_TRUE(ek);
    EXPECT_TRUE(is_svsm_vtpm_ek(*ek));
    EXPECT_FALSE(is_nexus_quote_ak(*ek));
    RecordProperty("manifest_bytes", static_cast<int>(bytes.size()));
    RecordProperty("ek_name_hex", nexus::crypto::to_hex(ek->name));
}

TEST(SvsmManifest, RejectsWrappersTrailingDataAndWrongNameAlgorithm) {
    auto raw = rsa_public(0xa5, true);
    auto trailing = raw;
    trailing.push_back(0);
    EXPECT_FALSE(parse_tpmt_public_rsa(trailing));
    raw[2] = 0;
    raw[3] = kTpmAlgSha1;
    EXPECT_FALSE(parse_tpmt_public_rsa(raw));
    std::vector<uint8_t> wrapped;
    nexus_test::put_u16(wrapped, static_cast<uint16_t>(raw.size()));
    wrapped.insert(wrapped.end(), raw.begin(), raw.end());
    EXPECT_FALSE(parse_tpmt_public_rsa(wrapped));
}

TEST(SvsmNonce, IsA64ByteDomainSeparatedFunctionOfTheCanonicalChallengeDigest) {
    Digest first{};
    Digest second{};
    second[0] = 1;
    const auto a = svsm_report_nonce(first);
    const auto b = svsm_report_nonce(second);
    EXPECT_NE(a, b);
    EXPECT_EQ(a, svsm_report_nonce(first));
    EXPECT_FALSE(std::all_of(a.begin() + 32, a.end(), [](uint8_t v) { return v == 0; }));
}

TEST(SvsmEnrollment, AdmissionNonceAndCandidateIdentityAreDomainBound) {
    std::array<uint8_t, 32> nonce{};
    std::array<uint8_t, 32> identity{};
    nonce.fill(0x11);
    identity.fill(0x22);
    const auto base = svsm_enrollment_challenge_digest(nonce, identity);
    nonce[0] ^= 1;
    EXPECT_NE(svsm_enrollment_challenge_digest(nonce, identity), base);
    nonce[0] ^= 1;
    identity[0] ^= 1;
    EXPECT_NE(svsm_enrollment_challenge_digest(nonce, identity), base);
}

TEST(PlatformEvidence, TagsMakeAzureAndSvsmMutuallyExclusive) {
    PlatformEvidence azure{SnpVtpmEvidence{}};
    PlatformEvidence svsm{SnpSvsmVtpmEvidence{}};
    const auto azure_wire = encode_platform_evidence(azure);
    const auto svsm_wire = encode_platform_evidence(svsm);
    EXPECT_NE(azure_wire, svsm_wire);
    auto decoded_azure = decode_platform_evidence(azure_wire);
    auto decoded_svsm = decode_platform_evidence(svsm_wire);
    ASSERT_TRUE(decoded_azure);
    ASSERT_TRUE(decoded_svsm);
    EXPECT_TRUE(std::holds_alternative<SnpVtpmEvidence>(*decoded_azure));
    EXPECT_TRUE(std::holds_alternative<SnpSvsmVtpmEvidence>(*decoded_svsm));

    auto profile = linux_attestation_profile_v2_svsm();
    AttestationChallenge challenge;
    AttestationEvidence evidence;
    AzureSnpVtpmProvider azure_provider(profile);
    evidence.platform = SnpSvsmVtpmEvidence{};
    EXPECT_EQ(azure_provider.examine(challenge, evidence, {}).failure,
              AttestationFailure::ProfileIdMismatch);
    SnpSvsmVtpmProvider svsm_provider(profile);
    evidence.platform = SnpVtpmEvidence{};
    EXPECT_EQ(svsm_provider.examine(challenge, evidence, {}).failure,
              AttestationFailure::ProfileIdMismatch);

    auto inner = nlohmann::json::parse(encode_snp_svsm_vtpm_evidence(
        SnpSvsmVtpmEvidence{}));
    inner["hcl_blob"] = "must-not-be-accepted";
    EXPECT_FALSE(decode_snp_svsm_vtpm_evidence(inner.dump()));
}

TEST(PlatformEvidence, ProviderTypeIsInsideTheIdentitySigningDigest) {
    AttestationEvidence azure;
    azure.platform = SnpVtpmEvidence{};
    auto svsm = azure;
    svsm.platform = SnpSvsmVtpmEvidence{};
    EXPECT_NE(evidence_signing_digest(azure), evidence_signing_digest(svsm));
}

TEST(SvsmProviderReadiness, RequiresReleaseBootPcrPinsButNotDynamicImaPcr10) {
    auto profile = linux_attestation_profile_v2_svsm();
    profile.snp.min_tcb = {1, 1, 1, 1};
    profile.snp.expected_measurement_hex = std::string(96, 'a');
    profile.ima_policy_digest.fill(0x31);
    profile.approved_paths = {{"/usr/bin/nexus-attestd", {std::string(64, '3')}}};
    profile.evidence_collector_path = "/usr/bin/nexus-attestd";
    for (uint32_t pcr : kSvsmBootPcrs) {
        profile.expected_pcrs.emplace_back(pcr, std::string(64, '4'));
    }
    SnpSvsmVtpmProvider provider(profile);
    EXPECT_FALSE(provider.readiness().has_value());

    profile.expected_pcrs.erase(profile.expected_pcrs.begin());
    EXPECT_EQ(SnpSvsmVtpmProvider(profile).readiness(),
              AttestationFailure::ProfileIncomplete);

    profile.expected_pcrs.clear();
    for (uint32_t pcr : kSvsmBootPcrs)
        profile.expected_pcrs.emplace_back(pcr, std::string(64, '4'));
    profile.expected_pcrs.emplace_back(kImaPcr, std::string(64, '5'));
    EXPECT_EQ(SnpSvsmVtpmProvider(profile).readiness(),
              AttestationFailure::ProfileIncomplete);
}

TEST(BinaryIma, ReplaysExactSha256TemplateDataAndKeepsLastPathMeasurement) {
    auto first = binary_entry("/usr/bin/nexus-attestd", 0x11);
    const auto second = binary_entry("/usr/bin/nexus-attestd", 0x22);
    first.insert(first.end(), second.begin(), second.end());
    const auto log = parse_ima_binary(first);
    ASSERT_TRUE(log);
    ASSERT_EQ(log->entries.size(), 2u);
    const auto replay = replay_ima_binary_pcr(*log, 10, kTpmAlgSha256);
    ASSERT_EQ(replay.size(), 32u);
    const auto cut = ima_binary_truncate_to_pcr(first, 10, kTpmAlgSha256, replay);
    ASSERT_TRUE(cut);
    EXPECT_EQ(*cut, first);
    const auto last = ima_binary_entry_for_path(*log, "/usr/bin/nexus-attestd");
    ASSERT_TRUE(last);
    EXPECT_EQ(last->file_hash_hex, std::string(64, '2'));
    EXPECT_TRUE(replay_ima_binary_pcr(*log, 10, kTpmAlgSha1).empty());
}

TEST(BinaryIma, RejectsTruncationUnsupportedTemplatesMutationAndViolations) {
    const auto valid = binary_entry("/usr/bin/nexus-attestd", 0x11);
    auto truncated = valid;
    truncated.pop_back();
    EXPECT_FALSE(parse_ima_binary(truncated));

    const auto unsupported = binary_entry("/usr/bin/nexus-attestd", 0x11, "ima-buf");
    EXPECT_FALSE(parse_ima_binary(unsupported));

    auto changed = valid;
    changed.back() ^= 1;
    EXPECT_FALSE(parse_ima_binary(changed));

    auto violation = valid;
    std::fill(violation.begin() + 4, violation.begin() + 24, 0);
    const auto violation_log = parse_ima_binary(violation);
    ASSERT_TRUE(violation_log);
    EXPECT_TRUE(violation_log->entries.front().violation);
    EXPECT_TRUE(replay_ima_binary_pcr(*violation_log, 10, kTpmAlgSha256).empty());

    std::array<uint8_t, 32> impossible{};
    impossible[0] = 1;
    EXPECT_FALSE(ima_binary_truncate_to_pcr(valid, 10, kTpmAlgSha256, impossible));
}

TEST(BinaryIma, ParsesAnOptInLiveKernelCapture) {
    const char* path = std::getenv("NEXUS_SVSM_LIVE_IMA");
    if (!path || *path == '\0') GTEST_SKIP() << "set NEXUS_SVSM_LIVE_IMA to a read-only capture";
    std::ifstream file(path, std::ios::binary);
    ASSERT_TRUE(file) << path;
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),
                                     std::istreambuf_iterator<char>()};
    const auto log = parse_ima_binary(bytes);
    ASSERT_TRUE(log) << "the live binary_runtime_measurements ABI did not parse";
    ASSERT_FALSE(log->entries.empty());
    const auto violation = std::find_if(log->entries.begin(), log->entries.end(),
                                        [](const ImaBinaryEntry& entry) {
                                            return entry.violation;
                                        });
    EXPECT_EQ(violation, log->entries.end())
        << "live IMA violation marker at path '"
        << (violation == log->entries.end() ? "" : violation->path) << "'";
    if (violation == log->entries.end()) {
        EXPECT_EQ(replay_ima_binary_pcr(*log, 10, kTpmAlgSha256).size(), 32u);
    }
    RecordProperty("live_ima_bytes", static_cast<int>(bytes.size()));
    RecordProperty("live_ima_entries", static_cast<int>(log->entries.size()));
}

TEST(SvsmAkEnrollment, ReceiptRequiresTheExactActivatedSecretAndKeyNames) {
    const auto ek = rsa_public(0xc1, true);
    const auto ak = rsa_public(0xd3, false);
    std::string failure;
    const auto challenge = make_svsm_ak_activation_challenge(ek, ak, &failure);
    ASSERT_TRUE(challenge.has_value()) << failure;
    EXPECT_GT(challenge->credential_blob.size(), challenge->expected_secret.size());
    EXPECT_GT(challenge->encrypted_secret.size(), 2u);
    auto wrong = challenge->expected_secret;
    wrong[0] ^= 1;
    EXPECT_FALSE(complete_svsm_ak_activation(*challenge, wrong));
    const auto receipt = complete_svsm_ak_activation(*challenge,
                                                     challenge->expected_secret);
    ASSERT_TRUE(receipt);
    EXPECT_EQ(*receipt, ak_ek_binding_digest(challenge->ek_name, challenge->ak_name));

    Digest enrollment{};
    enrollment.fill(0x5a);
    const auto offer = svsm_ak_activation_offer(enrollment, *challenge);
    const auto decoded_offer = decode_svsm_ak_activation_offer(
        encode_svsm_ak_activation_offer(offer));
    ASSERT_TRUE(decoded_offer);
    EXPECT_EQ(decoded_offer->enrollment_context, offer.enrollment_context);
    EXPECT_EQ(decoded_offer->credential_blob, challenge->credential_blob);
    EXPECT_EQ(decoded_offer->encrypted_secret, challenge->encrypted_secret);

    SvsmAkActivationResponse response;
    response.enrollment_context = offer.enrollment_context;
    response.activated_secret = challenge->expected_secret;
    const auto decoded_response = decode_svsm_ak_activation_response(
        encode_svsm_ak_activation_response(response));
    ASSERT_TRUE(decoded_response);
    EXPECT_EQ(complete_svsm_ak_activation(enrollment, *challenge, *decoded_response),
              receipt);

    auto foreign_context = *decoded_response;
    foreign_context.enrollment_context[0] ^= 1;
    EXPECT_FALSE(complete_svsm_ak_activation(enrollment, *challenge, foreign_context));

    const auto with_unknown_field =
        encode_svsm_ak_activation_offer(offer).substr(
            0, encode_svsm_ak_activation_offer(offer).size() - 1) +
        ",\"qualifying_data\":\"attacker-selected\"}";
    EXPECT_FALSE(decode_svsm_ak_activation_offer(with_unknown_field));
}

TEST(SvsmAkEnrollment, RefusesKeysWithTheRightEncodingButWrongRoles) {
    const auto ek = rsa_public(0xc1, true);
    const auto ak = rsa_public(0xd3, false);
    std::string failure;
    EXPECT_FALSE(make_svsm_ak_activation_challenge(ak, ek, &failure));
    EXPECT_NE(failure.find("wrong TPM object role"), std::string::npos);
}

TEST(SvsmAkEnrollment, ActivatesAgainstAnOptInDisposableSoftwareTpm) {
    const char* ek_path = std::getenv("NEXUS_SVSM_TEST_EK_PUBLIC");
    const char* ak_path = std::getenv("NEXUS_SVSM_TEST_AK_PUBLIC");
    if (!ek_path || !ak_path || *ek_path == '\0' || *ak_path == '\0') {
        GTEST_SKIP() << "set NEXUS_SVSM_TEST_EK_PUBLIC and NEXUS_SVSM_TEST_AK_PUBLIC";
    }
    const auto ek = read_file(ek_path);
    const auto ak = read_file(ak_path);
    ASSERT_FALSE(ek.empty());
    ASSERT_FALSE(ak.empty());
    std::string failure;
    const auto challenge = make_svsm_ak_activation_challenge(ek, ak, &failure);
    ASSERT_TRUE(challenge) << failure;
    const auto activated = activate_svsm_ak_credential(
        ek, ak, challenge->credential_blob, challenge->encrypted_secret, &failure);
    ASSERT_TRUE(activated) << failure;
    EXPECT_EQ(*activated, challenge->expected_secret);
    EXPECT_TRUE(complete_svsm_ak_activation(*challenge, *activated));
}

TEST(SvsmAkEnrollment, LiveProtectedActivationPersistsOnlyTheExactEkAkPair) {
    const char* ek_path = std::getenv("NEXUS_SVSM_TEST_EK_PUBLIC");
    const char* ak_path = std::getenv("NEXUS_SVSM_TEST_AK_PUBLIC");
    const char* state_path = std::getenv("NEXUS_SVSM_TEST_STATE_DIR");
    if (!ek_path || !ak_path || !state_path || *ek_path == '\0' || *ak_path == '\0' ||
        *state_path == '\0') {
        GTEST_SKIP() << "set the live EK, AK and isolated verifier state paths";
    }
    const auto ek = read_file(ek_path);
    const auto ak = read_file(ak_path);
    const auto parsed_ek = parse_tpmt_public_rsa(ek);
    const auto parsed_ak = parse_tpmt_public_rsa(ak);
    ASSERT_TRUE(parsed_ek && is_svsm_vtpm_ek(*parsed_ek));
    ASSERT_TRUE(parsed_ak && is_nexus_quote_ak(*parsed_ak));

    std::string failure;
    const auto challenge = make_svsm_ak_activation_challenge(ek, ak, &failure);
    ASSERT_TRUE(challenge) << failure;
    const auto activated = activate_svsm_ak_credential(
        ek, ak, challenge->credential_blob, challenge->encrypted_secret, &failure);
    ASSERT_TRUE(activated) << failure;

    ASSERT_GE(sodium_init(), 0);
    nexus::crypto::Ed25519PublicKey identity_public{};
    nexus::crypto::Ed25519PrivateKey identity_private{};
    ASSERT_EQ(crypto_sign_keypair(identity_public.data(), identity_private.data()), 0);
    SvsmAkActivationOfferMessage offer;
    offer.network_id.fill(0x11);
    offer.subject_node.bytes = identity_public;
    offer.subject_key = identity_public;
    offer.incarnation = 1;
    offer.epoch = 2;
    offer.profile_id = AttestationProfileId::SnpSvsmVtpm;
    offer.profile_ruleset = kAttestationProfileRulesetVersion;
    offer.observer.bytes.fill(0x22);
    offer.enrollment_challenge_digest.fill(0x33);
    offer.verifier_nonce.fill(0x44);
    offer.ek_public = ek;
    offer.ak_public = ak;
    offer.ek_name = challenge->ek_name;
    offer.ak_name = challenge->ak_name;
    offer.ak_spki_digest = raw_ima_digest(nexus::crypto::from_base64(parsed_ak->spki_b64));
    offer.activation = svsm_ak_activation_offer(offer.enrollment_challenge_digest,
                                                *challenge);
    offer.activation.enrollment_context = svsm_ak_activation_offer_context(offer);

    SvsmAkActivationResponseMessage response;
    response.network_id = offer.network_id;
    response.subject_node = offer.subject_node;
    response.incarnation = offer.incarnation;
    response.epoch = offer.epoch;
    response.profile_id = offer.profile_id;
    response.profile_ruleset = offer.profile_ruleset;
    response.observer = offer.observer;
    response.activation_context = offer.activation.enrollment_context;
    response.activated_secret = *activated;
    const auto response_digest = svsm_ak_activation_response_digest(response);
    ASSERT_EQ(crypto_sign_detached(response.identity_signature.data(), nullptr,
                                   response_digest.data(), response_digest.size(),
                                   identity_private.data()), 0);

    SvsmAkActivationExchange exchange(*challenge, offer);
    const auto receipt = exchange.complete(response);
    ASSERT_TRUE(receipt);
    EXPECT_FALSE(exchange.complete(response));

    SvsmAkActivationRecord record;
    record.network_id = offer.network_id;
    record.node_id = offer.subject_node;
    record.node_key = offer.subject_key;
    record.incarnation = offer.incarnation;
    record.profile_id = offer.profile_id;
    record.profile_ruleset = offer.profile_ruleset;
    record.ek_name = offer.ek_name;
    record.ak_name = offer.ak_name;
    record.ak_spki_b64 = parsed_ak->spki_b64;
    record.ak_spki_digest = offer.ak_spki_digest;
    record.activation_receipt = *receipt;
    record.enrollment_evidence_digest.fill(0x55);
    {
        SvsmActivationStore store(state_path);
        ASSERT_TRUE(store.store(record));
    }
    SvsmActivationStore restarted(state_path);
    const auto loaded = restarted.load(record.network_id, record.node_id,
                                       record.incarnation, record.profile_id);
    ASSERT_TRUE(std::holds_alternative<SvsmAkActivationRecord>(loaded));
    EXPECT_EQ(std::get<SvsmAkActivationRecord>(loaded).activation_receipt, *receipt);

    auto substituted_ek = ek;
    substituted_ek.back() ^= 2;
    const auto wrong_ek = make_svsm_ak_activation_challenge(substituted_ek, ak, &failure);
    ASSERT_TRUE(wrong_ek) << failure;
    EXPECT_FALSE(activate_svsm_ak_credential(
        substituted_ek, ak, wrong_ek->credential_blob, wrong_ek->encrypted_secret,
        &failure));

    auto substituted_ak = ak;
    substituted_ak.back() ^= 2;
    const auto wrong_ak = make_svsm_ak_activation_challenge(ek, substituted_ak, &failure);
    ASSERT_TRUE(wrong_ak) << failure;
    EXPECT_FALSE(activate_svsm_ak_credential(
        ek, substituted_ak, wrong_ak->credential_blob, wrong_ak->encrypted_secret,
        &failure));

    auto wrong_attributes = ak;
    wrong_attributes[7] ^= 0x02;
    EXPECT_FALSE(make_svsm_ak_activation_challenge(ek, wrong_attributes, &failure));
    RecordProperty("ek_name_hex", nexus::crypto::to_hex(record.ek_name));
    RecordProperty("ak_name_hex", nexus::crypto::to_hex(record.ak_name));
    RecordProperty("activation_receipt_hex", nexus::crypto::to_hex(*receipt));
}

TEST(SvsmAkEnrollment, ReloadsProtectedActivationInAFreshVerifierProcess) {
    const char* state_path = std::getenv("NEXUS_SVSM_TEST_STATE_DIR");
    if (!state_path || *state_path == '\0') {
        GTEST_SKIP() << "set the isolated verifier state path";
    }
    std::ifstream file(std::filesystem::path(state_path) / "svsm-ak-activations.json");
    ASSERT_TRUE(file);
    const auto document = nlohmann::json::parse(file, nullptr, false);
    ASSERT_TRUE(document.is_object());
    ASSERT_TRUE(document.contains("records") && document["records"].is_array());
    ASSERT_EQ(document["records"].size(), 1u);
    const auto& encoded = document["records"][0];
    const auto network_bytes = nexus::crypto::from_hex(encoded.at("network_id").get<std::string>());
    const auto node_bytes = nexus::crypto::from_hex(encoded.at("node_id").get<std::string>());
    ASSERT_EQ(network_bytes.size(), NetworkId{}.size());
    ASSERT_EQ(node_bytes.size(), NodeId{}.bytes.size());
    NetworkId network{};
    NodeId node{};
    std::copy(network_bytes.begin(), network_bytes.end(), network.begin());
    std::copy(node_bytes.begin(), node_bytes.end(), node.bytes.begin());
    SvsmActivationStore restarted(state_path);
    const auto loaded = restarted.load(
        network, node, IncarnationId{encoded.at("incarnation").get<uint64_t>()},
        static_cast<AttestationProfileId>(encoded.at("profile_id").get<uint16_t>()));
    ASSERT_TRUE(std::holds_alternative<SvsmAkActivationRecord>(loaded));
    EXPECT_TRUE(svsm_activation_record_valid(std::get<SvsmAkActivationRecord>(loaded)));
}

}  // namespace
