#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTransfer.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/SnpSvsmVtpmProvider.hpp>
#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>
#include <LemonadeNexusAttestd/AttestdClient.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__)
#include <sys/stat.h>
#endif

using namespace nexus::security;
namespace attestd = nexus::attestd;
namespace crypto = nexus::crypto;
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

std::string required_env(const char* name) {
    const char* value = std::getenv(name);
    if (!value || !*value) throw std::runtime_error(std::string("missing ") + name);
    return value;
}

std::vector<uint8_t> read_bytes(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read " + path.string());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string read_text(const fs::path& path) {
    const auto bytes = read_bytes(path);
    return {bytes.begin(), bytes.end()};
}

void write_bytes(const fs::path& path, std::span<const uint8_t> bytes, unsigned mode = 0644) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot write " + path.string());
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    out.close();
    if (!out)
        throw std::runtime_error("cannot finish " + path.string());
#if defined(__linux__)
    if (::chmod(path.c_str(), static_cast<mode_t>(mode)) != 0)
        throw std::runtime_error("cannot set mode on " + path.string());
#else
    (void)mode;
#endif
}

void write_text(const fs::path& path, std::string_view text) {
    write_bytes(path, {reinterpret_cast<const uint8_t*>(text.data()), text.size()});
}

crypto::Ed25519Keypair load_or_create_identity(const fs::path& path) {
    crypto::Ed25519Keypair identity;
    if (fs::exists(path)) {
        const auto bytes = read_bytes(path);
        if (bytes.size() != identity.public_key.size() + identity.private_key.size())
            throw std::runtime_error("invalid identity file");
        std::copy_n(bytes.begin(), identity.public_key.size(), identity.public_key.begin());
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(identity.public_key.size()),
                    identity.private_key.size(), identity.private_key.begin());
        crypto::Ed25519PublicKey derived{};
        if (crypto_sign_ed25519_sk_to_pk(derived.data(), identity.private_key.data()) != 0 ||
            derived != identity.public_key)
            throw std::runtime_error("identity key mismatch");
        return identity;
    }
    fs::create_directories(path.parent_path());
    fs::permissions(path.parent_path(), fs::perms::owner_all, fs::perm_options::replace);
    crypto_sign_keypair(identity.public_key.data(), identity.private_key.data());
    std::vector<uint8_t> bytes(identity.public_key.begin(), identity.public_key.end());
    bytes.insert(bytes.end(), identity.private_key.begin(), identity.private_key.end());
    write_bytes(path, bytes, 0600);
    return identity;
}

crypto::Ed25519PublicKey vote_key() {
    std::array<uint8_t, crypto_sign_SEEDBYTES> seed{};
    seed.fill(0x6d);
    crypto::Ed25519Keypair key;
    crypto_sign_seed_keypair(key.public_key.data(), key.private_key.data(), seed.data());
    return key.public_key;
}

LinuxAttestationProfile diagnostic_profile(const fs::path& path) {
    const json input = json::parse(read_text(path));
    if (input.value("diagnostic_only", false) != true)
        throw std::runtime_error("policy is not marked diagnostic-only");
    auto profile = linux_attestation_profile_v3_svsm_release();
    profile.approved_paths.clear();
    for (const auto& item : input.at("approved_paths")) {
        profile.approved_paths.push_back(
            {item.at("path").get<std::string>(), item.at("sha256").get<std::vector<std::string>>()});
    }
    profile.evidence_collector_path = input.at("evidence_collector_path").get<std::string>();
    profile.expected_pcrs.clear();
    for (const auto& item : input.at("expected_pcrs")) {
        profile.expected_pcrs.emplace_back(item.at("index").get<uint32_t>(),
                                           item.at("sha256").get<std::string>());
    }
    if (!profile_is_complete(profile)) throw std::runtime_error("diagnostic profile incomplete");
    SnpSvsmVtpmProvider provider(profile, {});
    if (provider.readiness()) throw std::runtime_error("diagnostic SVSM profile not ready");
    return profile;
}

SecurityMessage message_for(const AttestationChallenge& value, const NodeId& sender) {
    return {SecurityMessageKind::AttestationChallenge, constants::kSecurityRulesetVersion,
            constants::kConsensusRulesetVersion, value.network_id, value.epoch, sender, value};
}

SecurityMessage message_for(const AttestationEvidence& value, const NodeId& sender) {
    return {SecurityMessageKind::AttestationEvidence, constants::kSecurityRulesetVersion,
            constants::kConsensusRulesetVersion, value.network_id, value.epoch, sender, value};
}

SecurityMessage message_for(const SvsmAkActivationResponseMessage& value, const NodeId& sender) {
    return {SecurityMessageKind::SvsmAkActivationResponse, constants::kSecurityRulesetVersion,
            constants::kConsensusRulesetVersion, value.network_id, value.epoch, sender, value};
}

SecurityMessage message_for(const AttestationEvidenceStart& value, const NodeId& sender) {
    return {SecurityMessageKind::AttestationEvidenceStart, constants::kSecurityRulesetVersion,
            constants::kConsensusRulesetVersion, value.evidence.network_id, value.evidence.epoch,
            sender, value};
}

SecurityMessage message_for(const AttestationEvidenceChunk& value, const NodeId& sender) {
    return {SecurityMessageKind::AttestationEvidenceChunk, constants::kSecurityRulesetVersion,
            constants::kConsensusRulesetVersion, {}, {}, sender, value};
}

SecurityMessage message_for(const AttestationEvidenceEnd& value, const NodeId& sender) {
    return {SecurityMessageKind::AttestationEvidenceEnd, constants::kSecurityRulesetVersion,
            constants::kConsensusRulesetVersion, {}, {}, sender, value};
}

template <typename T>
void save_wire(const fs::path& path, const T& value, const NodeId& sender, unsigned mode = 0644) {
    const auto bytes = encode_security_message(message_for(value, sender));
    if (bytes.empty()) throw std::runtime_error("wire encoding failed");
    write_bytes(path, bytes, mode);
}

template <typename T>
T load_wire_body(const fs::path& path) {
    const auto decoded = decode_security_message(read_bytes(path));
    if (!std::holds_alternative<SecurityMessage>(decoded))
        throw std::runtime_error("wire decoding failed");
    const auto& body = std::get<SecurityMessage>(decoded).body;
    if (!std::holds_alternative<T>(body)) throw std::runtime_error("wrong wire body");
    return std::get<T>(body);
}

void save_transfer(const fs::path& directory, const AttestationEvidence& evidence,
                   const NodeId& sender) {
    const auto transfer = make_evidence_transfer(evidence);
    if (!transfer) throw std::runtime_error("evidence transfer creation failed");
    fs::create_directories(directory / "chunks");
    save_wire(directory / "start.wire", transfer->start, sender);
    for (std::size_t i = 0; i < transfer->chunks.size(); ++i) {
        save_wire(directory / "chunks" / (std::to_string(i) + ".wire"),
                  transfer->chunks[i], sender);
    }
    save_wire(directory / "end.wire", transfer->end, sender);
    json summary = {{"format", "bounded-attestation-evidence-transfer"},
                    {"transfer_id", crypto::to_hex(transfer->start.transfer_id)},
                    {"ima_bytes", transfer->start.ima_bytes},
                    {"total_transfer_bytes", transfer->start.total_transfer_bytes},
                    {"total_chunks", transfer->start.total_chunks},
                    {"ima_digest", crypto::to_hex(transfer->start.ima_digest)},
                    {"platform_digest", crypto::to_hex(transfer->start.platform_digest)}};
    write_text(directory / "summary.json", summary.dump(2) + "\n");
}

AttestationEvidence load_transfer(const fs::path& directory,
                                  const AttestationChallenge& challenge,
                                  const NodeId& sender) {
    const auto start = load_wire_body<AttestationEvidenceStart>(directory / "start.wire");
    AttestationTransferReceiver receiver;
    if (receiver.begin(sender, start, challenge, 0).failure != EvidenceTransferFailure::None)
        throw std::runtime_error("evidence transfer start rejected");
    for (uint32_t i = 0; i < start.total_chunks; ++i) {
        const auto chunk = load_wire_body<AttestationEvidenceChunk>(
            directory / "chunks" / (std::to_string(i) + ".wire"));
        if (receiver.chunk(sender, chunk, i + 1).failure != EvidenceTransferFailure::None)
            throw std::runtime_error("evidence transfer chunk rejected");
    }
    const auto end = load_wire_body<AttestationEvidenceEnd>(directory / "end.wire");
    auto result = receiver.end(sender, end, start.total_chunks + 1);
    if (!result.ok()) throw std::runtime_error("evidence transfer end rejected");
    return std::move(*result.evidence);
}

json challenge_json(const AttestationChallenge& challenge) {
    return {{"network_id", crypto::to_hex(challenge.network_id)},
            {"challenge_digest", crypto::to_hex(challenge_digest(challenge))},
            {"node_id", crypto::to_hex(challenge.node_id.bytes)},
            {"node_key", crypto::to_hex(challenge.node_key)},
            {"incarnation", challenge.incarnation.underlying()},
            {"epoch", challenge.epoch.underlying()},
            {"purpose", static_cast<uint16_t>(challenge.purpose)},
            {"context_digest", crypto::to_hex(challenge.context_digest)},
            {"policy_digest", crypto::to_hex(challenge.policy_digest)},
            {"ima_mode", static_cast<uint16_t>(challenge.ima_mode)},
            {"ima_checkpoint_digest", crypto::to_hex(challenge.ima_checkpoint_digest)},
            {"ima_prior_event_count", challenge.ima_prior_event_count},
            {"ima_prior_pcr10", crypto::to_hex(challenge.ima_prior_pcr10)}};
}

json record_json(const SvsmAkActivationRecord& record) {
    return {{"network_id", crypto::to_hex(record.network_id)},
            {"node_id", crypto::to_hex(record.node_id.bytes)},
            {"node_key", crypto::to_hex(record.node_key)},
            {"incarnation", record.incarnation.underlying()},
            {"profile_id", static_cast<uint16_t>(record.profile_id)},
            {"profile_ruleset", record.profile_ruleset},
            {"ek_name", crypto::to_hex(record.ek_name)},
            {"ak_name", crypto::to_hex(record.ak_name)},
            {"ak_spki_b64", record.ak_spki_b64},
            {"ak_spki_digest", crypto::to_hex(record.ak_spki_digest)},
            {"activation_receipt", crypto::to_hex(record.activation_receipt)},
            {"enrollment_evidence_digest", crypto::to_hex(record.enrollment_evidence_digest)},
            {"record_digest", crypto::to_hex(record.record_digest)}};
}

class SvsmServiceLive : public ::testing::Test {
protected:
    void SetUp() override {
        const char* enabled = std::getenv("NEXUS_SERVICE_LIVE_ENABLE");
        if (!enabled) {
            GTEST_SKIP() << "set NEXUS_SERVICE_LIVE_ENABLE=1 to run hardware diagnostics";
        }
        if (std::string_view(enabled) != "1") {
            FAIL() << "NEXUS_SERVICE_LIVE_ENABLE must be exactly 1";
        }
#if !defined(__linux__) || !defined(LEMONADE_HAVE_TPM_FAPI)
        FAIL() << "SVSM service diagnostics require Linux and TPM FAPI support";
#else
        ASSERT_GE(sodium_init(), 0);
        try {
            output_ = required_env("NEXUS_SERVICE_LIVE_OUTPUT");
            state_ = required_env("NEXUS_SERVICE_LIVE_STATE");
            secret_ = required_env("NEXUS_SERVICE_LIVE_SECRET");
            identity_path_ = secret_ / "node-identity.bin";
            old_response_path_ = secret_ / "first-activation-response.wire";
            profile_ = diagnostic_profile(required_env("NEXUS_SERVICE_LIVE_POLICY"));
            crl_ = read_text(required_env("NEXUS_SERVICE_LIVE_CRL"));
            identity_ = load_or_create_identity(identity_path_);
            socket_ = required_env("NEXUS_SERVICE_LIVE_SOCKET");
            cache_ = required_env("NEXUS_SERVICE_LIVE_CACHE");
            fs::create_directories(output_);
        } catch (const std::exception& e) {
            FAIL() << e.what();
        }
        network_.fill(0x5a);
        observer_.bytes.fill(0xa5);
        node_.bytes = identity_.public_key;
#endif
    }

    AmdRevocationSource revocation() const {
        const auto crl = crl_;
        return [crl] {
            AmdRevocationState state;
            state.crls = {crl};
            state.now_unix = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            return state;
        };
    }

    PlatformEvidenceProducer producer() const {
        EvidenceProducerSources sources;
        sources.identity = identity_;
        sources.vote_key_for_epoch = [](EpochId) { return std::optional{vote_key()}; };
        sources.cache_directory = cache_;
        attestd::AttestdClientConfig config;
        config.path = socket_;
        sources.platform_source = attestd::attestd_platform_source(config);
        return PlatformEvidenceProducer(std::move(sources));
    }

    AttestationService service() const {
        return AttestationService(network_, profile_, revocation(), state_);
    }

    SvsmAkActivationRecord load_record() const {
        SvsmActivationStore store(state_ / "svsm-activations");
        const auto loaded = store.load(network_, node_, incarnation_, AttestationProfileId::SnpSvsmVtpm);
        if (!std::holds_alternative<SvsmAkActivationRecord>(loaded))
            throw std::runtime_error("activation record absent");
        return std::get<SvsmAkActivationRecord>(loaded);
    }

    fs::path output_;
    fs::path state_;
    fs::path secret_;
    fs::path identity_path_;
    fs::path old_response_path_;
    fs::path socket_;
    fs::path cache_;
    LinuxAttestationProfile profile_;
    std::string crl_;
    crypto::Ed25519Keypair identity_;
    NetworkId network_{};
    NodeId observer_{};
    NodeId node_{};
    IncarnationId incarnation_{11};
    EpochId epoch_{47};
};

TEST_F(SvsmServiceLive, FirstBootEnrollmentAndAttestationUseTheServiceHandlers) {
    ASSERT_FALSE(fs::exists(state_ / "svsm-activations"));
    auto verifier = service();
    auto candidate = producer();

    const auto enrollment_challenge = verifier.create_challenge(
        node_, identity_.public_key, incarnation_, epoch_, AttestationPurpose::Eligibility);
    ASSERT_TRUE(enrollment_challenge);
    ASSERT_EQ(enrollment_challenge->purpose, AttestationPurpose::PlatformEnrollment);
    const auto enrollment = candidate.produce(*enrollment_challenge);
    ASSERT_TRUE(enrollment);
    ASSERT_EQ(enrollment->node_id, node_);
    ASSERT_EQ(enrollment->purpose, AttestationPurpose::PlatformEnrollment);
    const auto* enrolled_svsm = std::get_if<SnpSvsmVtpmEvidence>(&enrollment->platform);
    ASSERT_NE(enrolled_svsm, nullptr);
    ASSERT_TRUE(enrolled_svsm->ima_binary_log.empty());

    save_wire(output_ / "first-enrollment-challenge.wire", *enrollment_challenge, observer_);
    save_wire(output_ / "first-enrollment-evidence.wire", *enrollment, node_);
    write_text(output_ / "first-enrollment-challenge.json",
               challenge_json(*enrollment_challenge).dump(2) + "\n");
    write_text(output_ / "first-enrollment-platform.json",
               encode_platform_evidence(enrollment->platform) + "\n");

    const auto offer = verifier.receive_enrollment_evidence(*enrollment, observer_);
    ASSERT_TRUE(offer);
    ASSERT_EQ(offer->subject_node, node_);
    ASSERT_EQ(offer->subject_key, identity_.public_key);
    ASSERT_EQ(offer->ek_public, enrolled_svsm->ek_manifest);
    ASSERT_EQ(offer->ak_public, enrolled_svsm->ak_public);
    const auto response = candidate.activate(*offer);
    ASSERT_TRUE(response);

    auto altered = *response;
    altered.activation_context.front() ^= 1;
    EXPECT_FALSE(verifier.receive_activation_response(altered));
    const auto normal_challenge = verifier.receive_activation_response(*response);
    ASSERT_TRUE(normal_challenge);
    EXPECT_FALSE(verifier.receive_activation_response(*response));
    EXPECT_FALSE(verifier.receive_enrollment_evidence(*enrollment, observer_));
    save_wire(old_response_path_, *response, node_, 0600);

    const auto record = load_record();
    EXPECT_TRUE(svsm_activation_record_valid(record));
    EXPECT_EQ(record.node_id, enrollment->node_id);
    EXPECT_EQ(record.node_key, identity_.public_key);
    EXPECT_EQ(record.ek_name, offer->ek_name);
    EXPECT_EQ(record.ak_name, offer->ak_name);
    EXPECT_EQ(record.enrollment_evidence_digest, evidence_signing_digest(*enrollment));
    EXPECT_EQ(record.ak_spki_digest, offer->ak_spki_digest);
    write_text(output_ / "activation-record-public.json", record_json(record).dump(2) + "\n");

    ASSERT_EQ(normal_challenge->purpose, AttestationPurpose::Eligibility);
    ASSERT_EQ(normal_challenge->ima_mode, ImaEvidenceMode::Full);
    const auto normal = candidate.produce(*normal_challenge);
    ASSERT_TRUE(normal);
    save_wire(output_ / "first-normal-challenge.wire", *normal_challenge, observer_);
    save_transfer(output_ / "first-normal-transfer", *normal, node_);
    write_text(output_ / "first-normal-challenge.json", challenge_json(*normal_challenge).dump(2) + "\n");
    write_text(output_ / "first-normal-platform.json", encode_platform_evidence(normal->platform) + "\n");
    const auto verdict = verifier.receive_evidence(*normal);
    ASSERT_TRUE(verdict.passed) << static_cast<uint16_t>(verdict.failure);
    EXPECT_EQ(verdict.failure, AttestationFailure::None);
    const auto replay = verifier.receive_evidence(*normal);
    EXPECT_FALSE(replay.passed);
    EXPECT_EQ(replay.failure, AttestationFailure::ChallengeMismatch);

    json result = {{"diagnostic_only", true},
                   {"service_create_challenge", "platform-enrollment"},
                   {"service_receive_enrollment_evidence", "accepted"},
                   {"producer_activate_credential", "accepted"},
                   {"altered_activation_response", "rejected"},
                   {"service_receive_activation_response", "accepted-and-persisted"},
                   {"activation_response_replay", "rejected"},
                   {"enrollment_evidence_replay", "rejected"},
                   {"normal_attestation", "passed"},
                   {"normal_evidence_replay", "challenge-mismatch"},
                   {"node_id", crypto::to_hex(node_.bytes)},
                   {"enrollment_evidence_digest", crypto::to_hex(evidence_signing_digest(*enrollment))},
                   {"ek_name", crypto::to_hex(record.ek_name)},
                   {"ak_name", crypto::to_hex(record.ak_name)},
                   {"activation_receipt", crypto::to_hex(record.activation_receipt)},
                   {"evidence_digest", crypto::to_hex(verdict.evidence_digest)}};
    write_text(output_ / "first-boot-result.json", result.dump(2) + "\n");
}

TEST_F(SvsmServiceLive, VerifierRestartLoadsExactEnrollmentAndAttestsAgain) {
    const auto enrollment = load_wire_body<AttestationEvidence>(
        output_ / "first-enrollment-evidence.wire");
    const auto* svsm = std::get_if<SnpSvsmVtpmEvidence>(&enrollment.platform);
    ASSERT_NE(svsm, nullptr);
    const auto record = load_record();
    SvsmAkEnrollmentRequirements requirements;
    requirements.policy = profile_.snp;
    requirements.require_revocation_check = profile_.require_endorsement_revocation;
    requirements.revocation = revocation()();
    const auto independent = verify_svsm_ak_enrollment_identity(
        *svsm, enrollment.challenge_digest, requirements);
    ASSERT_TRUE(independent.ok) << independent.failure;
    EXPECT_EQ(record.ek_name, independent.ek_name);
    EXPECT_EQ(record.ak_name, independent.ak_name);
    EXPECT_EQ(record.ak_spki_b64, independent.ak_spki_b64);
    EXPECT_EQ(record.enrollment_evidence_digest, evidence_signing_digest(enrollment));

    auto restarted = service();
    auto candidate = producer();
    const auto challenge = restarted.create_challenge(
        node_, identity_.public_key, incarnation_, epoch_, AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge);
    ASSERT_EQ(challenge->purpose, AttestationPurpose::Eligibility);
    ASSERT_EQ(challenge->ima_mode, ImaEvidenceMode::Resume);
    const auto evidence = candidate.produce(*challenge);
    ASSERT_TRUE(evidence);
    const auto verdict = restarted.receive_evidence(*evidence);
    ASSERT_TRUE(verdict.passed) << static_cast<uint16_t>(verdict.failure);

    save_wire(output_ / "same-boot-restart-challenge.wire", *challenge, observer_);
    save_transfer(output_ / "same-boot-restart-transfer", *evidence, node_);
    write_text(output_ / "same-boot-restart-challenge.json", challenge_json(*challenge).dump(2) + "\n");
    write_text(output_ / "same-boot-restart-platform.json", encode_platform_evidence(evidence->platform) + "\n");
    json result = {{"diagnostic_only", true},
                   {"new_verifier_process", true},
                   {"challenge_purpose", "eligibility"},
                   {"ima_mode", "resume"},
                   {"stored_record_valid", svsm_activation_record_valid(record)},
                   {"stored_ek_matches_retained_enrollment", record.ek_name == independent.ek_name},
                   {"stored_ak_matches_retained_enrollment", record.ak_name == independent.ak_name},
                   {"stored_spki_matches_retained_enrollment", record.ak_spki_b64 == independent.ak_spki_b64},
                   {"stored_transcript_digest_matches", record.enrollment_evidence_digest == evidence_signing_digest(enrollment)},
                   {"normal_attestation", "passed"},
                   {"evidence_digest", crypto::to_hex(verdict.evidence_digest)}};
    write_text(output_ / "same-boot-restart-result.json", result.dump(2) + "\n");
}

TEST_F(SvsmServiceLive, VmRestartRejectsOldStateAndHasNoReenrollmentTransition) {
    const auto old_enrollment = load_wire_body<AttestationEvidence>(
        output_ / "first-enrollment-evidence.wire");
    const auto old_normal_challenge = load_wire_body<AttestationChallenge>(
        output_ / "first-normal-challenge.wire");
    const auto old_normal = load_transfer(
        output_ / "first-normal-transfer", old_normal_challenge, node_);
    const auto old_response = load_wire_body<SvsmAkActivationResponseMessage>(old_response_path_);
    const auto record = load_record();
    auto verifier = service();
    auto candidate = producer();

    const auto challenge = verifier.create_challenge(
        node_, identity_.public_key, incarnation_, EpochId{48}, AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge);
    ASSERT_EQ(challenge->purpose, AttestationPurpose::Eligibility);
    const auto old_verdict = verifier.receive_evidence(old_normal);
    EXPECT_FALSE(old_verdict.passed);
    EXPECT_EQ(old_verdict.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_FALSE(verifier.receive_activation_response(old_response));

    const auto fresh = candidate.produce(*challenge);
    ASSERT_TRUE(fresh);
    const auto* old_svsm = std::get_if<SnpSvsmVtpmEvidence>(&old_enrollment.platform);
    ASSERT_NE(old_svsm, nullptr);
    const auto verdict = verifier.receive_evidence(*fresh);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::SnpInvalid);

    const auto next = verifier.create_challenge(
        node_, identity_.public_key, incarnation_, EpochId{48}, AttestationPurpose::Eligibility);
    ASSERT_TRUE(next);
    EXPECT_EQ(next->purpose, AttestationPurpose::Eligibility);
    EXPECT_EQ(next->ima_mode, ImaEvidenceMode::Resume);
    EXPECT_NE(next->purpose, AttestationPurpose::PlatformEnrollment);

    AttestationService probe(network_, profile_, revocation(), output_ / "post-restart-probe-state");
    const auto enrollment_challenge = probe.create_challenge(
        node_, identity_.public_key, incarnation_, EpochId{48}, AttestationPurpose::Eligibility);
    ASSERT_TRUE(enrollment_challenge);
    ASSERT_EQ(enrollment_challenge->purpose, AttestationPurpose::PlatformEnrollment);
    EXPECT_FALSE(probe.receive_enrollment_evidence(old_enrollment, observer_));
    const auto fresh_enrollment = candidate.produce(*enrollment_challenge);
    ASSERT_TRUE(fresh_enrollment);
    const auto* fresh_svsm = std::get_if<SnpSvsmVtpmEvidence>(&fresh_enrollment->platform);
    ASSERT_NE(fresh_svsm, nullptr);
    const bool fresh_keys_changed = fresh_svsm->ek_manifest != old_svsm->ek_manifest ||
                                    fresh_svsm->ak_public != old_svsm->ak_public;
    EXPECT_TRUE(fresh_keys_changed);
    const auto probe_offer = probe.receive_enrollment_evidence(*fresh_enrollment, observer_);
    ASSERT_TRUE(probe_offer);
    EXPECT_FALSE(probe.receive_activation_response(old_response));

    save_wire(output_ / "post-vm-restart-challenge.wire", *challenge, observer_);
    save_wire(output_ / "post-vm-restart-persisted-evidence.wire", *fresh, node_);
    save_wire(output_ / "post-vm-restart-probe-challenge.wire", *enrollment_challenge, observer_);
    save_wire(output_ / "post-vm-restart-probe-enrollment.wire", *fresh_enrollment, node_);
    write_text(output_ / "post-vm-restart-challenge.json", challenge_json(*challenge).dump(2) + "\n");
    write_text(output_ / "post-vm-restart-persisted-platform.json", encode_platform_evidence(fresh->platform) + "\n");
    write_text(output_ / "post-vm-restart-probe-challenge.json",
               challenge_json(*enrollment_challenge).dump(2) + "\n");
    write_text(output_ / "post-vm-restart-probe-enrollment-platform.json",
               encode_platform_evidence(fresh_enrollment->platform) + "\n");
    json result = {{"diagnostic_only", true},
                   {"old_record_loaded", svsm_activation_record_valid(record)},
                   {"old_normal_evidence", "challenge-mismatch"},
                   {"old_activation_response", "rejected-no-pending-exchange"},
                   {"persisted_resume_after_reboot_passed", verdict.passed},
                   {"persisted_resume_failure", static_cast<uint16_t>(verdict.failure)},
                   {"persisted_resume_boundary", "old IMA checkpoint is not this boot's prefix"},
                   {"fresh_ek_or_ak_changed", fresh_keys_changed},
                   {"probe_old_enrollment_evidence", "challenge-mismatch"},
                   {"probe_fresh_enrollment_evidence", "accepted-offer-created"},
                   {"old_activation_response_for_fresh_exchange", "rejected"},
                   {"next_challenge_purpose", static_cast<uint16_t>(next->purpose)},
                   {"next_challenge_ima_mode", static_cast<uint16_t>(next->ima_mode)},
                   {"reenrollment_transition_available", next->purpose == AttestationPurpose::PlatformEnrollment},
                   {"probe_state_is_recovery", false},
                   {"old_ek_manifest_sha256", crypto::to_hex(raw_ima_digest(old_svsm->ek_manifest))},
                   {"new_ek_manifest_sha256", crypto::to_hex(raw_ima_digest(fresh_svsm->ek_manifest))},
                   {"old_ak_public_sha256", crypto::to_hex(raw_ima_digest(old_svsm->ak_public))},
                   {"new_ak_public_sha256", crypto::to_hex(raw_ima_digest(fresh_svsm->ak_public))}};
    write_text(output_ / "post-vm-restart-result.json", result.dump(2) + "\n");
}

}  // namespace
