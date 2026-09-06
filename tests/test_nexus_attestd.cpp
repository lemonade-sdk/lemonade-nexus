// nexus-attestd: the logic that does not need a TPM.
//
// The daemon's value is entirely in what it REFUSES. These tests pin the refusal
// set, pin the derived quote binding against the shared evidence_binding() rule,
// and pin the closed request grammar — which is what makes "a caller cannot
// supply raw qualifyingData" a checkable property rather than a claim in a
// comment.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/EvidenceBinding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexusAttestd/AttestdClient.hpp>
#include <LemonadeNexusAttestd/AttestdCodec.hpp>
#include <LemonadeNexusAttestd/AttestdFraming.hpp>
#include <LemonadeNexusAttestd/AttestdGate.hpp>
#include <LemonadeNexusAttestd/AttestdService.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace constants = nexus::security::constants;
namespace fs = std::filesystem;

using nexus::attestd::AttestdConfig;
using nexus::attestd::AttestdService;
using nexus::attestd::Refusal;
using nexus::attestd::check_challenge;
using nexus::attestd::decode_challenge;
using nexus::attestd::derive_quote_binding;
using nexus::attestd::PlatformEvidenceBundle;
using nexus::security::AttestationChallenge;
using nexus::security::AttestationProfileId;
using nexus::security::AttestationPurpose;
using nexus::security::challenge_digest;
using nexus::security::evidence_binding;

namespace {

using json = nlohmann::json;
using nexus::attestd::FrameKind;

/// Split a framed response into (kind, payload) pairs. The bounds are asserted
/// here so a malformed stream fails as a test error, not as a hang.
std::vector<std::pair<FrameKind, std::string>> split_frames(std::string_view bytes) {
    std::vector<std::pair<FrameKind, std::string>> out;
    std::size_t at = 0;
    while (at + nexus::attestd::kFrameHeaderBytes <= bytes.size()) {
        const auto* p = reinterpret_cast<const uint8_t*>(bytes.data()) + at;
        const std::size_t len = (std::size_t(p[0]) << 24) | (std::size_t(p[1]) << 16) |
                                (std::size_t(p[2]) << 8) | std::size_t(p[3]);
        at += nexus::attestd::kFrameHeaderBytes;
        if (at + len > bytes.size()) break;
        out.emplace_back(static_cast<FrameKind>(p[4]), std::string(bytes.substr(at, len)));
        at += len;
    }
    return out;
}

/// Drive the service and return everything it wrote.
std::string collect_frames(AttestdService& service, std::string_view request) {
    std::string wire;
    service.handle_request(request, [&](std::string_view frame) {
        wire.append(frame);
        return true;
    });
    return wire;
}

/// The single frame of a response that should have exactly one.
std::pair<FrameKind, std::string> one_frame(AttestdService& service, std::string_view request) {
    const auto frames = split_frames(collect_frames(service, request));
    EXPECT_EQ(frames.size(), 1u);
    return frames.empty() ? std::pair{FrameKind::Refusal, std::string{}} : frames.front();
}

template <std::size_t N>
std::array<uint8_t, N> patterned(uint8_t seed) {
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<uint8_t>(seed + i);
    }
    return out;
}

/// The key the daemon under test is pretending to hold.
const nexus::crypto::Ed25519PublicKey kSelfKey = patterned<32>(0x30);

/// A challenge this daemon would answer, so every negative below differs from it
/// in exactly one field.
AttestationChallenge good_challenge() {
    AttestationChallenge c;
    c.network_id = patterned<32>(0x01);
    c.nonce = patterned<32>(0x10);
    c.node_id.bytes = kSelfKey;
    c.node_key = kSelfKey;
    c.incarnation = 7;
    c.epoch = 42;
    c.security_ruleset = constants::kSecurityRulesetVersion;
    c.consensus_ruleset = constants::kConsensusRulesetVersion;
    c.profile_id = nexus::security::kTier1AttestationProfileId;
    c.profile_ruleset = nexus::security::kAttestationProfileRulesetVersion;
    c.policy_digest = patterned<32>(0x40);
    c.purpose = AttestationPurpose::Eligibility;
    c.context_digest = patterned<32>(0x50);
    return c;
}

/// The request form of the challenge above.
json good_request() {
    const auto c = good_challenge();
    json j;
    j["version"] = nexus::attestd::kAttestdWireVersion;
    j["type"] = std::string(nexus::attestd::kRequestType);
    j["network_id"] = nexus::crypto::to_hex(c.network_id);
    j["nonce"] = nexus::crypto::to_hex(c.nonce);
    j["node_id"] = nexus::crypto::to_hex(c.node_id.bytes);
    j["node_key"] = nexus::crypto::to_hex(c.node_key);
    j["incarnation"] = c.incarnation;
    j["epoch"] = c.epoch;
    j["security_ruleset"] = c.security_ruleset;
    j["consensus_ruleset"] = c.consensus_ruleset;
    j["profile_id"] = static_cast<uint16_t>(c.profile_id);
    j["profile_ruleset"] = c.profile_ruleset;
    j["policy_digest"] = nexus::crypto::to_hex(c.policy_digest);
    j["purpose"] = static_cast<uint16_t>(c.purpose);
    j["context_digest"] = nexus::crypto::to_hex(c.context_digest);
    return j;
}

}  // namespace

// ---------------------------------------------------------------------------
// The gate: what the daemon refuses before any hardware is touched
// ---------------------------------------------------------------------------

TEST(AttestdGate, AnswersAWellFormedChallenge) {
    EXPECT_EQ(check_challenge(good_challenge()), Refusal::None);
}

TEST(AttestdGate, RefusesEveryProfileButAzureSnpVtpm) {
    for (const auto id : {AttestationProfileId::Unknown, AttestationProfileId::SnpSvsmVtpm,
                          AttestationProfileId::SnpDirectBoot, AttestationProfileId::Tdx}) {
        auto c = good_challenge();
        c.profile_id = id;
        EXPECT_EQ(check_challenge(c), Refusal::ProfileNotSupported)
            << "profile " << static_cast<int>(id);
    }
}

TEST(AttestdGate, RefusesAnUnimplementedProfileRuleset) {
    auto c = good_challenge();
    c.profile_ruleset = nexus::security::kAttestationProfileRulesetVersion + 1;
    EXPECT_EQ(check_challenge(c), Refusal::ProfileRulesetMismatch);
}

TEST(AttestdGate, RefusesAnUnimplementedRuleset) {
    auto security_bump = good_challenge();
    security_bump.security_ruleset = constants::kSecurityRulesetVersion + 1;
    EXPECT_EQ(check_challenge(security_bump), Refusal::RulesetMismatch);

    auto consensus_bump = good_challenge();
    consensus_bump.consensus_ruleset = constants::kConsensusRulesetVersion + 1;
    EXPECT_EQ(check_challenge(consensus_bump), Refusal::RulesetMismatch);
}

TEST(AttestdGate, RefusesAnAllZeroNetwork) {
    auto c = good_challenge();
    c.network_id.fill(0);
    EXPECT_EQ(check_challenge(c), Refusal::NetworkUnbound);
}

TEST(AttestdGate, RefusesAnAllZeroNodeKey) {
    auto zero_key = good_challenge();
    zero_key.node_key.fill(0);
    EXPECT_EQ(check_challenge(zero_key), Refusal::NodeUnbound);

    auto zero_id = good_challenge();
    zero_id.node_id.bytes.fill(0);
    EXPECT_EQ(check_challenge(zero_id), Refusal::NodeUnbound);
}

TEST(AttestdGate, RefusesADefaultConstructedChallenge) {
    // The failure mode this exists to prevent: an empty struct that reached the
    // socket must never become a signed quote.
    EXPECT_NE(check_challenge(AttestationChallenge{}), Refusal::None);
}


TEST(AttestdGate, RefusesFinalReadinessWithNoContext) {
    auto c = good_challenge();
    c.purpose = AttestationPurpose::FinalEpochReadiness;
    c.context_digest.fill(0);
    EXPECT_EQ(check_challenge(c), Refusal::ContextUnbound);

    // The same purpose WITH a context is answerable.
    c.context_digest = patterned<32>(0x50);
    EXPECT_EQ(check_challenge(c), Refusal::None);
}

// ---------------------------------------------------------------------------
// The derived binding: the daemon chooses the quote nonce, never the caller
// ---------------------------------------------------------------------------

TEST(AttestdBinding, MatchesEvidenceBindingOverTheChallengeDigest) {
    const auto c = good_challenge();
    const std::vector<uint8_t> measurement = {0xaa, 0xbb, 0xcc, 0xdd};
    EXPECT_EQ(derive_quote_binding(c, measurement),
              evidence_binding(challenge_digest(c), c.node_key, measurement));
}

TEST(AttestdBinding, IsNeverTheRawChallengeNonce) {
    // The nonce inside a challenge is an input to challenge_digest(), not
    // qualifyingData. If these were ever equal, a caller could steer the quote
    // by choosing the nonce alone.
    const auto c = good_challenge();
    const std::vector<uint8_t> measurement = {0x01};
    const auto derived = derive_quote_binding(c, measurement);
    EXPECT_NE(derived, evidence_binding(c.nonce, c.node_key, measurement));

    std::array<uint8_t, nexus::security::kEvidenceBindingSize> raw{};
    std::copy(c.nonce.begin(), c.nonce.end(), raw.begin());
    EXPECT_NE(derived, raw);
}

TEST(AttestdBinding, ChangesWithEveryChallengeField) {
    const std::vector<uint8_t> measurement = {0x01, 0x02};
    const auto base = derive_quote_binding(good_challenge(), measurement);

    const std::pair<const char*, void (*)(AttestationChallenge&)> mutations[] = {
        {"network_id", [](AttestationChallenge& c) { c.network_id[0] ^= 1; }},
        {"nonce", [](AttestationChallenge& c) { c.nonce[0] ^= 1; }},
        {"node_key", [](AttestationChallenge& c) { c.node_key[0] ^= 1; }},
        {"incarnation", [](AttestationChallenge& c) { c.incarnation ^= 1; }},
        {"epoch", [](AttestationChallenge& c) { c.epoch ^= 1; }},
        {"policy_digest", [](AttestationChallenge& c) { c.policy_digest[0] ^= 1; }},
        {"context_digest", [](AttestationChallenge& c) { c.context_digest[0] ^= 1; }},
        {"purpose",
         [](AttestationChallenge& c) { c.purpose = AttestationPurpose::FinalEpochReadiness; }},
    };
    for (const auto& [name, apply] : mutations) {
        auto mutated = good_challenge();
        apply(mutated);
        EXPECT_NE(derive_quote_binding(mutated, measurement), base) << name;
    }
}

TEST(AttestdBinding, CoversTheBinaryMeasurement) {
    const auto c = good_challenge();
    const std::vector<uint8_t> one = {0x01};
    const std::vector<uint8_t> two = {0x02};
    EXPECT_NE(derive_quote_binding(c, one), derive_quote_binding(c, two));
    EXPECT_NE(derive_quote_binding(c, one), derive_quote_binding(c, {}));
}

// ---------------------------------------------------------------------------
// Echoed fields
// ---------------------------------------------------------------------------





// ---------------------------------------------------------------------------
// The closed request grammar
// ---------------------------------------------------------------------------

TEST(AttestdCodec, RoundTripsAChallenge) {
    const auto decoded = decode_challenge(good_request().dump());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(challenge_digest(*decoded), challenge_digest(good_challenge()));
    EXPECT_EQ(decoded->node_key, kSelfKey);
    EXPECT_EQ(decoded->epoch, 42u);
}

TEST(AttestdCodec, RefusesAnyFieldThatWouldSteerTheQuote) {
    // The point of the closed grammar: there is no request field for raw
    // qualifyingData, a PCR selection, a message to sign, or SNP report data —
    // and adding one is a refusal, not something quietly ignored.
    for (const char* smuggled : {"qualifying_data", "qualifyingData", "report_data", "binding",
                                 "extra_data", "pcr_selection", "sign", "message", "raw_nonce"}) {
        auto request = good_request();
        request[smuggled] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        EXPECT_FALSE(decode_challenge(request.dump()).has_value()) << smuggled;
    }
}

TEST(AttestdCodec, RefusesAMissingField) {
    for (const char* field : {"network_id", "nonce", "node_id", "node_key", "incarnation", "epoch",
                              "security_ruleset", "consensus_ruleset", "profile_id",
                              "profile_ruleset", "policy_digest", "purpose", "context_digest"}) {
        auto request = good_request();
        request.erase(field);
        EXPECT_FALSE(decode_challenge(request.dump()).has_value()) << field;
    }
}

TEST(AttestdCodec, RefusesAWrongWidthOrWrongTypeField) {
    auto short_hex = good_request();
    short_hex["node_key"] = "aabb";
    EXPECT_FALSE(decode_challenge(short_hex.dump()).has_value());

    auto long_hex = good_request();
    long_hex["network_id"] = std::string(66, 'a');
    EXPECT_FALSE(decode_challenge(long_hex.dump()).has_value());

    auto not_hex = good_request();
    not_hex["policy_digest"] = std::string(64, 'z');
    EXPECT_FALSE(decode_challenge(not_hex.dump()).has_value());

    auto wrong_type = good_request();
    wrong_type["epoch"] = "42";
    EXPECT_FALSE(decode_challenge(wrong_type.dump()).has_value());

    auto negative = good_request();
    negative["incarnation"] = -1;
    EXPECT_FALSE(decode_challenge(negative.dump()).has_value());

    auto overflow = good_request();
    overflow["security_ruleset"] = 70000;
    EXPECT_FALSE(decode_challenge(overflow.dump()).has_value());
}

TEST(AttestdCodec, RefusesAnUnknownPurpose) {
    for (const int purpose : {0, 3, 65535}) {
        auto request = good_request();
        request["purpose"] = purpose;
        EXPECT_FALSE(decode_challenge(request.dump()).has_value()) << purpose;
    }
}

TEST(AttestdCodec, RefusesTheWrongEnvelope) {
    auto version = good_request();
    version["version"] = nexus::attestd::kAttestdWireVersion + 1;
    EXPECT_FALSE(decode_challenge(version.dump()).has_value());

    auto type = good_request();
    type["type"] = "attestation_evidence";
    EXPECT_FALSE(decode_challenge(type.dump()).has_value());

    EXPECT_FALSE(decode_challenge("").has_value());
    EXPECT_FALSE(decode_challenge("not json").has_value());
    EXPECT_FALSE(decode_challenge("[]").has_value());
    EXPECT_FALSE(decode_challenge("{}").has_value());
}

TEST(AttestdCodec, RefusesAnOversizedRequest) {
    auto request = good_request();
    request["type"] = std::string(nexus::attestd::kMaxRequestBytes, 'x');
    EXPECT_FALSE(decode_challenge(request.dump()).has_value());
}

TEST(AttestdCodec, RefusesAnUnknownProfileIdWithoutInventingOne) {
    auto request = good_request();
    request["profile_id"] = 9999;
    const auto decoded = decode_challenge(request.dump());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->profile_id, AttestationProfileId::Unknown);
    EXPECT_EQ(check_challenge(*decoded), Refusal::ProfileNotSupported);
}


// ---------------------------------------------------------------------------
// The service: the wire path always answers, and always answers typed
// ---------------------------------------------------------------------------

namespace {

/// A service holding a real keypair, so the gate's identity check is exercised
/// against something a signature could actually be produced with.
class AttestdServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_EQ(crypto_sign_keypair(identity_.public_key.data(), identity_.private_key.data()),
                  0);
        // Unique per process AND per test: ctest runs each test as its own
        // process, and gtest's random_seed is the same in all of them, so a
        // seed-named directory has one process removing what another is using.
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        temp_dir_ = fs::temp_directory_path() /
                    ("nexus_test_attestd_" + std::to_string(::getpid()) + "_" +
                     (info ? info->name() : "unknown"));
        fs::remove_all(temp_dir_);
        fs::create_directories(temp_dir_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(temp_dir_, ec);
    }

    [[nodiscard]] AttestdConfig config() const {
        AttestdConfig cfg;
        cfg.cache_dir = temp_dir_;
        cfg.allow_network = false;
        return cfg;
    }

    /// good_challenge(), readdressed to the generated identity.
    [[nodiscard]] AttestationChallenge mine() const {
        auto c = good_challenge();
        c.node_id.bytes = identity_.public_key;
        c.node_key = identity_.public_key;
        return c;
    }

    nexus::crypto::Ed25519Keypair identity_{};
    fs::path temp_dir_;
};

}  // namespace

TEST_F(AttestdServiceTest, RefusesBeforeConsultingThePlatform) {
    AttestdService service{config()};
    PlatformEvidenceBundle bundle;
    std::string detail;

    // Every one of these must be decided by the gate, so the answer is the same
    // on a laptop and on a TPM host — nothing reaches the hardware.
    auto zero_network = mine();
    zero_network.network_id.fill(0);
    EXPECT_EQ(service.answer(zero_network, bundle, &detail), Refusal::NetworkUnbound);

    auto wrong_profile = mine();
    wrong_profile.profile_id = AttestationProfileId::SnpDirectBoot;
    EXPECT_EQ(service.answer(wrong_profile, bundle, &detail), Refusal::ProfileNotSupported);

    // node_id and node_key must agree; WHICH identity it is does not matter,
    // because the daemon holds no key and signs nothing.
    auto split = mine();
    split.node_key = patterned<32>(0x99);
    EXPECT_EQ(service.answer(split, bundle, &detail), Refusal::NodeUnbound);
}



TEST_F(AttestdServiceTest, TheWirePathAlwaysAnswersTyped) {
    AttestdService service{config()};

    for (const char* garbage : {"", "{", "[]", "null", "{\"type\":\"whatever\"}"}) {
        const auto document = json::parse(one_frame(service, garbage).second, nullptr, false);
        ASSERT_FALSE(document.is_discarded()) << garbage;
        EXPECT_EQ(document["type"], std::string(nexus::attestd::kRefusalType)) << garbage;
        EXPECT_EQ(document["refusal"], "malformed_request") << garbage;
    }

    // A well-formed request gets a typed answer about the PLATFORM, never
    // about identity: the daemon holds no key and has no opinion on whose
    // challenge this is.
    const auto document = json::parse(one_frame(service, good_request().dump()).second);
    EXPECT_EQ(document["type"], std::string(nexus::attestd::kRefusalType));
    EXPECT_EQ(document["refusal"], "platform_unavailable");
}

// ---------------------------------------------------------------------------
// The boundary: no identity, no signature
// ---------------------------------------------------------------------------

// The property this whole component split exists for. AttestdConfig carries no
// key material, so there is nothing for the privileged process to leak and
// nothing it could sign a Nexus protocol object with.
TEST_F(AttestdServiceTest, HoldsNoIdentityAndSignsNothing) {
    AttestdService service{config()};
    const std::string response = collect_frames(service, good_request().dump());
    // Whatever the platform answers, the reply is a bundle or a refusal — never
    // a signed AttestationEvidence.
    EXPECT_EQ(response.find("identity_signature"), std::string::npos);
    EXPECT_EQ(response.find("epoch_vote_key"), std::string::npos);
}

// ---------------------------------------------------------------------------
// The local framed stream, and the bounds that keep it bounded
// ---------------------------------------------------------------------------

namespace {

using nexus::attestd::FrameError;
using nexus::attestd::ResponseAssembler;
using nexus::attestd::encode_frame;
using nexus::attestd::kMaxLocalChunks;
using nexus::attestd::kMaxLocalFrameBytes;
using nexus::attestd::read_framed_response;

/// A bundle whose evidence is `log_bytes` of measurement log, so the size of
/// the local response can be steered without a TPM.
PlatformEvidenceBundle bundle_with_log(std::size_t log_bytes) {
    PlatformEvidenceBundle b;
    b.challenge_digest = patterned<32>(0x77);
    b.platform.ima_log.assign(log_bytes, 'x');
    b.platform.hcl_blob.assign(64, 0x5A);
    b.platform.tpms_attest.assign(64, 0x5B);
    return b;
}

std::string frames_for(const PlatformEvidenceBundle& b, bool* emitted = nullptr) {
    std::string wire;
    const bool ok = nexus::attestd::emit_bundle(b, [&](std::string_view f) {
        wire.append(f);
        return true;
    });
    if (emitted) *emitted = ok;
    return wire;
}

/// Feed raw bytes to the reader over a socketpair. `close_write` models a daemon
/// that hung up; leaving it open models one that stalled. The write runs on its
/// own thread because a response larger than the socket buffer would otherwise
/// block before the reader ever started.
FrameError read_bytes(std::string_view wire, bool close_write, int deadline_seconds,
                      PlatformEvidenceBundle* out = nullptr) {
    int fds[2] = {-1, -1};
    EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    const std::string payload{wire};
    std::thread writer([fd = fds[1], payload, close_write] {
        std::size_t sent = 0;
        while (sent < payload.size()) {
            const ssize_t n = ::write(fd, payload.data() + sent, payload.size() - sent);
            if (n <= 0) break;
            sent += static_cast<std::size_t>(n);
        }
        if (close_write) ::close(fd);
    });

    PlatformEvidenceBundle sink;
    const auto result = read_framed_response(fds[0], deadline_seconds, out ? *out : sink);
    ::close(fds[0]);
    writer.join();
    if (!close_write) ::close(fds[1]);
    return result.ok ? FrameError::None : result.transport;
}

}  // namespace

TEST(AttestdFraming, ALocalResponseMayExceedTheMeshWireBound) {
    // The layering D3 fixes. 56 KiB is what a PEER will accept; it is not a
    // limit on what the local daemon may hand its own Nexus process.
    const auto bundle = bundle_with_log(100 * 1024);
    const auto encoded = nexus::security::encode_snp_vtpm_evidence(bundle.platform);
    ASSERT_GT(encoded.size(), constants::kMaxPlatformEvidenceWireBytes);

    bool emitted = false;
    const std::string wire = frames_for(bundle, &emitted);
    ASSERT_TRUE(emitted);

    PlatformEvidenceBundle got;
    EXPECT_EQ(read_bytes(wire, /*close_write=*/true, 5, &got), FrameError::None);
    EXPECT_EQ(got.challenge_digest, bundle.challenge_digest);
    EXPECT_EQ(got.platform.ima_log, bundle.platform.ima_log);
}

TEST(AttestdFraming, AFrameOverTheSizeBoundIsRefusedBeforeItsBodyIsRead) {
    // Only the 5-byte header is written, and the write side stays OPEN. A reader
    // that reserved or read the declared body would block to the deadline; the
    // bound has to be checked first, so this returns immediately.
    std::string header(5, '\0');
    const uint32_t huge = static_cast<uint32_t>(kMaxLocalFrameBytes + 1);
    header[0] = static_cast<char>((huge >> 24) & 0xFF);
    header[1] = static_cast<char>((huge >> 16) & 0xFF);
    header[2] = static_cast<char>((huge >> 8) & 0xFF);
    header[3] = static_cast<char>(huge & 0xFF);
    header[4] = static_cast<char>(nexus::attestd::FrameKind::Header);

    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(read_bytes(header, /*close_write=*/false, 10), FrameError::Oversized);
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(5));
}

TEST(AttestdFraming, MoreChunksThanTheBudgetAreRefused) {
    ResponseAssembler assembler;
    json head;
    head["version"] = nexus::attestd::kAttestdWireVersion;
    head["type"] = std::string(nexus::attestd::kBundleType);
    head["challenge_digest"] = nexus::crypto::to_hex(patterned<32>(0x01));
    head["platform_bytes"] = kMaxLocalFrameBytes * kMaxLocalChunks;
    ASSERT_TRUE(assembler.offer(nexus::attestd::FrameKind::Header, head.dump()));

    for (std::size_t i = 0; i < kMaxLocalChunks; ++i) {
        ASSERT_TRUE(assembler.offer(nexus::attestd::FrameKind::EvidenceChunk, "x")) << i;
    }
    EXPECT_FALSE(assembler.offer(nexus::attestd::FrameKind::EvidenceChunk, "x"));
    EXPECT_EQ(assembler.error(), FrameError::TooManyChunks);
    EXPECT_FALSE(assembler.done());
}

TEST(AttestdFraming, AStalledStreamExpiresRatherThanWaiting) {
    // Half a frame, write side left open: the deadline is the only thing that
    // ends this, and it must.
    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(read_bytes(std::string(3, '\0'), /*close_write=*/false, 1), FrameError::Truncated);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_GE(elapsed, std::chrono::milliseconds(900));
    EXPECT_LT(elapsed, std::chrono::seconds(10));
}

TEST(AttestdFraming, MalformedFramesAreRefused) {
    // An unknown kind.
    EXPECT_EQ(read_bytes(encode_frame(static_cast<nexus::attestd::FrameKind>(99), "{}"), true, 5),
              FrameError::Malformed);

    // A chunk before any header: the grammar is a state machine, not a bag.
    EXPECT_EQ(read_bytes(encode_frame(nexus::attestd::FrameKind::EvidenceChunk, "x"), true, 5),
              FrameError::Malformed);

    // An End with nothing to end.
    EXPECT_EQ(read_bytes(encode_frame(nexus::attestd::FrameKind::End, "{\"chunks\":0}"), true, 5),
              FrameError::Malformed);

    // A header that is not JSON, and one missing its length.
    EXPECT_EQ(read_bytes(encode_frame(nexus::attestd::FrameKind::Header, "not json"), true, 5),
              FrameError::Malformed);
    EXPECT_EQ(read_bytes(encode_frame(nexus::attestd::FrameKind::Header, "{\"version\":1}"), true, 5),
              FrameError::Malformed);
}

TEST(AttestdFraming, AHeaderDeclaringMoreThanTheBudgetIsRefused) {
    json head;
    head["version"] = nexus::attestd::kAttestdWireVersion;
    head["type"] = std::string(nexus::attestd::kBundleType);
    head["challenge_digest"] = nexus::crypto::to_hex(patterned<32>(0x01));
    head["platform_bytes"] = kMaxLocalFrameBytes * kMaxLocalChunks + 1;

    ResponseAssembler assembler;
    EXPECT_FALSE(assembler.offer(nexus::attestd::FrameKind::Header, head.dump()));
    EXPECT_EQ(assembler.error(), FrameError::TooLarge);
}

TEST(AttestdFraming, ReassembledBytesMustMatchWhatTheEndFrameCommittedTo) {
    const auto bundle = bundle_with_log(1024);
    std::string wire = frames_for(bundle);

    // Flip a byte inside the evidence. The length still adds up, so only the
    // committed digest catches it.
    const auto at = wire.find("xxxx");
    ASSERT_NE(at, std::string::npos);
    wire[at] = 'y';

    EXPECT_EQ(read_bytes(wire, true, 5), FrameError::Malformed);
}

TEST(AttestdFraming, ATruncatedStreamNeverYieldsABundle) {
    const auto bundle = bundle_with_log(1024);
    const std::string wire = frames_for(bundle);
    // Everything but the End frame, then hang up.
    EXPECT_EQ(read_bytes(wire.substr(0, wire.size() - 8), true, 5), FrameError::Truncated);
}

TEST(AttestdFraming, ARefusalTerminatesTheStreamAndCarriesNoBundle) {
    std::string wire;
    ASSERT_TRUE(nexus::attestd::emit_refusal(Refusal::PlatformUnavailable,
                                             [&](std::string_view f) {
                                                 wire.append(f);
                                                 return true;
                                             },
                                             "no TPM here"));
    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    ASSERT_EQ(::write(fds[1], wire.data(), wire.size()), static_cast<ssize_t>(wire.size()));
    ::close(fds[1]);

    PlatformEvidenceBundle out;
    const auto result = read_framed_response(fds[0], 5, out);
    ::close(fds[0]);

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.refusal, Refusal::PlatformUnavailable);
    EXPECT_EQ(result.transport, FrameError::None);
    EXPECT_EQ(result.detail, "no TPM here");
    EXPECT_TRUE(out.platform.empty());
}

TEST(AttestdFraming, TheRequestSurfaceIsStillOneChallengeAndNothingElse) {
    // The client can only ever ask one thing, and the bytes it sends are the
    // closed grammar the daemon parses — no path, no offset, no nonce, no PCR
    // selection, no bytes to sign.
    const auto request = nexus::attestd::encode_challenge_request(good_challenge());
    const auto parsed = json::parse(request);
    EXPECT_EQ(parsed.size(), 15u);
    for (const char* forbidden : {"qualifying_data", "pcr_selection", "path", "offset",
                                  "sign", "report_data", "length"}) {
        EXPECT_FALSE(parsed.contains(forbidden)) << forbidden;
    }
    // And it round-trips into exactly the challenge that was asked for.
    auto back = decode_challenge(std::string_view(request).substr(0, request.size() - 1));
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(challenge_digest(*back), challenge_digest(good_challenge()));
}

// ---------------------------------------------------------------------------
// The privilege boundary, restated as a test
// ---------------------------------------------------------------------------

// AttestdConfig is the daemon's entire configurable surface. If key material
// could reach the daemon at all, it would reach it through here — so the
// absence is asserted on the type, not on a code path that might be missed.
TEST(AttestdBoundary, NothingInTheDaemonConfigCanCarryKeyMaterial) {
    // Structured binding, so a new field breaks the BUILD rather than slipping
    // past a runtime check. Both members are named here; neither can hold a key.
    AttestdConfig config;
    auto& [cache_dir, allow_network] = config;
    cache_dir = "/var/lib/nexus-attestd/cache";
    allow_network = false;

    static_assert(std::is_same_v<decltype(cache_dir), std::filesystem::path>);
    static_assert(std::is_same_v<decltype(allow_network), bool>);
    EXPECT_EQ(config.cache_dir, "/var/lib/nexus-attestd/cache");
}

TEST(AttestdBoundary, NoResponseEverCarriesAuthority) {
    // Every response the daemon can produce, checked for the field names that
    // would mean it had signed or voted.
    AttestdConfig config;
    config.cache_dir = ::testing::TempDir();
    AttestdService service{config};

    std::vector<std::string> responses;
    responses.push_back(collect_frames(service, "{"));                     // malformed
    responses.push_back(collect_frames(service, good_request().dump()));   // gated
    {
        auto other_network = good_request();
        other_network["network_id"] = std::string(64, '0');
        responses.push_back(collect_frames(service, other_network.dump()));
    }

    for (const auto& response : responses) {
        for (const char* forbidden : {"identity_signature", "epoch_vote_key", "private",
                                      "frost", "share", "secret", "signature"}) {
            EXPECT_EQ(response.find(forbidden), std::string::npos)
                << forbidden << " appeared in a daemon response";
        }
    }
}

TEST(AttestdBoundary, TheRequestGrammarAdmitsNoQuoteSteering) {
    // A caller may not choose the quoted PCRs, the REPORT_DATA, the nonce, or
    // any path the daemon reads. Each of these is a well-formed request with
    // exactly one extra key, and each must be refused outright.
    AttestdConfig config;
    config.cache_dir = ::testing::TempDir();
    AttestdService service{config};

    for (const char* key : {"qualifying_data", "pcr_selection", "report_data", "hcl_blob_override",
                            "sign", "path", "offset", "ima_log_path"}) {
        auto request = good_request();
        request[key] = "whatever";
        const auto document = json::parse(one_frame(service, request.dump()).second);
        EXPECT_EQ(document["refusal"], "malformed_request") << key;
    }
}

// ---------------------------------------------------------------------------
// Hostile framing: the assembler under a peer that lies
// ---------------------------------------------------------------------------

namespace {

json good_header(std::size_t platform_bytes) {
    json head;
    head["version"] = nexus::attestd::kAttestdWireVersion;
    head["type"] = std::string(nexus::attestd::kBundleType);
    head["challenge_digest"] = nexus::crypto::to_hex(patterned<32>(0x01));
    head["platform_bytes"] = platform_bytes;
    return head;
}

}  // namespace

TEST(AttestdFramingHostile, ZeroLengthChunksStillCountAgainstTheChunkBudget) {
    ResponseAssembler assembler;
    ASSERT_TRUE(assembler.offer(FrameKind::Header, good_header(1).dump()));
    for (std::size_t i = 0; i < kMaxLocalChunks; ++i) {
        ASSERT_TRUE(assembler.offer(FrameKind::EvidenceChunk, "")) << i;
    }
    EXPECT_FALSE(assembler.offer(FrameKind::EvidenceChunk, ""));
    EXPECT_EQ(assembler.error(), FrameError::TooManyChunks);
}

TEST(AttestdFramingHostile, ADuplicateHeaderIsRefused) {
    ResponseAssembler assembler;
    ASSERT_TRUE(assembler.offer(FrameKind::Header, good_header(4).dump()));
    EXPECT_FALSE(assembler.offer(FrameKind::Header, good_header(4).dump()));
    EXPECT_EQ(assembler.error(), FrameError::Malformed);
}

TEST(AttestdFramingHostile, NothingIsAcceptedAfterTheStreamEnds) {
    // End closes the stream; a second End, a late chunk, and a late refusal are
    // all refused rather than mutating a completed response.
    const auto ended = [] {
        ResponseAssembler a;
        EXPECT_TRUE(a.offer(FrameKind::Header, good_header(0).dump()));
        json end;
        end["chunks"] = 0;
        end["platform_sha256"] = std::string(64, '0');
        EXPECT_FALSE(a.offer(FrameKind::End, end.dump()));
        EXPECT_TRUE(a.done());
        return a;
    };
    for (const auto kind : {FrameKind::End, FrameKind::EvidenceChunk, FrameKind::Refusal,
                            FrameKind::Header}) {
        auto a = ended();
        EXPECT_FALSE(a.offer(kind, "{}")) << static_cast<int>(kind);
    }
}

TEST(AttestdFramingHostile, ARefusalAfterAHeaderIsRefused) {
    ResponseAssembler assembler;
    ASSERT_TRUE(assembler.offer(FrameKind::Header, good_header(4).dump()));
    EXPECT_FALSE(assembler.offer(FrameKind::Refusal, "{\"code\":8}"));
    EXPECT_EQ(assembler.error(), FrameError::Malformed);
    EXPECT_EQ(assembler.refusal(), Refusal::None);  // not mistaken for a real refusal
}

TEST(AttestdFramingHostile, AMaximumSizedFrameIsStillAccepted) {
    // The bound is exact: kMaxLocalFrameBytes passes, one more is refused.
    ResponseAssembler assembler;
    ASSERT_TRUE(assembler.offer(FrameKind::Header, good_header(kMaxLocalFrameBytes).dump()));
    EXPECT_TRUE(assembler.offer(FrameKind::EvidenceChunk,
                                std::string(kMaxLocalFrameBytes, 'x')));
    ResponseAssembler over;
    ASSERT_TRUE(over.offer(FrameKind::Header, good_header(kMaxLocalFrameBytes).dump()));
    EXPECT_FALSE(over.offer(FrameKind::EvidenceChunk,
                            std::string(kMaxLocalFrameBytes + 1, 'x')));
    EXPECT_EQ(over.error(), FrameError::Oversized);
}

TEST(AttestdFramingHostile, AWrappingLengthPrefixIsRefusedBeforeAllocation) {
    // 0xFFFFFFFF declared: the reader must refuse on the declared value alone.
    std::string header(5, '\xFF');
    header[4] = static_cast<char>(FrameKind::Header);
    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(read_bytes(header, /*close_write=*/false, 10), FrameError::Oversized);
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(5));
}

TEST(AttestdFramingHostile, ATruncatedLengthPrefixFailsClosed) {
    EXPECT_EQ(read_bytes(std::string(3, '\0'), /*close_write=*/true, 5), FrameError::Truncated);
    EXPECT_EQ(read_bytes("", /*close_write=*/true, 5), FrameError::Truncated);
}

TEST(AttestdFramingHostile, TrailingBytesAfterEndCannotAlterTheResult) {
    const auto bundle = bundle_with_log(512);
    std::string wire = frames_for(bundle);
    wire += std::string(4096, 'Z');  // never read: the reader stops at End

    PlatformEvidenceBundle got;
    EXPECT_EQ(read_bytes(wire, /*close_write=*/true, 5, &got), FrameError::None);
    EXPECT_EQ(got.platform.ima_log, bundle.platform.ima_log);
}

TEST(AttestdFramingHostile, TheServerRefusesToEmitABundleOverItsOwnBudget) {
    // The emitter's bound mirrors the reader's: a bundle needing more than
    // kMaxLocalChunks emits NOTHING, not a stream the reader must abort.
    const auto oversized = bundle_with_log(kMaxLocalFrameBytes * kMaxLocalChunks + 1);
    std::string wire;
    EXPECT_FALSE(nexus::attestd::emit_bundle(oversized, [&](std::string_view f) {
        wire.append(f);
        return true;
    }));
    EXPECT_TRUE(wire.empty());
}

// ---------------------------------------------------------------------------
// Hostile grammar: JSON shapes the closed grammar must refuse
// ---------------------------------------------------------------------------

namespace {
AttestdConfig grammar_config() {
    AttestdConfig cfg;
    cfg.cache_dir = ::testing::TempDir();
    cfg.allow_network = false;
    return cfg;
}
}  // namespace

TEST(AttestdGrammarHostile, WrongJsonShapesAreRefusedTyped) {
    AttestdService service{grammar_config()};

    const auto refuse = [&](const std::string& request, const char* what) {
        const auto frame = one_frame(service, request);
        const auto document = json::parse(frame.second, nullptr, false);
        ASSERT_FALSE(document.is_discarded()) << what;
        EXPECT_EQ(document["refusal"], "malformed_request") << what;
    };

    auto with = [&](const char* key, json value) {
        auto r = good_request();
        r[key] = std::move(value);
        return r.dump();
    };

    refuse(with("nonce", nullptr), "null value");
    refuse(with("epoch", -1), "negative integer");
    refuse(with("epoch", 1.5), "fraction");
    refuse(with("epoch", json::array({1})), "array for scalar");
    refuse(with("nonce", json::object({{"hex", "00"}})), "nested object");
    refuse(with("purpose", 65536), "oversized purpose");
    refuse(with("incarnation", json::parse("18446744073709551616")), "over-u64 integer");
    refuse("{}", "empty object");
    refuse(good_request().dump() + good_request().dump(), "second JSON object");
    refuse(good_request().dump() + " x", "trailing data");
    refuse(std::string(9 * 1024, ' ') + good_request().dump(), "over the request byte cap");

    // Deep nesting parses or fails, but never crashes and never authorizes.
    std::string deep(2000, '[');
    deep += std::string(2000, ']');
    refuse(deep, "deep nesting");
}

TEST(AttestdGrammarHostile, ADuplicateKeyCannotSmuggleASecondValue) {
    // nlohmann keeps the LAST duplicate, before the closed-grammar scan runs.
    // Whatever survives parsing is what the daemon hashes into the challenge
    // digest, so a duplicate steers nothing — the quote binds the value the
    // daemon actually used, and the caller sees which one that was.
    auto base = good_request();
    std::string request = base.dump();
    const std::string honest = "\"epoch\":" + base["epoch"].dump();
    const auto at = request.find(honest);
    ASSERT_NE(at, std::string::npos);
    request.insert(at, "\"epoch\":999,");

    const auto decoded = decode_challenge(request);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->epoch, base["epoch"].get<uint64_t>());
}
