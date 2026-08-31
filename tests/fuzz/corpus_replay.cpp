// The fuzz targets, driven by a deterministic corpus.
//
// This runs in the normal suite so the harnesses stay compiled and exercised on
// every build. It is not a substitute for a real fuzzing run: it proves the
// targets survive a fixed spread of shapes, not that no input crashes them.
//
// The corpus is generated from a fixed seed, so a failure here reproduces
// exactly. Under libFuzzer the same targets take generated input instead.

#include "fuzz/fuzz_targets.hpp"

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace constants = nexus::security::constants;

namespace {

/// xorshift64*, so the corpus is identical on every platform and every run.
class Rng {
public:
    explicit Rng(uint64_t seed) : state_(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    uint64_t next() {
        state_ ^= state_ >> 12;
        state_ ^= state_ << 25;
        state_ ^= state_ >> 27;
        return state_ * 0x2545F4914F6CDD1Dull;
    }
    uint8_t byte() { return static_cast<uint8_t>(next() >> 24); }
    std::size_t below(std::size_t bound) {
        return bound == 0 ? 0 : static_cast<std::size_t>(next() % bound);
    }

private:
    uint64_t state_;
};

/// Shapes worth feeding every parser: nothing, one byte, a run of zeros, a run
/// of 0xFF (every length field maximal), and text.
std::vector<std::vector<uint8_t>> structural_corpus() {
    std::vector<std::vector<uint8_t>> corpus;
    corpus.emplace_back();
    corpus.push_back({0x00});
    corpus.push_back({0xFF});
    corpus.emplace_back(64, 0x00);
    corpus.emplace_back(64, 0xFF);
    corpus.emplace_back(4096, 0xFF);
    const std::string text = "10 aa ima-ng sha256:bb /opt/nexus\n{\"a\":1}\n";
    corpus.emplace_back(text.begin(), text.end());
    const std::string pem = "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n";
    corpus.emplace_back(pem.begin(), pem.end());
    return corpus;
}

/// Random inputs across the length range each parser bounds.
std::vector<std::vector<uint8_t>> random_corpus(Rng& rng, std::size_t count) {
    std::vector<std::vector<uint8_t>> corpus;
    corpus.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> input(rng.below(2048));
        for (auto& byte : input) byte = rng.byte();
        corpus.push_back(std::move(input));
    }
    return corpus;
}

/// Bit-flips and truncations of one valid envelope. A corrupted-but-plausible
/// message is the input most likely to reach deep parser state.
void mutate_into(std::vector<std::vector<uint8_t>>& corpus,
                 const std::vector<uint8_t>& encoded, Rng& rng) {
    if (encoded.empty()) {
        return;
    }
    corpus.push_back(encoded);
    for (int i = 0; i < 64; ++i) {
        auto mutated = encoded;
        mutated[rng.below(mutated.size())] ^= static_cast<uint8_t>(1u << rng.below(8));
        corpus.push_back(std::move(mutated));
    }
    for (std::size_t cut = 1; cut < encoded.size(); cut += 7) {
        corpus.emplace_back(encoded.begin(), encoded.begin() + static_cast<std::ptrdiff_t>(cut));
    }
}

/// One genuinely signed observation and one signed participation answer, so the
/// mutations reach past the structural gates into the signature checks and the
/// counting behind them.
std::vector<std::vector<uint8_t>> eligibility_corpus(Rng& rng) {
    std::vector<std::vector<uint8_t>> corpus;
    const auto& context = nexus_fuzz::fuzz_fact_context();

    nexus::security::EligibilityObservation observation;
    observation.network_id = context.network_id;
    observation.epoch = context.epoch;
    observation.subject.bytes.fill(0x02);
    observation.subject_incarnation = 1;
    observation.kind = nexus::security::ObservationKind::Attestation;
    observation.attestation_digest.fill(0xA1);
    observation.claims.profile_id = nexus::security::kTier1AttestationProfileId;
    observation.claims.profile_ruleset = nexus::security::kAttestationProfileRulesetVersion;
    observation.claims.hardware_confidentiality_valid = true;
    observation.claims.tcb_valid = true;
    observation.height = 42;
    observation.state_reference.fill(0xC0);
    observation = sign_observation(observation, nexus_fuzz::fuzz_observer_key());

    nexus::security::SecurityMessage envelope;
    envelope.kind = nexus::security::SecurityMessageKind::EligibilityObservation;
    envelope.security_ruleset = constants::kSecurityRulesetVersion;
    envelope.consensus_ruleset = constants::kConsensusRulesetVersion;
    envelope.network_id = context.network_id;
    envelope.epoch = context.epoch;
    envelope.sender = observation.observer;
    envelope.body = observation;
    mutate_into(corpus, nexus::security::encode_security_message(envelope), rng);

    const auto answer = nexus::security::answer_participation_challenge(
        nexus_fuzz::fuzz_participation_challenge(), nexus_fuzz::fuzz_observer_key());
    nexus::security::SecurityMessage reply;
    reply.kind = nexus::security::SecurityMessageKind::ParticipationResponse;
    reply.security_ruleset = constants::kSecurityRulesetVersion;
    reply.consensus_ruleset = constants::kConsensusRulesetVersion;
    reply.network_id = context.network_id;
    reply.epoch = context.epoch;
    reply.sender = answer.node_id;
    reply.body = answer;
    mutate_into(corpus, nexus::security::encode_security_message(reply), rng);

    nexus::security::SecurityMessage ask;
    ask.kind = nexus::security::SecurityMessageKind::ParticipationChallenge;
    ask.security_ruleset = constants::kSecurityRulesetVersion;
    ask.consensus_ruleset = constants::kConsensusRulesetVersion;
    ask.network_id = context.network_id;
    ask.epoch = context.epoch;
    ask.sender = nexus_fuzz::fuzz_participation_challenge().observer;
    ask.body = nexus_fuzz::fuzz_participation_challenge();
    mutate_into(corpus, nexus::security::encode_security_message(ask), rng);
    return corpus;
}

/// A valid message with one byte corrupted is the input most likely to reach
/// deep parser state, so the corpus carries those too.
std::vector<std::vector<uint8_t>> near_miss_corpus(Rng& rng) {
    std::vector<std::vector<uint8_t>> corpus;
    nexus::security::AttestationChallenge challenge;
    challenge.network_id.fill(0xA0);
    challenge.nonce.fill(0x11);
    challenge.node_id.bytes.fill(0x22);
    challenge.node_key.fill(0x33);
    challenge.incarnation = 4;
    challenge.epoch = 12;
    challenge.security_ruleset = constants::kSecurityRulesetVersion;
    challenge.consensus_ruleset = constants::kConsensusRulesetVersion;
    challenge.profile_id = nexus::security::AttestationProfileId::AzureSnpVtpm;
    challenge.profile_ruleset = nexus::security::kAttestationProfileRulesetVersion;
    challenge.policy_digest.fill(0x44);

    nexus::security::SecurityMessage message;
    message.kind = nexus::security::SecurityMessageKind::AttestationChallenge;
    message.security_ruleset = constants::kSecurityRulesetVersion;
    message.consensus_ruleset = constants::kConsensusRulesetVersion;
    message.network_id = challenge.network_id;
    message.epoch = challenge.epoch;
    message.sender.bytes.fill(0x55);
    message.body = challenge;

    mutate_into(corpus, nexus::security::encode_security_message(message), rng);
    return corpus;
}

}  // namespace

// Each target must return on every input. A crash, a hang or a sanitizer report
// fails the test; there is nothing else to assert, because a parser's whole job
// on hostile input is to decline it without incident.
TEST(FuzzCorpus, EveryTargetSurvivesTheCorpus) {
    ASSERT_GE(sodium_init(), 0);
    Rng rng{0xC0FFEE};

    std::vector<std::vector<uint8_t>> corpus = structural_corpus();
    for (auto& input : random_corpus(rng, 256)) corpus.push_back(std::move(input));
    for (auto& input : near_miss_corpus(rng)) corpus.push_back(std::move(input));
    for (auto& input : eligibility_corpus(rng)) corpus.push_back(std::move(input));

    for (const auto& target : nexus_fuzz::kTargets) {
        for (const auto& input : corpus) {
            target.run(input);
        }
        SUCCEED() << target.name << " survived " << corpus.size() << " inputs";
    }
}

// The envelope bound is applied before anything is allocated from a length the
// input chose. A message claiming more than the compiled maximum is refused on
// its header, so an attacker cannot make a node reserve memory by asking.
TEST(FuzzCorpus, OversizedInputIsRefusedWithoutAllocating) {
    std::vector<uint8_t> oversized(constants::kMaxSecurityMessageBytes + 1,
                                   0xFF);
    const auto decoded = nexus::security::decode_security_message(oversized);
    ASSERT_TRUE(std::holds_alternative<nexus::security::CodecError>(decoded));

    // And every length field inside a well-sized message is bounded too: a
    // header full of 0xFF decodes to an error, never to a huge reservation.
    std::vector<uint8_t> maximal(256, 0xFF);
    const auto second = nexus::security::decode_security_message(maximal);
    EXPECT_TRUE(std::holds_alternative<nexus::security::CodecError>(second));
}
