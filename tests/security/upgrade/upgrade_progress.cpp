// The upgrade-turn record rules (Design-Auto-Update Phase 5), without a mesh:
// the deterministic order, the record codec, the turn rule, the witness
// quorum, the halt, and the local gate.

#include <LemonadeNexus/Security/Upgrade/UpgradeProgress.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <map>

namespace {

using namespace nexus;
using namespace nexus::security;

constexpr uint64_t kRelease = 2026102401;

struct Key {
    crypto::Ed25519Keypair pair;
    NodeId id;
};

class UpgradeProgressTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        network.fill(0x4E);
        for (int i = 0; i < 9; ++i) {
            Key key;
            crypto_sign_keypair(key.pair.public_key.data(), key.pair.private_key.data());
            key.id.bytes = key.pair.public_key;
            keys.push_back(key);
        }
        for (int i = 0; i < 5; ++i) tier1.push_back(keys[i].id);
        for (int i = 5; i < 8; ++i) tier2.push_back(keys[i].id);
        witnesses = {network, EpochId{3}, tier1};
    }

    [[nodiscard]] const Key& key_of(const NodeId& node) const {
        return *std::find_if(keys.begin(), keys.end(),
                             [&node](const Key& k) { return k.id == node; });
    }

    [[nodiscard]] UpgradeStatus status(const NodeId& node, uint8_t flags,
                                       uint64_t staged = kRelease) const {
        UpgradeStatus s;
        s.network_id = network;
        s.node = node;
        s.running_release = kRelease - 1;
        s.staged_release = staged;
        s.flags = flags;
        s.timestamp_ms = 1'800'000'000'000ULL;
        sign_upgrade_status(s, key_of(node).pair.private_key);
        return s;
    }

    [[nodiscard]] UpgradeObservation observation(const NodeId& witness, const NodeId& subject,
                                                 const Digest& head) const {
        UpgradeObservation o;
        o.network_id = network;
        o.release_number = kRelease;
        o.subject = subject;
        o.chain_head = head;
        o.witness = witness;
        o.evidence_digest.fill(0xE1);
        sign_upgrade_observation(o, key_of(witness).pair.private_key);
        return o;
    }

    [[nodiscard]] UpgradeRecord next(UpgradeEvent event) const {
        UpgradeRecord r;
        r.network_id = network;
        r.sequence = state.sequence + 1;
        r.previous = state.head;
        r.event = event;
        r.release_number = kRelease;
        return r;
    }

    [[nodiscard]] UpgradeRecord start_record() const {
        auto r = next(UpgradeEvent::Start);
        r.approval_digest.fill(0xA9);
        r.order = derive_upgrade_order(kRelease, tier1, tier2);
        return r;
    }

    void apply(const UpgradeRecord& record) {
        ASSERT_EQ(check_upgrade_record(state, record, &witnesses), UpgradeRecordFailure::None);
        apply_upgrade_record(state, record);
    }

    [[nodiscard]] UpgradeRecord turn_for(const NodeId& subject) const {
        auto r = next(UpgradeEvent::Turn);
        r.subject = subject;
        r.status = status(subject, kUpgradeStatusReady | kUpgradeStatusHealthy);
        return r;
    }

    [[nodiscard]] UpgradeRecord upgraded_for(const NodeId& subject) const {
        auto r = next(UpgradeEvent::Upgraded);
        r.subject = subject;
        for (const auto& witness : tier1) {
            if (witness != subject) {
                r.observations.push_back(observation(witness, subject, state.head));
            }
        }
        return r;
    }

    NetworkId network{};
    std::vector<Key> keys;
    std::vector<NodeId> tier1;
    std::vector<NodeId> tier2;
    UpgradeWitnessSet witnesses;
    UpgradeChainState state;
};

TEST_F(UpgradeProgressTest, OrderPutsTier2FirstAndIsDeterministicPerRelease) {
    const auto order = derive_upgrade_order(kRelease, tier1, tier2);
    ASSERT_EQ(order.size(), tier1.size() + tier2.size());
    for (std::size_t i = 0; i < order.size(); ++i) {
        EXPECT_EQ(order[i].tier1, i >= tier2.size()) << i;
    }
    // Input order does not matter; the release number does.
    auto shuffled_tier1 = tier1;
    std::reverse(shuffled_tier1.begin(), shuffled_tier1.end());
    EXPECT_EQ(derive_upgrade_order(kRelease, shuffled_tier1, tier2), order);
    const auto other = derive_upgrade_order(kRelease + 1, tier1, tier2);
    std::vector<NodeId> a, b;
    for (const auto& p : order) a.push_back(p.node);
    for (const auto& p : other) b.push_back(p.node);
    EXPECT_NE(a, b) << "the ranking must depend on the release number";
    // A node listed as both counts as Tier 1, once.
    auto both = tier2;
    both.push_back(tier1.front());
    EXPECT_EQ(derive_upgrade_order(kRelease, tier1, both), order);
}

TEST_F(UpgradeProgressTest, RecordsRoundTripAndBoundsHold) {
    apply(start_record());
    const auto turn = turn_for(*state.next_subject());
    const auto bytes = encode_upgrade_record(turn);
    const auto decoded = decode_upgrade_record(bytes);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(upgrade_record_digest(*decoded), upgrade_record_digest(turn));
    auto trailing = bytes;
    trailing.push_back(0);
    EXPECT_FALSE(decode_upgrade_record(trailing).has_value());
    EXPECT_FALSE(decode_upgrade_record(std::span(bytes).first(bytes.size() - 1)).has_value());
    UpgradeRecord huge = start_record();
    huge.order.resize(constants::kMaxUpgradeParticipants + 1);
    EXPECT_TRUE(encode_upgrade_record(huge).empty());
}

TEST_F(UpgradeProgressTest, AStartMustBeCanonicalNewerAndChained) {
    auto shuffled = start_record();
    std::swap(shuffled.order[0], shuffled.order[1]);
    EXPECT_EQ(check_upgrade_record(state, shuffled, &witnesses), UpgradeRecordFailure::BadOrder);
    auto unchained = start_record();
    unchained.sequence = 5;
    EXPECT_EQ(check_upgrade_record(state, unchained, &witnesses),
              UpgradeRecordFailure::NotChained);
    apply(start_record());
    auto again = start_record();
    EXPECT_EQ(check_upgrade_record(state, again, &witnesses), UpgradeRecordFailure::StaleRelease);
}

TEST_F(UpgradeProgressTest, TurnsFollowTheOrderAndOnlyOneIsOpen) {
    apply(start_record());
    const NodeId first = *state.next_subject();
    const NodeId second = state.order[1].node;
    // The second server asking first is refused: it is not next.
    EXPECT_EQ(check_upgrade_record(state, turn_for(second), &witnesses),
              UpgradeRecordFailure::NotNext);
    apply(turn_for(first));
    EXPECT_EQ(state.in_turn, first);
    // Two servers trying to restart at the same time: while one turn is open,
    // no second Turn record is valid, for anyone.
    EXPECT_EQ(check_upgrade_record(state, turn_for(second), &witnesses),
              UpgradeRecordFailure::NotNext);
    EXPECT_EQ(evaluate_upgrade_gate(state, first, kRelease), UpgradeGate::Go);
    EXPECT_EQ(evaluate_upgrade_gate(state, second, kRelease), UpgradeGate::Wait);
    // A new Start cannot cut in while the turn is open.
    auto newer = start_record();
    newer.release_number = kRelease + 1;
    newer.order = derive_upgrade_order(kRelease + 1, tier1, tier2);
    EXPECT_EQ(check_upgrade_record(state, newer, &witnesses), UpgradeRecordFailure::TurnOpen);
}

TEST_F(UpgradeProgressTest, ATurnNeedsTheSubjectsOwnReadyStatus) {
    apply(start_record());
    const NodeId first = *state.next_subject();
    auto forged = turn_for(first);
    forged.status->signature[0] ^= 1;
    EXPECT_EQ(check_upgrade_record(state, forged, &witnesses), UpgradeRecordFailure::BadStatus);
    auto foreign = turn_for(first);
    foreign.status = status(tier1.front() == first ? tier1.back() : tier1.front(),
                            kUpgradeStatusReady);
    EXPECT_EQ(check_upgrade_record(state, foreign, &witnesses), UpgradeRecordFailure::BadStatus);
    auto other_release = turn_for(first);
    other_release.status = status(first, kUpgradeStatusReady, kRelease + 1);
    EXPECT_EQ(check_upgrade_record(state, other_release, &witnesses),
              UpgradeRecordFailure::BadStatus);
    auto failed = turn_for(first);
    failed.status = status(first, kUpgradeStatusReady | kUpgradeStatusFailed);
    EXPECT_EQ(check_upgrade_record(state, failed, &witnesses), UpgradeRecordFailure::BadStatus);
}

TEST_F(UpgradeProgressTest, UpgradedNeedsAWitnessQuorumBoundToThePosition) {
    apply(start_record());
    const NodeId first = *state.next_subject();  // a Tier 2 server
    apply(turn_for(first));

    auto too_few = upgraded_for(first);
    too_few.observations.resize(2);
    EXPECT_EQ(check_upgrade_record(state, too_few, &witnesses),
              UpgradeRecordFailure::TooFewWitnesses);

    // An observation from an earlier chain position is a replay.
    auto replayed = upgraded_for(first);
    replayed.observations.front() =
        observation(replayed.observations.front().witness, first, Digest{});
    EXPECT_EQ(check_upgrade_record(state, replayed, &witnesses),
              UpgradeRecordFailure::BadObservation);

    // A Tier 2 server cannot witness.
    auto tier2_witness = upgraded_for(first);
    tier2_witness.observations.front() = observation(tier2.back(), first, state.head);
    EXPECT_EQ(check_upgrade_record(state, tier2_witness, &witnesses),
              UpgradeRecordFailure::BadObservation);

    auto duplicate = upgraded_for(first);
    duplicate.observations.back() = duplicate.observations.front();
    EXPECT_EQ(check_upgrade_record(state, duplicate, &witnesses),
              UpgradeRecordFailure::BadObservation);

    auto forged = upgraded_for(first);
    forged.observations.front().evidence_digest[0] ^= 1;
    EXPECT_EQ(check_upgrade_record(state, forged, &witnesses),
              UpgradeRecordFailure::BadObservation);

    EXPECT_EQ(check_upgrade_record(state, upgraded_for(first), nullptr),
              UpgradeRecordFailure::BadObservation);
    apply(upgraded_for(first));
    EXPECT_FALSE(state.in_turn.has_value());
    EXPECT_EQ(evaluate_upgrade_gate(state, first, kRelease), UpgradeGate::Done);
}

TEST_F(UpgradeProgressTest, ATier1SubjectNeverWitnessesItself) {
    apply(start_record());
    // Walk the Tier 2 servers through.
    while (!state.order[static_cast<std::size_t>(std::count_if(
                            state.order.begin(), state.order.end(),
                            [this](const UpgradeParticipant& p) {
                                return state.upgraded.contains(p.node);
                            }))]
                .tier1) {
        const NodeId subject = *state.next_subject();
        apply(turn_for(subject));
        apply(upgraded_for(subject));
    }
    const NodeId subject = *state.next_subject();
    ASSERT_TRUE(std::find(tier1.begin(), tier1.end(), subject) != tier1.end());
    apply(turn_for(subject));
    auto self_witness = upgraded_for(subject);
    self_witness.observations.push_back(observation(subject, subject, state.head));
    EXPECT_EQ(check_upgrade_record(state, self_witness, &witnesses),
              UpgradeRecordFailure::BadObservation);
    // Four other members, threshold max(4 - 1, f + 1) = 3.
    auto three = upgraded_for(subject);
    three.observations.resize(3);
    EXPECT_EQ(check_upgrade_record(state, three, &witnesses), UpgradeRecordFailure::None);
}

TEST_F(UpgradeProgressTest, AFailedReportHaltsTheRelease) {
    apply(start_record());
    const NodeId first = *state.next_subject();
    const NodeId second = state.order[1].node;
    // Only the server whose turn is open can halt, and only with its own
    // signed Failed status.
    auto early = next(UpgradeEvent::Halt);
    early.subject = first;
    early.status = status(first, kUpgradeStatusFailed);
    EXPECT_EQ(check_upgrade_record(state, early, &witnesses), UpgradeRecordFailure::NotInTurn);
    apply(turn_for(first));
    auto by_other = next(UpgradeEvent::Halt);
    by_other.subject = second;
    by_other.status = status(second, kUpgradeStatusFailed);
    EXPECT_EQ(check_upgrade_record(state, by_other, &witnesses), UpgradeRecordFailure::NotInTurn);
    auto not_failed = next(UpgradeEvent::Halt);
    not_failed.subject = first;
    not_failed.status = status(first, kUpgradeStatusReady);
    EXPECT_EQ(check_upgrade_record(state, not_failed, &witnesses), UpgradeRecordFailure::BadStatus);

    auto halt = next(UpgradeEvent::Halt);
    halt.subject = first;
    halt.status = status(first, kUpgradeStatusFailed);
    apply(halt);
    EXPECT_TRUE(state.halted);
    for (const auto& p : state.order) {
        EXPECT_EQ(evaluate_upgrade_gate(state, p.node, kRelease), UpgradeGate::Halted);
    }
    EXPECT_EQ(check_upgrade_record(state, turn_for(second), &witnesses),
              UpgradeRecordFailure::RolloutClosed);
    // Only a newer release starts again.
    auto newer = start_record();
    newer.release_number = kRelease + 1;
    newer.order = derive_upgrade_order(kRelease + 1, tier1, tier2);
    apply(newer);
    EXPECT_FALSE(state.halted);
    EXPECT_EQ(evaluate_upgrade_gate(state, first, kRelease), UpgradeGate::NotStarted);
}

TEST_F(UpgradeProgressTest, AServerAlreadyOnTheReleaseIsUpgradedWithoutATurn) {
    apply(start_record());
    const NodeId first = *state.next_subject();
    apply(upgraded_for(first));
    EXPECT_TRUE(state.upgraded.contains(first));
    // Not next: refused.
    const NodeId third = state.order[2].node;
    EXPECT_EQ(check_upgrade_record(state, upgraded_for(third), &witnesses),
              UpgradeRecordFailure::NotInTurn);
}

TEST_F(UpgradeProgressTest, OutsidersGoOnlyAfterTheRolloutCompletes) {
    apply(start_record());
    const NodeId outsider = keys[8].id;
    EXPECT_EQ(evaluate_upgrade_gate(state, outsider, kRelease), UpgradeGate::Wait);
    EXPECT_EQ(evaluate_upgrade_gate(state, outsider, kRelease + 1), UpgradeGate::NotStarted);
    while (const auto subject = state.next_subject()) {
        apply(turn_for(*subject));
        apply(upgraded_for(*subject));
    }
    EXPECT_TRUE(state.complete());
    EXPECT_EQ(evaluate_upgrade_gate(state, outsider, kRelease), UpgradeGate::Go);
}

TEST_F(UpgradeProgressTest, AFinalizedStartRebasesANodeThatMissedRecords) {
    UpgradeChainState behind;
    apply(start_record());
    apply(turn_for(*state.next_subject()));
    auto newer = next(UpgradeEvent::Start);
    newer.release_number = kRelease + 1;
    newer.approval_digest.fill(0xB1);
    newer.order = derive_upgrade_order(kRelease + 1, tier1, tier2);
    newer.sequence = state.sequence + 1;
    // The open turn blocks it on the full chain, so build it on a closed one.
    UpgradeChainState fresh;
    newer.previous = Digest{};
    newer.sequence = 9;
    EXPECT_EQ(check_upgrade_record(fresh, newer, &witnesses), UpgradeRecordFailure::NotChained);
    EXPECT_EQ(check_upgrade_record(fresh, newer, &witnesses, true), UpgradeRecordFailure::None);
    // A replayed older Start never rebases a newer rollout.
    UpgradeChainState newer_state = fresh;
    apply_upgrade_record(newer_state, newer);
    auto old_start = start_record();
    old_start.sequence = 20;
    EXPECT_EQ(check_upgrade_record(newer_state, old_start, &witnesses, true),
              UpgradeRecordFailure::StaleRelease);
}

}  // namespace
