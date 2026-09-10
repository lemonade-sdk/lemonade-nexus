// Durable observations across a restart.
//
// The properties under test: a restart neither invents eligibility history nor
// loses it, a damaged file is reported as damaged rather than as a clean slate,
// and an edited file cannot assert a fact no observer signed.

#include <LemonadeNexus/Security/Eligibility/EligibilityStore.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace constants = nexus::security::constants;

using nexus::security::Digest;
using nexus::security::EligibilityLedger;
using nexus::security::EligibilityLoadResult;
using nexus::security::EligibilityObservation;
using nexus::security::EligibilityStore;
using nexus::security::EpochId;
using nexus::security::Height;
using nexus::security::MeshFactContext;
using nexus::security::NetworkId;
using nexus::security::NodeId;
using nexus::security::ObservationKind;
using nexus::security::ObservationOutcome;
using nexus::security::established_fact_context;
using nexus::security::sign_observation;

namespace {

constexpr EpochId kEpoch = 9;

NetworkId network() {
    NetworkId id{};
    id.fill(0xA0);
    return id;
}

Digest digest(uint8_t seed) {
    Digest d{};
    d.fill(seed);
    return d;
}

struct Node {
    nexus::crypto::Ed25519Keypair identity;
    NodeId id;
};

Node make_node() {
    Node node;
    crypto_sign_keypair(node.identity.public_key.data(), node.identity.private_key.data());
    node.id.bytes = node.identity.public_key;
    return node;
}

class StoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        root_ = fs::temp_directory_path() /
                ("nexus_elig_" + std::to_string(::getpid()) + "_" +
                 ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(root_);

        for (int i = 0; i < 5; ++i) members_.push_back(make_node());
        candidate_ = make_node();
        std::vector<NodeId> ids;
        for (const auto& member : members_) ids.push_back(member.id);
        context_ = established_fact_context(network(), kEpoch, ids);
    }

    void TearDown() override { fs::remove_all(root_); }

    [[nodiscard]] EligibilityObservation observation(const Node& observer, uint8_t seed,
                                                      Height height,
                                                      ObservationKind kind) const {
        EligibilityObservation o;
        o.network_id = network();
        o.epoch = kEpoch;
        o.subject = candidate_.id;
        o.subject_incarnation = 1;
        o.kind = kind;
        if (kind == ObservationKind::Attestation) {
            o.attestation_digest = digest(seed);
        }
        o.height = height;
        o.state_reference = digest(0xC0);
        return sign_observation(o, observer.identity);
    }

    /// A ledger with both facts proved by a quorum.
    [[nodiscard]] EligibilityLedger full_ledger() const {
        EligibilityLedger ledger;
        for (std::size_t i = 0; i < context_.quorum; ++i) {
            EXPECT_EQ(ledger.record(observation(members_[i], 0x10, 100,
                                                ObservationKind::Attestation), context_),
                      ObservationOutcome::Accepted);
            EXPECT_EQ(ledger.record(observation(members_[i], 0x11, 200,
                                                ObservationKind::Attestation), context_),
                      ObservationOutcome::Accepted);
            EXPECT_EQ(ledger.record(observation(members_[i], 0, 300,
                                                ObservationKind::Participation), context_),
                      ObservationOutcome::Accepted);
        }
        return ledger;
    }

    fs::path root_;
    std::vector<Node> members_;
    Node candidate_;
    MeshFactContext context_;
};

}  // namespace

TEST_F(StoreTest, ARestartKeepsWhatWasRecorded) {
    EligibilityStore store{root_};
    const EligibilityLedger before = full_ledger();
    ASSERT_TRUE(before.evaluate(candidate_.id, 1, context_).uptime_valid);
    ASSERT_TRUE(store.store(kEpoch, before.snapshot()));

    EligibilityLedger after;
    const auto result = store.load(kEpoch, context_, after);
    ASSERT_TRUE(std::holds_alternative<std::monostate>(result));

    const auto evidence = after.evaluate(candidate_.id, 1, context_);
    EXPECT_TRUE(evidence.uptime_valid);
    EXPECT_TRUE(evidence.mesh_health_valid);
    EXPECT_EQ(evidence.continuity_observers, context_.quorum);
}

// A node with nothing stored has no history. It does not start eligible and it
// does not start ineligible-but-trusted: it simply has no facts.
TEST_F(StoreTest, ARestartWithNothingStoredInventsNoHistory) {
    EligibilityStore store{root_};
    EligibilityLedger ledger;
    const auto result = store.load(kEpoch, context_, ledger);
    ASSERT_TRUE(std::holds_alternative<EligibilityLoadResult>(result));
    EXPECT_EQ(std::get<EligibilityLoadResult>(result), EligibilityLoadResult::Absent);

    const auto evidence = ledger.evaluate(candidate_.id, 1, context_);
    EXPECT_FALSE(evidence.uptime_valid);
    EXPECT_FALSE(evidence.mesh_health_valid);
}

// Corrupt is not Absent. Lost eligibility state must not read as a clean slate.
TEST_F(StoreTest, DamagedStateIsReportedAsCorrupt) {
    EligibilityStore store{root_};
    ASSERT_TRUE(store.store(kEpoch, full_ledger().snapshot()));

    const fs::path file = root_ / ("observations-" + std::to_string(kEpoch) + ".json");
    ASSERT_TRUE(fs::exists(file));
    { std::ofstream out(file, std::ios::trunc); out << "{ this is not json"; }

    EligibilityLedger ledger;
    const auto result = store.load(kEpoch, context_, ledger);
    ASSERT_TRUE(std::holds_alternative<EligibilityLoadResult>(result));
    EXPECT_EQ(std::get<EligibilityLoadResult>(result), EligibilityLoadResult::Corrupt);
    EXPECT_EQ(ledger.size(), 0u);
}

// The signatures decide, not the file. Editing a stored record cannot make the
// mesh have said something it did not.
TEST_F(StoreTest, AnEditedRecordMakesTheWholeFileCorrupt) {
    EligibilityStore store{root_};
    ASSERT_TRUE(store.store(kEpoch, full_ledger().snapshot()));

    const fs::path file = root_ / ("observations-" + std::to_string(kEpoch) + ".json");
    std::string text;
    { std::ifstream in(file); text.assign(std::istreambuf_iterator<char>(in),
                                          std::istreambuf_iterator<char>()); }
    // Flip one hex character of the first signature.
    const auto at = text.find("\"signature\":\"");
    ASSERT_NE(at, std::string::npos);
    const std::size_t nibble = at + std::string("\"signature\":\"").size();
    text[nibble] = text[nibble] == 'a' ? 'b' : 'a';
    { std::ofstream out(file, std::ios::trunc); out << text; }

    EligibilityLedger ledger;
    const auto result = store.load(kEpoch, context_, ledger);
    ASSERT_TRUE(std::holds_alternative<EligibilityLoadResult>(result));
    EXPECT_EQ(std::get<EligibilityLoadResult>(result), EligibilityLoadResult::Corrupt);
    EXPECT_EQ(ledger.size(), 0u);
}

// Rolling the store back to an earlier epoch does not extend continuity: the
// facts are epoch-scoped, so an old file answers a question nobody is asking.
TEST_F(StoreTest, RollbackDoesNotExtendContinuity) {
    EligibilityStore store{root_};
    ASSERT_TRUE(store.store(kEpoch, full_ledger().snapshot()));

    // The mesh has moved on. The rolled-back file is for the previous epoch.
    const MeshFactContext next =
        established_fact_context(network(), kEpoch + 1, context_.observers);
    EligibilityLedger ledger;
    const auto result = store.load(kEpoch + 1, next, ledger);
    ASSERT_TRUE(std::holds_alternative<EligibilityLoadResult>(result));
    EXPECT_EQ(std::get<EligibilityLoadResult>(result), EligibilityLoadResult::Absent);
    EXPECT_FALSE(ledger.evaluate(candidate_.id, 1, next).uptime_valid);

    // Even loaded under its own epoch, the observations do not answer for the
    // epoch the mesh is actually in.
    EligibilityLedger old_ledger;
    ASSERT_TRUE(std::holds_alternative<std::monostate>(
        store.load(kEpoch, context_, old_ledger)));
    EXPECT_FALSE(old_ledger.evaluate(candidate_.id, 1, next).uptime_valid);
}

// A file naming one epoch cannot be served as another. Renaming it is the
// obvious rollback attempt, and the epoch inside the document refuses it.
TEST_F(StoreTest, ARenamedFileIsCorruptRatherThanAccepted) {
    EligibilityStore store{root_};
    ASSERT_TRUE(store.store(kEpoch, full_ledger().snapshot()));
    fs::rename(root_ / ("observations-" + std::to_string(kEpoch) + ".json"),
               root_ / ("observations-" + std::to_string(kEpoch + 1) + ".json"));

    const MeshFactContext next =
        established_fact_context(network(), kEpoch + 1, context_.observers);
    EligibilityLedger ledger;
    const auto result = store.load(kEpoch + 1, next, ledger);
    ASSERT_TRUE(std::holds_alternative<EligibilityLoadResult>(result));
    EXPECT_EQ(std::get<EligibilityLoadResult>(result), EligibilityLoadResult::Corrupt);
}

TEST_F(StoreTest, ExpiredEpochsAreDiscarded) {
    EligibilityStore store{root_};
    ASSERT_TRUE(store.store(kEpoch, full_ledger().snapshot()));
    ASSERT_TRUE(store.store(kEpoch + 1, full_ledger().snapshot()));

    store.discard_before(kEpoch + 1);
    EXPECT_FALSE(fs::exists(root_ / ("observations-" + std::to_string(kEpoch) + ".json")));
    EXPECT_TRUE(fs::exists(root_ / ("observations-" + std::to_string(kEpoch + 1) + ".json")));
}

// An observer that left the Tier 1 set cannot keep contributing through a file
// written while it was still a member.
TEST_F(StoreTest, AnObserverRemovedFromTheSetIsRefusedOnLoad) {
    EligibilityStore store{root_};
    ASSERT_TRUE(store.store(kEpoch, full_ledger().snapshot()));

    MeshFactContext smaller = context_;
    smaller.observers.erase(smaller.observers.begin());
    EligibilityLedger ledger;
    const auto result = store.load(kEpoch, smaller, ledger);
    ASSERT_TRUE(std::holds_alternative<EligibilityLoadResult>(result));
    EXPECT_EQ(std::get<EligibilityLoadResult>(result), EligibilityLoadResult::Corrupt);
}
