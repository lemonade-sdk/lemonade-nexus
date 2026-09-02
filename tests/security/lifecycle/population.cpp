// The full driver above N = 5: growth rotations at seven and ten members.
//
// The cross-population simulation measures records and verifiers at every
// table size; these tests run the LIVE driver mesh through one rotation and
// real newcomer adoption at the next two table steps, to catch anything that
// silently assumed five members: quorum iteration, witness counts, package
// sizing, and DKG participant handling.

#include "support/rotation.hpp"

namespace lifecycle_test {
namespace {

/// Ten eligible nodes -> the table's target of seven.
struct SevenMesh : RotatingMeshBase {
    SevenMesh() : RotatingMeshBase(5) {}
};

/// Twenty-five eligible nodes -> the table's target of ten.
struct TenMesh : RotatingMeshBase {
    TenMesh() : RotatingMeshBase(20) {}
};

template <typename Fixture>
void run_growth(Fixture& fixture, std::size_t expected_members) {
    fixture.bootstrap();
    fixture.run_until_committed(1);
    fixture.introduce_reserves();

    std::vector<Node*> members = fixture.founders;
    std::vector<Node*> pool = members;
    pool.insert(pool.end(), fixture.reserves.begin(), fixture.reserves.end());

    members = fixture.rotate(members, pool, 1);
    ASSERT_EQ(members.size(), expected_members);

    // The new epoch runs with the grown committee: right quorum, right
    // threshold, and commits under the new membership with the newcomers
    // voting.
    const auto& current = members.front()->runtime->epochs()->current();
    EXPECT_EQ(current.tier1_members.size(), expected_members);
    EXPECT_EQ(current.consensus_quorum, constants::consensus_quorum(expected_members));
    EXPECT_EQ(current.authority_threshold, constants::authority_threshold(expected_members));

    std::size_t newcomers = 0;
    for (Node* member : members) {
        EXPECT_EQ(member->driver->current_epoch(), 2u);
        EXPECT_TRUE(member->driver->is_tier1_member());
        ASSERT_NE(member->runtime->consensus(), nullptr);
        EXPECT_EQ(*member->runtime->authority().key_epoch(), 2u);
        ASSERT_NE(member->driver->verified_authority(), nullptr);
        EXPECT_EQ(member->driver->verified_authority()->epoch, 2u);
        if (std::find(fixture.founders.begin(), fixture.founders.end(), member) ==
            fixture.founders.end()) {
            ++newcomers;
        }
    }
    // Growth beyond five seats guarantees real adoption happened.
    EXPECT_GE(newcomers, expected_members - fixture.founders.size());

    // Pool nodes selection passed over stay exactly what they were: Tier 2.
    for (Node* reserve : fixture.reserves) {
        if (std::find(members.begin(), members.end(), reserve) != members.end()) {
            continue;
        }
        EXPECT_FALSE(reserve->driver->is_tier1_member());
        EXPECT_FALSE(reserve->runtime->authority().key_epoch().has_value());
    }

    const Height before = members.front()->driver->last_committed_height();
    for (int i = 0; i < 400; ++i) {
        fixture.step(1, members);
        if (members.front()->driver->last_committed_height() > before) break;
    }
    EXPECT_GT(members.front()->driver->last_committed_height(), before);
}

TEST_F(SevenMesh, GrowthRotationToSevenAdoptsNewcomersLive) {
    run_growth(*this, 7);
}

TEST_F(TenMesh, GrowthRotationToTenAdoptsNewcomersLive) {
    run_growth(*this, 10);
}

}  // namespace
}  // namespace lifecycle_test
