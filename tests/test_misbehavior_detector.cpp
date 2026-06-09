#include <LemonadeNexus/Gossip/MisbehaviorDetector.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <string>

using namespace nexus::gossip;
using json = nlohmann::json;
namespace crypto = nexus::crypto;

class MisbehaviorDetectorTest : public ::testing::Test {
protected:
    crypto::SodiumCryptoService cryptosvc;
    void SetUp() override { cryptosvc.start(); }
    void TearDown() override { cryptosvc.stop(); }

    // Build a tree-delta JSON object signed by `kp`, mirroring the wire form that
    // GossipService::do_handle_deltas verifies.
    json make_delta(const crypto::Ed25519Keypair& kp,
                    const std::string& target, uint64_t seq,
                    const std::string& op, const std::string& perm,
                    uint64_t ts, const json& data) {
        json d;
        d["operation"]           = op;
        d["target_node_id"]      = target;
        d["sequence"]            = seq;
        d["required_permission"] = perm;
        d["timestamp"]           = ts;
        d["data"]                = data;
        d["signer_pubkey"]       = "ed25519:" + crypto::to_base64(kp.public_key);

        std::string canonical = op + "\n" + target + "\n" + std::to_string(seq) + "\n" +
                                perm + "\n" + std::to_string(ts) + "\n" + data.dump();
        std::vector<uint8_t> bytes(canonical.begin(), canonical.end());
        auto sig = cryptosvc.ed25519_sign(kp.private_key, bytes);
        d["signature"] = crypto::to_base64(sig);
        return d;
    }
};

// Two validly-signed, conflicting deltas at the same (target,sequence) produce a
// proof that verifies as dispositive.
TEST_F(MisbehaviorDetectorTest, EquivocationProofVerifies) {
    auto kp = cryptosvc.ed25519_keygen();
    auto a = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 1}});
    auto b = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 2}});  // same pos, diff data

    EXPECT_TRUE(verify_tree_delta_signature(a, cryptosvc));
    EXPECT_TRUE(verify_tree_delta_signature(b, cryptosvc));
    EXPECT_TRUE(tree_deltas_conflict(a, b));

    auto proof = make_tree_delta_equivocation_proof(a, b, "reporter", 123, cryptosvc);
    ASSERT_TRUE(proof.has_value());
    EXPECT_EQ(proof->accused_pubkey, crypto::to_base64(kp.public_key));
    EXPECT_TRUE(verify_misbehavior_proof(*proof, cryptosvc));
}

// Identical statements are not a conflict (a duplicate is not equivocation).
TEST_F(MisbehaviorDetectorTest, IdenticalStatementsAreNotEquivocation) {
    auto kp = cryptosvc.ed25519_keygen();
    auto a = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 1}});
    auto b = a;
    EXPECT_FALSE(tree_deltas_conflict(a, b));
    EXPECT_FALSE(make_tree_delta_equivocation_proof(a, b, "r", 1, cryptosvc).has_value());
}

// Different (target,sequence) is not equivocation — those are distinct positions.
TEST_F(MisbehaviorDetectorTest, DifferentPositionIsNotEquivocation) {
    auto kp = cryptosvc.ed25519_keygen();
    auto a = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 1}});
    auto b = make_delta(kp, "node1", 6, "grant", "admin", 100, json{{"v", 2}});  // diff seq
    EXPECT_FALSE(tree_deltas_conflict(a, b));
}

// A tampered signature makes the statement invalid, so no proof can be built.
TEST_F(MisbehaviorDetectorTest, TamperedSignatureRejected) {
    auto kp = cryptosvc.ed25519_keygen();
    auto a = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 1}});
    auto b = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 2}});

    // Flip a byte of b's data without re-signing → signature no longer valid.
    b["data"] = json{{"v", 3}};
    EXPECT_FALSE(verify_tree_delta_signature(b, cryptosvc));
    EXPECT_FALSE(make_tree_delta_equivocation_proof(a, b, "r", 1, cryptosvc).has_value());
}

// GRIEFING RESISTANCE: an attacker cannot frame an honest victim. A proof whose
// statements are signed by the attacker but which accuses the victim's pubkey is
// rejected, because the statements are not signed by the accused key.
TEST_F(MisbehaviorDetectorTest, CannotFrameHonestPeer) {
    auto victim   = cryptosvc.ed25519_keygen();
    auto attacker = cryptosvc.ed25519_keygen();

    // Attacker signs two conflicting deltas with ITS OWN key...
    auto a = make_delta(attacker, "node1", 5, "grant", "admin", 100, json{{"v", 1}});
    auto b = make_delta(attacker, "node1", 5, "grant", "admin", 100, json{{"v", 2}});

    // ...then forges a proof claiming the VICTIM is the accused.
    MisbehaviorProof forged;
    forged.kind = MisbehaviorKind::TreeDeltaEquivocation;
    forged.accused_pubkey = crypto::to_base64(victim.public_key);
    forged.statement_a = a.dump();
    forged.statement_b = b.dump();
    forged.reporter_pubkey = "attacker";

    EXPECT_FALSE(verify_misbehavior_proof(forged, cryptosvc))
        << "statements not signed by the accused must never convict the accused";
}

// A proof carrying only one (or zero) genuinely-conflicting statements is rejected.
TEST_F(MisbehaviorDetectorTest, NonConflictingStatementsRejected) {
    auto kp = cryptosvc.ed25519_keygen();
    auto a = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 1}});
    auto b = make_delta(kp, "node2", 9, "revoke", "admin", 200, json{{"v", 2}});  // unrelated

    MisbehaviorProof p;
    p.kind = MisbehaviorKind::TreeDeltaEquivocation;
    p.accused_pubkey = crypto::to_base64(kp.public_key);
    p.statement_a = a.dump();
    p.statement_b = b.dump();
    EXPECT_FALSE(verify_misbehavior_proof(p, cryptosvc));
}

// Two independent observers (who see the conflict in opposite order) must compute the
// SAME proof_id, so the proof dedupes/converges across the mesh.
TEST_F(MisbehaviorDetectorTest, ProofIdIsOrderIndependent) {
    auto kp = cryptosvc.ed25519_keygen();
    auto a = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 1}});
    auto b = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 2}});

    auto p1 = make_tree_delta_equivocation_proof(a, b, "obs1", 10, cryptosvc);
    auto p2 = make_tree_delta_equivocation_proof(b, a, "obs2", 20, cryptosvc);
    ASSERT_TRUE(p1 && p2);
    EXPECT_EQ(p1->proof_id, p2->proof_id);
    EXPECT_FALSE(p1->proof_id.empty());
}

// Serialization round-trips so the proof survives gossip.
TEST_F(MisbehaviorDetectorTest, ProofJsonRoundTrip) {
    auto kp = cryptosvc.ed25519_keygen();
    auto a = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 1}});
    auto b = make_delta(kp, "node1", 5, "grant", "admin", 100, json{{"v", 2}});
    auto proof = make_tree_delta_equivocation_proof(a, b, "r", 1, cryptosvc);
    ASSERT_TRUE(proof.has_value());

    json j = *proof;
    auto restored = j.get<MisbehaviorProof>();
    EXPECT_EQ(restored.proof_id, proof->proof_id);
    EXPECT_TRUE(verify_misbehavior_proof(restored, cryptosvc));
}
