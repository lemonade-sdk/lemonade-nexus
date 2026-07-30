// Regression tests for the POST /api/join mesh re-key policy
// (nexus::api::plan_mesh_rekey / normalize_mesh_pubkey).
//
// A client that rotates its boringtun key on re-join must (a) have its stored
// wg_pubkey rewritten even though the tunnel IP is unchanged, and (b) have its
// previous dataplane peer dropped before the new one is added — otherwise the
// stale peer's allowed_ips route shadows the new key and the tunnel dies after
// the first session. The buggy prior behavior updated the node only on an IP
// change and never removed the stale peer; the cases below fail against it.

#include <gtest/gtest.h>

#include <LemonadeNexus/Api/MeshRekey.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <sodium.h>

#include <span>
#include <string>

using nexus::api::normalize_mesh_pubkey;
using nexus::api::plan_mesh_rekey;

namespace {

std::string b64(std::span<const uint8_t> bytes) {
    return nexus::crypto::to_base64(bytes);
}

} // namespace

// --- normalize_mesh_pubkey ---------------------------------------------------

TEST(MeshRekeyNormalize, RawCurveKeyPassesThrough) {
    // A raw (non-prefixed) key is already the dataplane's Curve25519 key.
    EXPECT_EQ(normalize_mesh_pubkey("rawCurveKeyBase64"), "rawCurveKeyBase64");
}

TEST(MeshRekeyNormalize, Ed25519PrefixConvertsToX25519) {
    ASSERT_GE(sodium_init(), 0);
    nexus::crypto::SodiumCryptoService crypto;
    crypto.start();
    auto kp = crypto.ed25519_keygen();

    auto input = "ed25519:" + b64(kp.public_key);
    auto expected = b64(nexus::crypto::SodiumCryptoService::ed25519_pk_to_x25519(kp.public_key));

    EXPECT_EQ(normalize_mesh_pubkey(input), expected);
    EXPECT_NE(normalize_mesh_pubkey(input), input);  // it actually converted
}

TEST(MeshRekeyNormalize, MalformedEd25519PassesThroughWithoutThrowing) {
    // Bad base64 and a too-short key must not throw — just return the input.
    EXPECT_EQ(normalize_mesh_pubkey("ed25519:not valid base64!!"),
              "ed25519:not valid base64!!");
    EXPECT_EQ(normalize_mesh_pubkey("ed25519:QUJD"), "ed25519:QUJD");  // 3 bytes, not 32
}

// --- plan_mesh_rekey ---------------------------------------------------------

// THE core regression: a re-join keeps its IP but rotates its key.
TEST(MeshRekeyPlan, ReJoinRotatedKeySameIpUpdatesNodeAndRemovesStalePeer) {
    auto plan = plan_mesh_rekey("10.64.0.11", "10.64.0.11", "keyOld", "keyNew");
    EXPECT_TRUE(plan.update_node);        // rewrite the stored key (was IP-only before)
    EXPECT_TRUE(plan.remove_stale_peer);  // drop the dead peer
    EXPECT_EQ(plan.stale_peer_key, "keyOld");
    EXPECT_EQ(plan.new_peer_key, "keyNew");
}

TEST(MeshRekeyPlan, ReJoinSameKeySameIpIsNoOp) {
    auto plan = plan_mesh_rekey("10.64.0.11", "10.64.0.11", "keyA", "keyA");
    EXPECT_FALSE(plan.update_node);
    EXPECT_FALSE(plan.remove_stale_peer);
    EXPECT_EQ(plan.new_peer_key, "keyA");
}

TEST(MeshRekeyPlan, ReJoinSameKeyNewIpUpdatesNodeButKeepsPeer) {
    auto plan = plan_mesh_rekey("10.64.0.11", "10.64.0.12", "keyA", "keyA");
    EXPECT_TRUE(plan.update_node);         // IP moved
    EXPECT_FALSE(plan.remove_stale_peer);  // same key, same peer
}

TEST(MeshRekeyPlan, FirstJoinEmptyPreviousNeverRemoves) {
    auto plan = plan_mesh_rekey("", "10.64.0.11", "", "keyNew");
    EXPECT_TRUE(plan.update_node);         // "" -> real IP/key
    EXPECT_FALSE(plan.remove_stale_peer);  // nothing to remove yet
    EXPECT_EQ(plan.new_peer_key, "keyNew");
}

// Rotation is judged on the NORMALIZED key: a stored ed25519:-prefixed key and
// its raw X25519 equivalent are the SAME peer, so no spurious remove/re-add.
TEST(MeshRekeyPlan, EquivalentKeysAcrossFormatsDoNotRemovePeer) {
    ASSERT_GE(sodium_init(), 0);
    nexus::crypto::SodiumCryptoService crypto;
    crypto.start();
    auto kp = crypto.ed25519_keygen();

    auto prev_wg = "ed25519:" + b64(kp.public_key);  // stored in prefixed form
    auto new_wg = b64(nexus::crypto::SodiumCryptoService::ed25519_pk_to_x25519(kp.public_key));

    auto plan = plan_mesh_rekey("10.64.0.11", "10.64.0.11", prev_wg, new_wg);
    EXPECT_FALSE(plan.remove_stale_peer);  // same dataplane key -> not stale
    EXPECT_EQ(plan.new_peer_key, new_wg);
}
