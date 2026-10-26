// Regression tests for lnsdk::BoringtunMesh mesh-key derivation.
//
// derive_keypair() must be a STABLE, deterministic function of the device
// seed so a client re-join presents the same Curve25519 key the server
// already knows (a fresh key each launch left a stale server peer and broke
// the tunnel after the first session). These tests pin: determinism, the
// X25519 clamp, pub == scalarmult_base(priv), seed-sensitivity, and that the
// key is the domain-separated keyed-BLAKE2b of the seed (not the RNG path).

#include <gtest/gtest.h>
#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using lnsdk::BoringtunMesh;

namespace {

std::array<uint8_t, 32> decode32(const std::string& b64) {
    std::array<uint8_t, 32> out{};
    EXPECT_EQ(sodium_base642bin(out.data(), out.size(), b64.c_str(), b64.size(),
                                nullptr, nullptr, nullptr,
                                sodium_base64_VARIANT_ORIGINAL),
              0);
    return out;
}

std::array<uint8_t, 32> filled_seed(uint8_t byte) {
    std::array<uint8_t, 32> seed{};
    seed.fill(byte);
    return seed;
}

} // namespace

TEST(BoringtunKeys, DeriveIsDeterministic) {
    ASSERT_GE(sodium_init(), 0);
    auto seed = filled_seed(0x11);
    auto k1 = BoringtunMesh::derive_keypair(seed);
    auto k2 = BoringtunMesh::derive_keypair(seed);
    EXPECT_EQ(k1.first, k2.first);    // same private key
    EXPECT_EQ(k1.second, k2.second);  // same public key
}

TEST(BoringtunKeys, DerivedPrivateKeyIsClamped) {
    ASSERT_GE(sodium_init(), 0);
    auto priv = decode32(BoringtunMesh::derive_keypair(filled_seed(0x22)).first);
    EXPECT_EQ(priv[0] & 0x07, 0);       // low 3 bits cleared
    EXPECT_EQ(priv[31] & 0x80, 0);      // top bit cleared
    EXPECT_EQ(priv[31] & 0x40, 0x40);   // bit 6 set
}

TEST(BoringtunKeys, PublicKeyMatchesScalarmultBase) {
    ASSERT_GE(sodium_init(), 0);
    auto kp = BoringtunMesh::derive_keypair(filled_seed(0x33));
    auto priv = decode32(kp.first);
    auto pub = decode32(kp.second);
    unsigned char expect[32];
    ASSERT_EQ(crypto_scalarmult_base(expect, priv.data()), 0);
    EXPECT_EQ(std::memcmp(expect, pub.data(), 32), 0);
}

TEST(BoringtunKeys, DifferentSeedsDeriveDifferentKeys) {
    ASSERT_GE(sodium_init(), 0);
    EXPECT_NE(BoringtunMesh::derive_keypair(filled_seed(0x01)).first,
              BoringtunMesh::derive_keypair(filled_seed(0x02)).first);
}

// The private key is the domain-separated keyed-BLAKE2b of the seed under the
// "ln-mesh-x25519" context, then X25519-clamped — not a random key and not the
// seed used verbatim for another purpose. Recompute it independently.
TEST(BoringtunKeys, DerivesViaKeyedBlake2bContext) {
    ASSERT_GE(sodium_init(), 0);
    auto seed = filled_seed(0x44);
    unsigned char key[crypto_generichash_KEYBYTES] = {
        'l', 'n', '-', 'm', 'e', 's', 'h', '-', 'x', '2', '5', '5', '1', '9'};
    unsigned char expect[32];
    ASSERT_EQ(crypto_generichash(expect, sizeof expect, seed.data(), seed.size(),
                                 key, sizeof key),
              0);
    expect[0] &= 248;
    expect[31] &= 127;
    expect[31] |= 64;
    auto priv = decode32(BoringtunMesh::derive_keypair(seed).first);
    EXPECT_EQ(std::memcmp(expect, priv.data(), 32), 0);
}

// A peer's tunnel address and private subnet become routes on the viewing
// device. A peer must not take the server's plane route, the viewer's own
// address, or another peer's address by widening what it advertises.
namespace {

lnsdk::MeshPeer mesh_peer(const std::string& id, const std::string& tunnel_ip,
                          const std::string& private_subnet = {}) {
    lnsdk::MeshPeer p;
    p.node_id = id;
    p.mesh_pubkey = "key-" + id;
    p.tunnel_ip = tunnel_ip;
    p.private_subnet = private_subnet;
    return p;
}

const std::vector<std::string> kPlane = {"10.64.0.0/10"};
const std::string kOwn = "10.64.0.2/32";

}  // namespace

TEST(BoringtunPeerRoutes, ValidPeersGetTheirTunnelAddressAndSubnet) {
    const auto routes = BoringtunMesh::peer_allowed_ips(
        {mesh_peer("a", "10.64.0.3/32", "10.128.0.4/30"), mesh_peer("b", "10.65.1.2")}, kPlane,
        kOwn);
    ASSERT_EQ(routes.size(), 2u);
    EXPECT_EQ(routes[0], "10.64.0.3/32,10.128.0.4/30");
    EXPECT_EQ(routes[1], "10.65.1.2/32");
}

TEST(BoringtunPeerRoutes, ASubnetOutsideThePrivatePoolIsNotRouted) {
    const auto routes = BoringtunMesh::peer_allowed_ips(
        {mesh_peer("plane", "10.64.0.3/32", "10.64.0.0/10"),
         mesh_peer("server", "10.64.0.4/32", "10.64.0.1/32"),
         mesh_peer("internet", "10.64.0.5/32", "0.0.0.0/0"),
         mesh_peer("lan", "10.64.0.6/32", "192.168.1.0/24"),
         mesh_peer("huge", "10.64.0.7/32", "10.128.0.0/9"),
         mesh_peer("hostbits", "10.64.0.8/32", "10.128.0.5/30")},
        kPlane, kOwn);
    ASSERT_EQ(routes.size(), 6u);
    EXPECT_EQ(routes[0], "10.64.0.3/32");
    EXPECT_EQ(routes[1], "10.64.0.4/32");
    EXPECT_EQ(routes[2], "10.64.0.5/32");
    EXPECT_EQ(routes[3], "10.64.0.6/32");
    EXPECT_EQ(routes[4], "10.64.0.7/32");
    EXPECT_EQ(routes[5], "10.64.0.8/32");
}

TEST(BoringtunPeerRoutes, OverlappingSubnetsAreRefusedForEveryPeerInvolved) {
    const auto routes = BoringtunMesh::peer_allowed_ips(
        {mesh_peer("a", "10.64.0.3/32", "10.128.0.0/24"),
         mesh_peer("b", "10.64.0.4/32", "10.128.0.8/30"),
         mesh_peer("c", "10.64.0.5/32", "10.128.1.0/30")},
        kPlane, kOwn);
    EXPECT_EQ(routes[0], "10.64.0.3/32");
    EXPECT_EQ(routes[1], "10.64.0.4/32");
    EXPECT_EQ(routes[2], "10.64.0.5/32,10.128.1.0/30");
}

TEST(BoringtunPeerRoutes, ATunnelAddressThatIsNotThePeersOwnGetsNoRoute) {
    const auto routes = BoringtunMesh::peer_allowed_ips(
        {mesh_peer("own", kOwn), mesh_peer("outside", "172.16.0.2/32"),
         mesh_peer("wide", "10.64.0.0/16"), mesh_peer("dup1", "10.64.0.9/32"),
         mesh_peer("dup2", "10.64.0.9"), mesh_peer("ok", "10.64.0.10/32")},
        kPlane, kOwn);
    ASSERT_EQ(routes.size(), 6u);
    for (std::size_t i = 0; i < 5; ++i) EXPECT_TRUE(routes[i].empty()) << i << ": " << routes[i];
    EXPECT_EQ(routes[5], "10.64.0.10/32");
}

// The session server's private API answers on the server's tunnel address,
// which the server peer's plane route carries. A peer route on that address is
// a longer match and would send the private API traffic to the peer instead.
// Before servers had unique addresses, every server and the first endpoint
// that a server allocated held 10.64.0.10.
TEST(BoringtunPeerRoutes, APeerNeverGetsTheSessionServersAddress) {
    const std::string server = "10.64.252.37";
    const auto routes = BoringtunMesh::peer_allowed_ips(
        {mesh_peer("bare", server), mesh_peer("prefixed", server + "/32"),
         mesh_peer("other-server", "10.64.252.38/32"), mesh_peer("endpoint", "10.65.0.9/32")},
        kPlane, kOwn, server);
    ASSERT_EQ(routes.size(), 4u);
    EXPECT_TRUE(routes[0].empty()) << routes[0];
    EXPECT_TRUE(routes[1].empty()) << routes[1];
    EXPECT_EQ(routes[2], "10.64.252.38/32");
    EXPECT_EQ(routes[3], "10.65.0.9/32");

    // The server address is also reserved when it arrives with a prefix.
    const auto prefixed = BoringtunMesh::peer_allowed_ips({mesh_peer("p", server)}, kPlane,
                                                          kOwn, server + "/32");
    EXPECT_TRUE(prefixed[0].empty()) << prefixed[0];

    // Without a known server address only the own address is reserved.
    const auto unknown =
        BoringtunMesh::peer_allowed_ips({mesh_peer("p", server)}, kPlane, kOwn);
    EXPECT_EQ(unknown[0], server + "/32");
}
