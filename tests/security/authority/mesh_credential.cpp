// The post-Genesis server credential, verified under finalized mesh authority.
//
// A credential is signed by an epoch's authority key and verified under the
// group public key carried by a VerifiedEpochAuthority. These tests use a
// single Ed25519 key as the stand-in group key — a FROST group signature
// verifies as a standard Ed25519 signature, so the verification path is
// identical. Trust flows Genesis -> handoff chain -> epoch authority ->
// credential; the root key signs nothing here.

#include <LemonadeNexus/Security/Authority/MeshCredential.hpp>
#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

using namespace nexus::security;
namespace crypto = nexus::crypto;

namespace {

NetworkId net(uint8_t b) {
    NetworkId id{};
    id.fill(b);
    return id;
}

// A verified epoch authority whose group key is `group` — as if produced by
// walking the chain to `epoch`.
VerifiedEpochAuthority authority_with(const crypto::Ed25519PublicKey& group, EpochId epoch,
                                      const NetworkId& network) {
    VerifiedEpochAuthority a;
    a.network_id = network;
    a.epoch = epoch;
    a.group_public_key = group;
    a.key_generation = epoch;
    return a;
}

MeshCredential sign_credential(const MeshCredentialGrant& grant,
                               const crypto::Ed25519Keypair& group) {
    MeshCredential cred;
    cred.grant = grant;
    const Digest digest = mesh_credential_digest(grant);
    crypto_sign_detached(cred.authority_signature.data(), nullptr, digest.data(), digest.size(),
                         group.private_key.data());
    return cred;
}

MeshCredentialGrant base_grant(const NetworkId& network) {
    MeshCredentialGrant g;
    g.network_id = network;
    g.epoch = 3;
    g.key_generation = 3;
    g.operation = CredentialOperation::Issue;
    g.subject_pubkey = "c3ViamVjdA==";
    g.subject_server_id = "srv-east-1";
    g.subject_wg_pubkey = "d2dwdWJrZXk=";
    g.platform_class = "";  // plain Tier 2
    g.issued_at = 1000;
    g.expires_at = 0;
    return g;
}

struct MeshCredentialTest : ::testing::Test {
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
    crypto::Ed25519Keypair group() {
        crypto::Ed25519Keypair kp;
        crypto_sign_keypair(kp.public_key.data(), kp.private_key.data());
        return kp;
    }
};

TEST_F(MeshCredentialTest, VerifiesUnderTheIssuingEpochAuthority) {
    const auto network = net(0x11);
    const auto g = group();
    const auto cred = sign_credential(base_grant(network), g);
    const auto authority = authority_with(g.public_key, 3, network);

    EXPECT_EQ(verify_mesh_credential(cred, authority, 2000), MeshCredentialFailure::None);
    // A plain Tier 2 credential claims no platform facts — enrollment needs no
    // confidential computing.
    EXPECT_TRUE(cred.grant.platform_class.empty());
}

TEST_F(MeshCredentialTest, EveryBoundFieldIsSigned) {
    const auto network = net(0x11);
    const auto g = group();
    const auto authority = authority_with(g.public_key, 3, network);

    const auto mutate = [&](auto change) {
        auto grant = base_grant(network);
        change(grant);
        auto cred = sign_credential(grant, g);
        // Re-sign happened over the mutated grant, so it verifies — the point
        // is that the DIGEST changed, i.e. the field is inside the signature.
        return mesh_credential_digest(grant);
    };
    const Digest base = mesh_credential_digest(base_grant(network));
    EXPECT_NE(mutate([](auto& x) { x.subject_pubkey = "b3RoZXI="; }), base);
    EXPECT_NE(mutate([](auto& x) { x.subject_server_id = "srv-west-9"; }), base);
    EXPECT_NE(mutate([](auto& x) { x.subject_wg_pubkey = "b3RoZXJ3Zw=="; }), base);
    EXPECT_NE(mutate([](auto& x) { x.platform_class = "snp-vtpm"; }), base);
    EXPECT_NE(mutate([](auto& x) { x.expected_measurement = "aa"; }), base);
    EXPECT_NE(mutate([](auto& x) { x.approved_binary_hash = "bb"; }), base);
    EXPECT_NE(mutate([](auto& x) { x.operation = CredentialOperation::Revoke; }), base);
    EXPECT_NE(mutate([](auto& x) { x.expires_at = 9999; }), base);
    EXPECT_NE(mutate([](auto& x) { x.previous_grant_digest[0] ^= 1; }), base);
}

TEST_F(MeshCredentialTest, AnotherEpochsKeyDoesNotVerify) {
    const auto network = net(0x11);
    const auto real_group = group();
    const auto other_group = group();
    const auto cred = sign_credential(base_grant(network), other_group);
    // The verifier holds the genuine epoch-3 authority; the credential was
    // signed under a different key. It fails on the signature, not fielded off
    // as some softer mismatch.
    const auto authority = authority_with(real_group.public_key, 3, network);
    EXPECT_EQ(verify_mesh_credential(cred, authority, 2000),
              MeshCredentialFailure::SignatureInvalid);
}

TEST_F(MeshCredentialTest, TheWrongEpochAuthorityIsRefusedByName) {
    const auto network = net(0x11);
    const auto g = group();
    const auto cred = sign_credential(base_grant(network), g);
    // The verifier supplied the epoch-4 authority for an epoch-3 credential:
    // it has not walked to epoch 3's authority, so it cannot verify yet.
    const auto authority = authority_with(g.public_key, 4, network);
    EXPECT_EQ(verify_mesh_credential(cred, authority, 2000),
              MeshCredentialFailure::EpochUnavailable);
}

TEST_F(MeshCredentialTest, WrongNetworkAndExpiryAndKeyGeneration) {
    const auto network = net(0x11);
    const auto g = group();

    // Foreign network.
    auto cred = sign_credential(base_grant(network), g);
    EXPECT_EQ(verify_mesh_credential(cred, authority_with(g.public_key, 3, net(0x22)), 2000),
              MeshCredentialFailure::WrongNetwork);

    // Expired against the clock; not expired when now is zero (historical).
    auto expiring = base_grant(network);
    expiring.expires_at = 1500;
    auto expcred = sign_credential(expiring, g);
    const auto authority = authority_with(g.public_key, 3, network);
    EXPECT_EQ(verify_mesh_credential(expcred, authority, 2000), MeshCredentialFailure::Expired);
    EXPECT_EQ(verify_mesh_credential(expcred, authority, 1400), MeshCredentialFailure::None);
    EXPECT_EQ(verify_mesh_credential(expcred, authority, 0), MeshCredentialFailure::None);

    // key_generation must equal the epoch (the main authority key).
    auto wrong_gen = base_grant(network);
    wrong_gen.key_generation = 2;
    auto gencred = sign_credential(wrong_gen, g);
    EXPECT_EQ(verify_mesh_credential(gencred, authority, 2000),
              MeshCredentialFailure::KeyGenerationInvalid);
}

// A revocation is an ordinary grant with the Revoke operation, signed the same
// way and verified the same way. A verifier holding a Revoke for a subject can
// refuse that subject's issued credential — finalized authority, not a
// root-key file.
TEST_F(MeshCredentialTest, RevocationIsAMeshAuthorizedGrant) {
    const auto network = net(0x11);
    const auto g = group();
    const auto authority = authority_with(g.public_key, 3, network);

    auto revoke = base_grant(network);
    revoke.operation = CredentialOperation::Revoke;
    revoke.subject_wg_pubkey.clear();
    const auto cred = sign_credential(revoke, g);
    EXPECT_EQ(verify_mesh_credential(cred, authority, 2000), MeshCredentialFailure::None);
    EXPECT_EQ(cred.grant.operation, CredentialOperation::Revoke);
}

}  // namespace
