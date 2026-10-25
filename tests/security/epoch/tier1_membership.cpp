// Tier 1 membership for clients: walking the authority chain from a pinned
// Genesis key, the standalone chain page codec, and the signed endpoint proof
// that binds a member to the host and port a client reached.

#include <LemonadeNexus/Security/Epoch/Tier1Membership.hpp>
#include <LemonadeNexus/Security/Transport/AuthorityChainCodec.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include "support/tier1_chain.hpp"

using namespace nexus::security;
using tier1_chain_test::Chain;
using tier1_chain_test::new_identity;

namespace {

std::vector<nexus::crypto::Ed25519Keypair> roster(std::size_t n) {
    std::vector<nexus::crypto::Ed25519Keypair> out;
    for (std::size_t i = 0; i < n; ++i) out.push_back(new_identity());
    return out;
}

std::array<uint8_t, kTier1EndpointNonceBytes> nonce() {
    std::array<uint8_t, kTier1EndpointNonceBytes> n{};
    randombytes_buf(n.data(), n.size());
    return n;
}

struct Tier1MembershipTest : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        first = roster(5);
        second = roster(5);
        third = roster(7);
        chain = Chain::make({first, second, third});
    }

    /// Walk every page a server holding the whole chain serves.
    void walk_all(AuthorityChainWalker& walker) const {
        for (int i = 0; i < 16; ++i) {
            const auto page = chain.page_after(walker.epoch().underlying());
            if (!page) return;
            if (walker.apply(*page) != ChainPageResult::Advanced) return;
        }
    }

    std::vector<nexus::crypto::Ed25519Keypair> first, second, third;
    Chain chain;
};

}  // namespace

TEST_F(Tier1MembershipTest, TheWalkerReachesTheCurrentEpochFromGenesis) {
    AuthorityChainWalker walker(chain.genesis.public_key);
    EXPECT_EQ(walker.epoch(), 0u);
    walk_all(walker);
    ASSERT_TRUE(walker.authority().has_value());
    EXPECT_EQ(walker.epoch(), 3u);
    EXPECT_EQ(walker.authority()->members, chain.latest().members);
    EXPECT_EQ(walker.authority()->anchor_digest, chain.latest().anchor_digest);
    // Nothing newer: the same page changes nothing.
    EXPECT_EQ(walker.apply(*chain.page_after(0)), ChainPageResult::NoProgress);
}

TEST_F(Tier1MembershipTest, ThePagesSurviveTheWireForm) {
    const auto page = chain.page_after(0);
    ASSERT_TRUE(page.has_value());
    const auto bytes = encode_authority_chain_page(*page);
    ASSERT_FALSE(bytes.empty());
    const auto decoded = decode_authority_chain_page(bytes);
    ASSERT_TRUE(decoded.has_value());
    AuthorityChainWalker walker(chain.genesis.public_key);
    EXPECT_EQ(walker.apply(*decoded), ChainPageResult::Advanced);
    EXPECT_EQ(walker.epoch(), 3u);

    // Trailing bytes, truncation, and a bad base flag are refused.
    auto trailing = bytes;
    trailing.push_back(0);
    EXPECT_FALSE(decode_authority_chain_page(trailing).has_value());
    auto truncated = bytes;
    truncated.resize(truncated.size() - 1);
    EXPECT_FALSE(decode_authority_chain_page(truncated).has_value());
    auto bad_flag = bytes;
    bad_flag[0] = 2;
    EXPECT_FALSE(decode_authority_chain_page(bad_flag).has_value());
    EXPECT_FALSE(decode_authority_chain_page({}).has_value());
}

TEST_F(Tier1MembershipTest, AForgedOrForeignChainIsRefused) {
    // Another Genesis key signs a chain of its own: the pinned key refuses it.
    const auto forged = Chain::make({first, second});
    AuthorityChainWalker walker(chain.genesis.public_key);
    EXPECT_EQ(walker.apply(*forged.page_after(0)), ChainPageResult::Refused);
    EXPECT_FALSE(walker.authority().has_value());

    // A page without the base proves nothing to a walker with no authority.
    EXPECT_EQ(walker.apply(*chain.page_after(1)), ChainPageResult::Refused);

    // A tampered certificate dies on the Genesis signature.
    auto tampered = *chain.page_after(0);
    tampered.base_certificate.authority_threshold += 1;
    EXPECT_EQ(walker.apply(tampered), ChainPageResult::Refused);

    // Once verified, a different base is another chain, not a refresh.
    ASSERT_EQ(walker.apply(*chain.page_after(0)), ChainPageResult::Advanced);
    EXPECT_EQ(walker.apply(*forged.page_after(0)), ChainPageResult::Refused);
    EXPECT_EQ(walker.epoch(), 3u);
}

TEST_F(Tier1MembershipTest, ABaseForAnotherNetworkIsRefused) {
    // Signed by the pinned key, but naming a network the key does not derive.
    auto page = *chain.page_after(0);
    page.base_certificate.network_id[0] ^= 0x01;
    const Digest digest = bootstrap_certificate_signing_digest(page.base_certificate);
    crypto_sign_detached(page.base_certificate.genesis_signature.data(), nullptr, digest.data(),
                         digest.size(), chain.genesis.private_key.data());
    AuthorityChainWalker walker(chain.genesis.public_key);
    EXPECT_EQ(walker.apply(page), ChainPageResult::Refused);
}

TEST_F(Tier1MembershipTest, AForgedLinkOrAGapStopsTheWalk) {
    AuthorityChainWalker walker(chain.genesis.public_key);
    auto page = *chain.page_after(0);
    ASSERT_EQ(page.links.size(), 2u);
    // A link whose content no longer matches its proof.
    page.links[1].handoff.group_public_key[0] ^= 0x01;
    EXPECT_EQ(walker.apply(page), ChainPageResult::Refused);
    // The verified prefix stays; the forged epoch never appears.
    EXPECT_EQ(walker.epoch(), 2u);

    // A gap: epoch 3's link handed to a walker at epoch 1.
    AuthorityChainWalker fresh(chain.genesis.public_key);
    AuthorityChainPage base_only = *chain.page_after(0);
    base_only.links.clear();
    ASSERT_EQ(fresh.apply(base_only), ChainPageResult::Advanced);
    AuthorityChainPage gap;
    gap.links.push_back(chain.links[1]);
    EXPECT_EQ(fresh.apply(gap), ChainPageResult::Refused);
    EXPECT_EQ(fresh.epoch(), 1u);
}

TEST_F(Tier1MembershipTest, AValidEndpointProofBindsMemberEpochAndEndpoint) {
    const auto& authority = chain.latest();
    const auto& member = third[2];
    const auto n = nonce();
    const auto proof = sign_tier1_endpoint_proof(chain.network, authority.epoch,
                                                 "t1.example.net", 9100, n, member);
    EXPECT_EQ(check_tier1_endpoint_proof(authority, proof, "t1.example.net", 9100, n),
              EndpointProofCheck::Valid);
    // Host names compare case-insensitively.
    EXPECT_EQ(check_tier1_endpoint_proof(authority, proof, "T1.Example.NET", 9100, n),
              EndpointProofCheck::Valid);
}

TEST_F(Tier1MembershipTest, EveryWrongEndpointProofIsRefusedByName) {
    const auto& authority = chain.latest();
    const auto n = nonce();
    const auto proof_for = [&](const nexus::crypto::Ed25519Keypair& who, uint64_t epoch,
                               const std::string& host, uint16_t port) {
        return sign_tier1_endpoint_proof(chain.network, EpochId{epoch}, host, port, n, who);
    };

    // A server outside the verified membership (a Tier 2 server).
    const auto outsider = new_identity();
    EXPECT_EQ(check_tier1_endpoint_proof(authority, proof_for(outsider, 3, "t2.example", 9100),
                                         "t2.example", 9100, n),
              EndpointProofCheck::NotMember);
    // A member of an earlier epoch only.
    EXPECT_EQ(check_tier1_endpoint_proof(authority, proof_for(first[0], 3, "old.example", 9100),
                                         "old.example", 9100, n),
              EndpointProofCheck::NotMember);
    // A member that is behind, or ahead of, the verified epoch.
    EXPECT_EQ(check_tier1_endpoint_proof(authority, proof_for(third[0], 2, "t1.example", 9100),
                                         "t1.example", 9100, n),
              EndpointProofCheck::OlderEpoch);
    EXPECT_EQ(check_tier1_endpoint_proof(authority, proof_for(third[0], 4, "t1.example", 9100),
                                         "t1.example", 9100, n),
              EndpointProofCheck::NewerEpoch);
    // A genuine proof relayed by another host, or for another port.
    const auto genuine = proof_for(third[0], 3, "t1.example", 9100);
    EXPECT_EQ(check_tier1_endpoint_proof(authority, genuine, "relay.example", 9100, n),
              EndpointProofCheck::WrongEndpoint);
    EXPECT_EQ(check_tier1_endpoint_proof(authority, genuine, "t1.example", 9200, n),
              EndpointProofCheck::WrongEndpoint);
    // A replay against a new nonce, a tampered claim, and a short nonce.
    const auto other_nonce = nonce();
    EXPECT_EQ(check_tier1_endpoint_proof(authority, genuine, "t1.example", 9100, other_nonce),
              EndpointProofCheck::BadSignature);
    auto tampered = genuine;
    tampered.host = "evil.example";
    EXPECT_EQ(check_tier1_endpoint_proof(authority, tampered, "evil.example", 9100, n),
              EndpointProofCheck::BadSignature);
    const std::array<uint8_t, 16> short_nonce{};
    EXPECT_EQ(check_tier1_endpoint_proof(authority, genuine, "t1.example", 9100, short_nonce),
              EndpointProofCheck::BadNonce);
    // A signature by another key over the member's claim.
    auto stolen = genuine;
    stolen.signature = proof_for(outsider, 3, "t1.example", 9100).signature;
    EXPECT_EQ(check_tier1_endpoint_proof(authority, stolen, "t1.example", 9100, n),
              EndpointProofCheck::BadSignature);
}
