// The daemon owns the node's TPM. These tests pin the producer's delegation
// contract: the offer context check runs in the producer, TPM material
// crosses the seam as-is, and a daemon refusal or unset seam is a hard
// refusal with no fallback.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexus/Security/Attestation/SvsmAkEnrollment.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace nexus::security;

template <std::size_t N>
std::array<uint8_t, N> patterned(uint8_t seed) {
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) out[i] = static_cast<uint8_t>(seed + static_cast<int>(i));
    return out;
}

template <std::size_t N>
std::vector<uint8_t> patterned_vec(uint8_t seed) {
    const auto a = patterned<N>(seed);
    return {std::begin(a), std::end(a)};
}

/// A valid activation offer: every identity field matches the fixture identity,
/// and the enrollment context is the derived one the producer demands.
struct ActivationFixture {
    static const nexus::crypto::Ed25519Keypair& identity() {
        static const auto keypair = [] {
            // RFC 8032 Ed25519 test vector 1: a valid deterministic keypair,
            // so the response signature can be verified, not just produced.
            const auto pk = nexus::crypto::from_hex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            // libsodium secret key = seed || public key.
            const auto sk = nexus::crypto::from_hex(
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            nexus::crypto::Ed25519Keypair k{};
            for (std::size_t i = 0; i < 32 && i < pk.size(); ++i) k.public_key[i] = pk[i];
            for (std::size_t i = 0; i < 64 && i < sk.size(); ++i) k.private_key[i] = sk[i];
            return k;
        }();
        return keypair;
    }
    static SvsmAkActivationOfferMessage make_offer() {
        SvsmAkActivationOfferMessage offer;
        offer.network_id = patterned<32>(0x08);
        offer.subject_node.bytes = identity().public_key;
        offer.subject_key = identity().public_key;
        offer.incarnation = 3;
        offer.epoch = 9;
        offer.profile_id = kTier1AttestationProfileId;
        offer.profile_ruleset = kAttestationProfileRulesetVersion;
        std::array<uint8_t, 32> other{};
        other[0] = 0xEE;
        offer.observer.bytes = other;
        offer.ek_public = patterned_vec<200>(0x10);
        offer.ak_public = patterned_vec<200>(0x20);
        std::array<uint8_t, 32> ek_name{};
        std::array<uint8_t, 32> ak_name{};
        for (std::size_t i = 0; i < 32; ++i) {
            ek_name[i] = static_cast<uint8_t>(0x30 + i);
            ak_name[i] = static_cast<uint8_t>(0x40 + i);
        }
        offer.ek_name.assign(ek_name.begin(), ek_name.end());
        offer.ak_name.assign(ak_name.begin(), ak_name.end());
        offer.ak_spki_digest = patterned<32>(0x50);
        offer.activation.credential_blob = patterned_vec<128>(0x60);
        offer.activation.encrypted_secret = patterned_vec<64>(0x70);
        offer.activation.enrollment_context = svsm_ak_activation_offer_context(offer);
        return offer;
    }

    static EvidenceProducerSources sources() {
        EvidenceProducerSources out;
        out.identity = identity();
        out.cache_directory = ::testing::TempDir();
        out.nexus_binary_path = "/opt/nexus/bin/nexus";
        return out;
    }
};

TEST(SvsmActivationDelegation, TheOfferFieldsCrossTheSeamUnaltered) {
    const auto offer = ActivationFixture::make_offer();

    std::span<const uint8_t> seen_ek, seen_ak, seen_blob, seen_secret;

    auto sources = ActivationFixture::sources();
    const std::vector<uint8_t> secret_value = patterned_vec<32>(0xA0);
    sources.activation_source =
        [&](std::span<const uint8_t> ek, std::span<const uint8_t> ak,
            std::span<const uint8_t> blob, std::span<const uint8_t> enc,
            std::string*) -> std::optional<std::vector<uint8_t>> {
        seen_ek = ek;
        seen_ak = ak;
        seen_blob = blob;
        seen_secret = enc;
        return secret_value;
    };

    PlatformEvidenceProducer producer(sources);
    const auto response = producer.activate(offer);
    ASSERT_TRUE(response.has_value());

    EXPECT_EQ(std::vector<uint8_t>(seen_ek.begin(), seen_ek.end()), offer.ek_public);
    EXPECT_EQ(std::vector<uint8_t>(seen_ak.begin(), seen_ak.end()), offer.ak_public);
    EXPECT_EQ(std::vector<uint8_t>(seen_blob.begin(), seen_blob.end()),
              offer.activation.credential_blob);
    EXPECT_EQ(std::vector<uint8_t>(seen_secret.begin(), seen_secret.end()),
              offer.activation.encrypted_secret);
    EXPECT_EQ(response->activated_secret, secret_value);
    EXPECT_EQ(response->activation_context, offer.activation.enrollment_context);
    EXPECT_EQ(response->subject_node, offer.subject_node);
    EXPECT_EQ(response->epoch, offer.epoch);

    // The identity signature over the canonical response digest must verify
    // with the fixture key.
    const auto digest = svsm_ak_activation_response_digest(*response);
    EXPECT_EQ(crypto_sign_verify_detached(response->identity_signature.data(), digest.data(),
                                          digest.size(),
                                          ActivationFixture::identity().public_key.data()),
              0);
    // The signature binds the offer's subject key: a foreign key must not verify.
    const auto foreign = nexus::crypto::from_hex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0ea549acde6960c");
    std::array<uint8_t, 32> foreign_pk{};
    std::copy(foreign.begin(), foreign.end(), foreign_pk.begin());
    EXPECT_NE(crypto_sign_verify_detached(response->identity_signature.data(), digest.data(),
                                          digest.size(), foreign_pk.data()),
              0);
}

TEST(SvsmActivationDelegation, ARefusedActivationHasNoFallback) {
    const auto offer = ActivationFixture::make_offer();

    auto sources = ActivationFixture::sources();
    sources.activation_source =
        [](std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>,
           std::span<const uint8_t>, std::string* failure) -> std::optional<std::vector<uint8_t>> {
        if (failure) *failure = "activation_failed: the TPM ran the activation and refused it";
        return std::nullopt;
    };

    PlatformEvidenceProducer producer(sources);
    EXPECT_FALSE(producer.activate(offer).has_value());
}

TEST(SvsmActivationDelegation, AnUnsetSeamRefusesRatherThanGuessing) {
    const auto offer = ActivationFixture::make_offer();

    auto sources = ActivationFixture::sources();
    // No activation_source: the refusal must match a daemon refusal.
    PlatformEvidenceProducer producer(sources);
    EXPECT_FALSE(producer.activate(offer).has_value());
}

TEST(SvsmActivationDelegation, AForeignSubjectIsNotAnswered) {
    const auto offer = ActivationFixture::make_offer();

    auto sources = ActivationFixture::sources();
    bool called = false;
    sources.activation_source =
        [&](std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>,
            std::span<const uint8_t>,
            std::string*) -> std::optional<std::vector<uint8_t>> {
        called = true;
        return patterned_vec<32>(0xA0);
    };

    // An offer for another node must be refused before the TPM is ever asked.
    std::array<uint8_t, 32> foreign{};
    foreign[0] = 0x99;
    const auto tampered = [&] {
        auto o = offer;
        o.subject_node.bytes = foreign;
        o.subject_key = foreign;
        o.activation.enrollment_context = svsm_ak_activation_offer_context(o);
        return o;
    }();

    PlatformEvidenceProducer producer(sources);
    EXPECT_FALSE(producer.activate(tampered).has_value());
    EXPECT_FALSE(called) << "the TPM seam was reached for an offer this node did not accept";
}

TEST(SvsmActivationDelegation, AStaleEnrollmentContextIsNotAnswered) {
    const auto offer = ActivationFixture::make_offer();

    auto sources = ActivationFixture::sources();
    bool called = false;
    sources.activation_source =
        [&](std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>,
            std::span<const uint8_t>,
            std::string*) -> std::optional<std::vector<uint8_t>> {
        called = true;
        return patterned_vec<32>(0xA0);
    };

    const auto stale = [&] {
        auto o = offer;
        o.epoch = 10;
        // Do NOT recompute the context: it still binds epoch 9's offer.
        return o;
    }();

    PlatformEvidenceProducer producer(sources);
    EXPECT_FALSE(producer.activate(stale).has_value());
    EXPECT_FALSE(called);
}

}  // namespace
