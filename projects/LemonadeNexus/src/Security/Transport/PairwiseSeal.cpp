#include <LemonadeNexus/Security/Transport/PairwiseSeal.hpp>

#include <sodium.h>

namespace nexus::security {

PairwiseSealer::PairwiseSealer(const crypto::Ed25519PrivateKey& own_identity_key)
    : secret_key_(crypto_scalarmult_curve25519_BYTES) {
    if (sodium_init() < 0) {
        return;
    }
    crypto::Ed25519PublicKey ed_public{};
    std::copy(own_identity_key.begin() + crypto::kEd25519SeedSize, own_identity_key.end(),
              ed_public.begin());
    if (crypto_sign_ed25519_sk_to_curve25519(secret_key_.data(), own_identity_key.data()) != 0 ||
        crypto_sign_ed25519_pk_to_curve25519(public_key_.data(), ed_public.data()) != 0) {
        secret_key_.clear();
    }
}

std::size_t PairwiseSealer::overhead() { return crypto_box_SEALBYTES; }

std::optional<std::vector<uint8_t>> PairwiseSealer::seal_for(
    const NodeId& recipient, std::span<const uint8_t> plaintext) const {
    crypto::X25519PublicKey recipient_key{};
    if (crypto_sign_ed25519_pk_to_curve25519(recipient_key.data(), recipient.bytes.data()) != 0) {
        return std::nullopt;
    }
    std::vector<uint8_t> out(plaintext.size() + crypto_box_SEALBYTES);
    if (crypto_box_seal(out.data(), plaintext.data(), plaintext.size(), recipient_key.data()) !=
        0) {
        return std::nullopt;
    }
    return out;
}

std::optional<std::vector<uint8_t>> PairwiseSealer::unseal(
    std::span<const uint8_t> ciphertext) const {
    if (secret_key_.empty() || ciphertext.size() < crypto_box_SEALBYTES) {
        return std::nullopt;
    }
    std::vector<uint8_t> out(ciphertext.size() - crypto_box_SEALBYTES);
    if (crypto_box_seal_open(out.data(), ciphertext.data(), ciphertext.size(),
                             public_key_.data(), secret_key_.data()) != 0) {
        return std::nullopt;
    }
    return out;
}

}  // namespace nexus::security
