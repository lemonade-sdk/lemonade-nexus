#pragma once

// FakeSealer: a test double for nexus-attestd's seal and unseal, shared by the
// boot-set and storage-share tests. It is not a TPM and these tests are not
// TPM evidence.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>

#include <sodium.h>

#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace seal_test {

using nexus::security::BootPcrValues;
using nexus::security::SealBackend;
using nexus::security::SealedBlob;
using nexus::security::SealReply;
using nexus::security::SealStatus;
using nexus::security::UnsealReply;
using nexus::security::boot_pcr_digest;
using nexus::security::decode_sealed_blob;
using nexus::security::encode_sealed_blob;
using nexus::security::sealed_blob_aad;
namespace crypto = nexus::crypto;

inline BootPcrValues pcrs_of(uint8_t pcr8, uint8_t pcr9) {
    BootPcrValues values{};
    values[0].fill(pcr8);
    values[1].fill(pcr9);
    return values;
}

/// Test double for nexus-attestd's seal and unseal. It models what the store
/// and the boot set act on: the running PCR values, the binding a blob
/// carries, the TPM a blob belongs to (`owner_seed`), and tampering (a real
/// AEAD over the real blob format). It is not a TPM.
struct FakeSealer {
    BootPcrValues pcrs = pcrs_of(0x11, 0x22);
    std::string owner_seed = "owner-seed-A";
    bool reachable = true;
    bool available = true;
    int seal_calls = 0;
    int unseal_calls = 0;

    crypto::AeadKey key() const {
        crypto::AeadKey k{};
        crypto_hash_sha256(k.data(), reinterpret_cast<const uint8_t*>(owner_seed.data()),
                           owner_seed.size());
        return k;
    }

    SealBackend backend() {
        SealBackend b;
        b.seal = [this](std::string_view domain, std::span<const uint8_t> plaintext,
                        const std::optional<BootPcrValues>& target) {
            ++seal_calls;
            SealReply reply;
            if (!reachable) {
                reply.status = SealStatus::Unreachable;
                return reply;
            }
            if (!available) {
                reply.status = SealStatus::Unavailable;
                return reply;
            }
            SealedBlob blob;
            blob.domain = std::string(domain);
            blob.pcr_digest = boot_pcr_digest(target ? *target : pcrs);
            blob.tpm_public.assign(owner_seed.begin(), owner_seed.end());
            blob.tpm_private.assign(16, 0x5A);
            blob.nonce.resize(crypto::kAeadNonceSize);
            randombytes_buf(blob.nonce.data(), blob.nonce.size());
            const auto aad = sealed_blob_aad(blob.domain, blob.pcr_digest, blob.tpm_public);
            blob.ciphertext.resize(plaintext.size() + crypto::kAeadTagSize);
            unsigned long long n = 0;
            const auto k = key();
            crypto_aead_xchacha20poly1305_ietf_encrypt(blob.ciphertext.data(), &n,
                                                       plaintext.data(), plaintext.size(),
                                                       aad.data(), aad.size(), nullptr,
                                                       blob.nonce.data(), k.data());
            reply.status = SealStatus::Ok;
            reply.blob = encode_sealed_blob(blob);
            return reply;
        };
        b.unseal = [this](std::string_view domain, std::string_view text) {
            ++unseal_calls;
            UnsealReply reply;
            if (!reachable) {
                reply.status = SealStatus::Unreachable;
                return reply;
            }
            if (!available) {
                reply.status = SealStatus::Unavailable;
                return reply;
            }
            const auto blob = decode_sealed_blob(text);
            if (!blob || blob->domain != domain ||
                std::string(blob->tpm_public.begin(), blob->tpm_public.end()) != owner_seed) {
                reply.status = SealStatus::Corrupt;
                return reply;
            }
            if (blob->pcr_digest != boot_pcr_digest(pcrs)) {
                reply.status = SealStatus::PolicyMismatch;
                return reply;
            }
            const auto aad = sealed_blob_aad(blob->domain, blob->pcr_digest, blob->tpm_public);
            crypto::SecureBuffer out(blob->ciphertext.size() - crypto::kAeadTagSize);
            unsigned long long n = 0;
            const auto k = key();
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    out.data(), &n, nullptr, blob->ciphertext.data(), blob->ciphertext.size(),
                    aad.data(), aad.size(), blob->nonce.data(), k.data()) != 0) {
                reply.status = SealStatus::Corrupt;
                return reply;
            }
            reply.status = SealStatus::Ok;
            reply.plaintext = std::move(out);
            return reply;
        };
        return b;
    }
};

}  // namespace seal_test
