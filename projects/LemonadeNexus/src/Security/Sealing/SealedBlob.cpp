#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>

#include "../AttestationDetail.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <exception>

namespace nexus::security {

namespace {

using json = nlohmann::json;

/// TPM_CC_PolicyPCR (TPM 2.0 Part 2, table 12).
constexpr uint32_t kTpmCcPolicyPcr = 0x0000017F;

void put_u32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

std::optional<Digest> parse_digest_hex(const json& value) {
    if (!value.is_string() || !detail::valid_hex(value.get<std::string>(), 2 * kDigestSize)) {
        return std::nullopt;
    }
    const auto bytes = crypto::from_hex(value.get<std::string>());
    Digest out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

/// Non-empty base64 within `maximum` bytes; an empty or oversized field is a
/// parse failure, never a default.
bool parse_bytes(const json& value, std::size_t maximum, std::vector<uint8_t>& out) {
    if (!value.is_string() || value.get<std::string>().empty()) return false;
    try {
        auto bytes = crypto::from_base64(value.get<std::string>());
        if (bytes.empty() || bytes.size() > maximum) return false;
        out = std::move(bytes);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

bool valid_seal_domain(std::string_view domain) {
    if (domain.empty() || domain.size() > kMaxSealDomainBytes) return false;
    if (domain.front() < 'a' || domain.front() > 'z') return false;
    return std::all_of(domain.begin(), domain.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    });
}

Digest boot_pcr_digest(const BootPcrValues& values) {
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    for (const auto& value : values) {
        crypto_hash_sha256_update(&state, value.data(), value.size());
    }
    Digest out{};
    crypto_hash_sha256_final(&state, out.data());
    return out;
}

std::vector<uint8_t> boot_pcr_selection_wire() {
    // TPML_PCR_SELECTION { count = 1, { hash = SHA256, sizeofSelect = 3,
    // pcrSelect = bitmap } }. Three select bytes cover PCR 0..23, the minimum
    // a PC-client TPM accepts.
    std::array<uint8_t, 3> bitmap{};
    for (const uint32_t pcr : kSvsmBootPcrs) {
        bitmap[pcr / 8] |= static_cast<uint8_t>(1u << (pcr % 8));
    }
    std::vector<uint8_t> out;
    put_u32(out, 1);
    out.push_back(static_cast<uint8_t>(kTpmAlgSha256 >> 8));
    out.push_back(static_cast<uint8_t>(kTpmAlgSha256 & 0xFF));
    out.push_back(static_cast<uint8_t>(bitmap.size()));
    out.insert(out.end(), bitmap.begin(), bitmap.end());
    return out;
}

Digest boot_pcr_policy_digest(const Digest& pcr_digest) {
    std::vector<uint8_t> input(kDigestSize, 0);  // policy sessions start at zero
    put_u32(input, kTpmCcPolicyPcr);
    const auto selection = boot_pcr_selection_wire();
    input.insert(input.end(), selection.begin(), selection.end());
    input.insert(input.end(), pcr_digest.begin(), pcr_digest.end());
    Digest out{};
    crypto_hash_sha256(out.data(), input.data(), input.size());
    return out;
}

std::vector<uint8_t> sealed_blob_aad(std::string_view domain, const Digest& pcr_digest,
                                     std::span<const uint8_t> tpm_public) {
    return crypto::aead_aad(
        crypto::aead_purpose::kSealedBlob,
        {std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(domain.data()),
                                  domain.size()),
         std::span<const uint8_t>(pcr_digest), tpm_public});
}

std::string encode_sealed_blob(const SealedBlob& blob) {
    json j;
    j["version"] = kSealedBlobFormatVersion;
    j["type"] = std::string(kSealedBlobType);
    j["domain"] = blob.domain;
    j["pcr_bank"] = "sha256";
    j["pcrs"] = json::array();
    for (const uint32_t pcr : kSvsmBootPcrs) j["pcrs"].push_back(pcr);
    j["pcr_digest"] = crypto::to_hex(blob.pcr_digest);
    j["tpm_public"] = crypto::to_base64(blob.tpm_public);
    j["tpm_private"] = crypto::to_base64(blob.tpm_private);
    j["nonce"] = crypto::to_base64(blob.nonce);
    j["ciphertext"] = crypto::to_base64(blob.ciphertext);
    return j.dump();
}

std::optional<SealedBlob> decode_sealed_blob(std::string_view text) {
    if (text.empty() || text.size() > kMaxSealedBlobBytes) return std::nullopt;
    const json j = json::parse(text, nullptr, false);
    if (j.is_discarded() ||
        !detail::exact_keys(j, {"version", "type", "domain", "pcr_bank", "pcrs", "pcr_digest",
                                "tpm_public", "tpm_private", "nonce", "ciphertext"})) {
        return std::nullopt;
    }
    if (!j["version"].is_number_unsigned() ||
        j["version"].get<uint64_t>() != kSealedBlobFormatVersion ||
        !j["type"].is_string() || j["type"].get<std::string>() != kSealedBlobType ||
        !j["pcr_bank"].is_string() || j["pcr_bank"].get<std::string>() != "sha256" ||
        !j["pcrs"].is_array() || j["pcrs"].size() != kSealPcrCount ||
        !j["domain"].is_string() || !valid_seal_domain(j["domain"].get<std::string>())) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < kSealPcrCount; ++i) {
        if (!j["pcrs"][i].is_number_unsigned() ||
            j["pcrs"][i].get<uint64_t>() != kSvsmBootPcrs[i]) {
            return std::nullopt;
        }
    }
    SealedBlob blob;
    blob.domain = j["domain"].get<std::string>();
    const auto digest = parse_digest_hex(j["pcr_digest"]);
    if (!digest) return std::nullopt;
    blob.pcr_digest = *digest;
    if (!parse_bytes(j["tpm_public"], kMaxTpmObjectBytes, blob.tpm_public) ||
        !parse_bytes(j["tpm_private"], kMaxTpmObjectBytes, blob.tpm_private) ||
        !parse_bytes(j["nonce"], crypto::kAeadNonceSize, blob.nonce) ||
        blob.nonce.size() != crypto::kAeadNonceSize ||
        !parse_bytes(j["ciphertext"], kMaxSealPlaintextBytes + crypto::kAeadTagSize,
                     blob.ciphertext) ||
        blob.ciphertext.size() <= crypto::kAeadTagSize) {
        return std::nullopt;
    }
    return blob;
}

std::optional<std::string> make_sealed_blob(std::string_view domain,
                                            const SealedKeyObject& object,
                                            std::span<const uint8_t> key,
                                            std::span<const uint8_t> plaintext) {
    if (!valid_seal_domain(domain) || key.size() != kSealKeyBytes || plaintext.empty() ||
        plaintext.size() > kMaxSealPlaintextBytes || object.tpm_public.empty() ||
        object.tpm_public.size() > kMaxTpmObjectBytes || object.tpm_private.empty() ||
        object.tpm_private.size() > kMaxTpmObjectBytes) {
        return std::nullopt;
    }
    SealedBlob blob;
    blob.domain = std::string(domain);
    blob.pcr_digest = object.pcr_digest;
    blob.tpm_public = object.tpm_public;
    blob.tpm_private = object.tpm_private;
    const auto aad = sealed_blob_aad(blob.domain, blob.pcr_digest, blob.tpm_public);
    blob.nonce.resize(crypto::kAeadNonceSize);
    randombytes_buf(blob.nonce.data(), blob.nonce.size());
    blob.ciphertext.resize(plaintext.size() + crypto::kAeadTagSize);
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            blob.ciphertext.data(), &written, plaintext.data(), plaintext.size(), aad.data(),
            aad.size(), nullptr, blob.nonce.data(), key.data()) != 0) {
        return std::nullopt;
    }
    blob.ciphertext.resize(static_cast<std::size_t>(written));
    return encode_sealed_blob(blob);
}

std::optional<crypto::SecureBuffer> open_sealed_blob(const SealedBlob& blob,
                                                     std::span<const uint8_t> key) {
    if (key.size() != kSealKeyBytes || blob.nonce.size() != crypto::kAeadNonceSize ||
        blob.ciphertext.size() <= crypto::kAeadTagSize) {
        return std::nullopt;
    }
    const auto aad = sealed_blob_aad(blob.domain, blob.pcr_digest, blob.tpm_public);
    crypto::SecureBuffer plaintext(blob.ciphertext.size() - crypto::kAeadTagSize);
    unsigned long long length = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &length, nullptr, blob.ciphertext.data(), blob.ciphertext.size(),
            aad.data(), aad.size(), blob.nonce.data(), key.data()) != 0 ||
        length != plaintext.size()) {
        return std::nullopt;
    }
    return plaintext;
}

std::optional<BootPcrValues> boot_pcrs_from_approval(const ReleaseApprovalV1& approval) {
    if (approval.expected_pcrs.size() != kSealPcrCount) return std::nullopt;
    BootPcrValues values{};
    for (std::size_t i = 0; i < kSealPcrCount; ++i) {
        const auto& [index, hex] = approval.expected_pcrs[i];
        if (index != kSvsmBootPcrs[i] || !detail::valid_hex(hex, 2 * values[i].size())) {
            return std::nullopt;
        }
        const auto bytes = crypto::from_hex(hex);
        std::copy(bytes.begin(), bytes.end(), values[i].begin());
    }
    return values;
}

}  // namespace nexus::security
