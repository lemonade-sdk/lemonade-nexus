#include <LemonadeNexusAttestd/AttestdCodec.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidence.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iterator>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace nexus::attestd {

namespace {

using json = nlohmann::json;

/// The complete request grammar. Anything outside this list is a refusal, so a
/// caller cannot append a "qualifying_data" or "pcr_selection" key and have an
/// older daemon ignore it into acceptance.
constexpr std::string_view kChallengeKeys[] = {
    "version",       "type",          "network_id",       "nonce",
    "node_id",       "node_key",      "incarnation",      "epoch",
    "security_ruleset", "consensus_ruleset", "profile_id", "profile_ruleset",
    "policy_digest", "purpose",       "context_digest",
    "ima_mode", "ima_checkpoint_digest", "ima_prior_event_count",
    "ima_prior_pcr10", "ima_checkpoint_paths",
};

[[nodiscard]] std::string hex_of(std::span<const uint8_t> bytes) { return crypto::to_hex(bytes); }

/// Fixed-width hex into a fixed-width array. A short or long value is a refusal,
/// never a silent truncation.
template <std::size_t N>
[[nodiscard]] bool read_hex(const json& value, std::array<uint8_t, N>& out) {
    if (!value.is_string()) return false;
    try {
        const auto bytes = crypto::from_hex(value.get<std::string>());
        if (bytes.size() != N) return false;
        std::copy(bytes.begin(), bytes.end(), out.begin());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

template <typename T>
[[nodiscard]] bool read_uint(const json& value, T& out) {
    if (!value.is_number_unsigned()) return false;
    const auto raw = value.get<uint64_t>();
    if (raw > static_cast<uint64_t>(std::numeric_limits<T>::max())) return false;
    out = static_cast<T>(raw);
    return true;
}

template <typename Tag>
[[nodiscard]] bool read_uint(const json& value, security::StrongId<Tag>& out) {
    uint64_t raw = 0;
    if (!read_uint(value, raw)) return false;
    out = raw;
    return true;
}

/// Only the purposes the protocol defines. An unknown value is refused rather
/// than defaulting into Eligibility, which is the weaker context.
[[nodiscard]] bool read_purpose(const json& value, security::AttestationPurpose& out) {
    uint16_t raw = 0;
    if (!read_uint(value, raw)) return false;
    switch (static_cast<security::AttestationPurpose>(raw)) {
        case security::AttestationPurpose::Eligibility:
        case security::AttestationPurpose::FinalEpochReadiness:
        case security::AttestationPurpose::PlatformEnrollment:
        case security::AttestationPurpose::StorageUnlock:
            out = static_cast<security::AttestationPurpose>(raw);
            return true;
    }
    return false;
}

}  // namespace

std::optional<security::AttestationChallenge> decode_challenge(std::string_view text) {
    if (text.empty() || text.size() > kMaxRequestBytes) return std::nullopt;

    json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;

    // Closed grammar. Checked before any field is read, so an unknown key can
    // never influence a field that was read first.
    for (const auto& [key, unused] : j.items()) {
        (void)unused;
        const bool known = std::any_of(std::begin(kChallengeKeys), std::end(kChallengeKeys),
                                       [&key](std::string_view k) { return k == key; });
        if (!known) return std::nullopt;
    }
    for (std::string_view key : kChallengeKeys) {
        if (!j.contains(std::string(key))) return std::nullopt;
    }

    if (!j["version"].is_number_integer() || j["version"].get<int>() != kAttestdWireVersion) {
        return std::nullopt;
    }
    if (!j["type"].is_string() || j["type"].get<std::string>() != kRequestType) {
        return std::nullopt;
    }

    security::AttestationChallenge c;
    uint16_t profile_id_raw = 0;
    if (!read_hex(j["network_id"], c.network_id)) return std::nullopt;
    if (!read_hex(j["nonce"], c.nonce)) return std::nullopt;
    if (!read_hex(j["node_id"], c.node_id.bytes)) return std::nullopt;
    if (!read_hex(j["node_key"], c.node_key)) return std::nullopt;
    if (!read_uint(j["incarnation"], c.incarnation)) return std::nullopt;
    if (!read_uint(j["epoch"], c.epoch)) return std::nullopt;
    if (!read_uint(j["security_ruleset"], c.security_ruleset)) return std::nullopt;
    if (!read_uint(j["consensus_ruleset"], c.consensus_ruleset)) return std::nullopt;
    if (!read_uint(j["profile_id"], profile_id_raw)) return std::nullopt;
    if (!read_uint(j["profile_ruleset"], c.profile_ruleset)) return std::nullopt;
    if (!read_hex(j["policy_digest"], c.policy_digest)) return std::nullopt;
    if (!read_purpose(j["purpose"], c.purpose)) return std::nullopt;
    if (!read_hex(j["context_digest"], c.context_digest)) return std::nullopt;
    uint16_t mode = 0;
    if (!read_uint(j["ima_mode"], mode) ||
        (mode != static_cast<uint16_t>(security::ImaEvidenceMode::Full) &&
         mode != static_cast<uint16_t>(security::ImaEvidenceMode::Resume))) return std::nullopt;
    c.ima_mode = static_cast<security::ImaEvidenceMode>(mode);
    if (!read_hex(j["ima_checkpoint_digest"], c.ima_checkpoint_digest) ||
        !read_uint(j["ima_prior_event_count"], c.ima_prior_event_count) ||
        !read_hex(j["ima_prior_pcr10"], c.ima_prior_pcr10) ||
        !j["ima_checkpoint_paths"].is_array() ||
        j["ima_checkpoint_paths"].size() > security::constants::kMaxSummarisedPaths)
        return std::nullopt;
    for (const auto& item : j["ima_checkpoint_paths"]) {
        if (!item.is_object() || item.size() != 2 || !item.contains("path") ||
            !item.contains("sha256") || !item["path"].is_string() ||
            !item["sha256"].is_string() || item["path"].get<std::string>().size() > 4096 ||
            item["sha256"].get<std::string>().size() != 64) return std::nullopt;
        c.ima_checkpoint_paths.push_back({item["path"].get<std::string>(),
                                          item["sha256"].get<std::string>()});
    }

    // An ID no compiled provider names stays Unknown, which check_challenge
    // refuses. Parsing it faithfully keeps the diagnosis honest.
    c.profile_id = security::is_known_attestation_profile_id(
                       static_cast<security::AttestationProfileId>(profile_id_raw))
                       ? static_cast<security::AttestationProfileId>(profile_id_raw)
                       : security::AttestationProfileId::Unknown;
    return c;
}

namespace {

/// The complete activation request grammar. Same closed-grammar rule as the
/// challenge: unknown keys are a refusal, so a caller cannot append a field an
/// older daemon would silently ignore.
constexpr std::string_view kActivationKeys[] = {
    "version", "type", "ek_public", "ak_public", "credential_blob", "encrypted_secret",
};

/// base64 into a bounded field. An empty field is a refusal — an empty
/// TPM2B_PUBLIC is not a key.
[[nodiscard]] bool read_activation_field(const json& value, std::vector<uint8_t>& out) {
    if (!value.is_string() || value.get<std::string>().empty()) return false;
    try {
        auto bytes = crypto::from_base64(value.get<std::string>());
        if (bytes.empty() || bytes.size() > kMaxActivationFieldBytes) return false;
        out = std::move(bytes);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

std::optional<SvsmAkActivationRequest> decode_activation_request(std::string_view text) {
    if (text.empty() || text.size() > kMaxRequestBytes) return std::nullopt;

    json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;

    for (const auto& [key, unused] : j.items()) {
        (void)unused;
        const bool known = std::any_of(std::begin(kActivationKeys), std::end(kActivationKeys),
                                       [&key](std::string_view k) { return k == key; });
        if (!known) return std::nullopt;
    }
    for (std::string_view key : kActivationKeys) {
        if (!j.contains(std::string(key))) return std::nullopt;
    }

    if (!j["version"].is_number_integer() || j["version"].get<int>() != kAttestdWireVersion) {
        return std::nullopt;
    }
    if (!j["type"].is_string() || j["type"].get<std::string>() != kActivationRequestType) {
        return std::nullopt;
    }

    SvsmAkActivationRequest request;
    if (!read_activation_field(j["ek_public"], request.ek_public) ||
        !read_activation_field(j["ak_public"], request.ak_public) ||
        !read_activation_field(j["credential_blob"], request.credential_blob) ||
        !read_activation_field(j["encrypted_secret"], request.encrypted_secret)) {
        return std::nullopt;
    }
    return request;
}

std::string encode_activation_request(const SvsmAkActivationRequest& request) {
    json j;
    j["version"] = kAttestdWireVersion;
    j["type"] = std::string(kActivationRequestType);
    j["ek_public"] = crypto::to_base64(request.ek_public);
    j["ak_public"] = crypto::to_base64(request.ak_public);
    j["credential_blob"] = crypto::to_base64(request.credential_blob);
    j["encrypted_secret"] = crypto::to_base64(request.encrypted_secret);
    return j.dump() + "\n";
}

// --- seal / unseal ----------------------------------------------------------

namespace {

constexpr std::string_view kSealKeys[] = {"version", "type", "domain", "target"};
constexpr std::string_view kUnsealKeys[] = {"version",    "type",       "domain",
                                            "pcr_digest", "tpm_public", "tpm_private"};
constexpr std::string_view kSealResultKeys[] = {"version",    "type",        "pcr_digest",
                                                "tpm_public", "tpm_private", "key"};
constexpr std::string_view kUnsealResultKeys[] = {"version", "type", "key"};

/// The exact key set, checked before any field is read.
[[nodiscard]] bool has_exact_keys(const json& j, std::span<const std::string_view> keys) {
    if (!j.is_object() || j.size() != keys.size()) return false;
    return std::all_of(keys.begin(), keys.end(),
                       [&j](std::string_view key) { return j.contains(std::string(key)); });
}

[[nodiscard]] bool has_version_and_type(const json& j, std::string_view type) {
    return j["version"].is_number_integer() && j["version"].get<int>() == kAttestdWireVersion &&
           j["type"].is_string() && j["type"].get<std::string>() == type;
}

[[nodiscard]] bool lower_hex(const std::string& text, std::size_t length) {
    return text.size() == length && std::all_of(text.begin(), text.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

/// Lowercase hex only, so one value has one spelling on the wire.
template <std::size_t N>
[[nodiscard]] bool read_lower_hex(const json& value, std::array<uint8_t, N>& out) {
    return value.is_string() && lower_hex(value.get_ref<const std::string&>(), 2 * N) &&
           read_hex(value, out);
}

/// Non-empty base64 within `maximum` bytes.
[[nodiscard]] bool read_b64(const json& value, std::size_t maximum, std::vector<uint8_t>& out) {
    if (!value.is_string() || value.get_ref<const std::string&>().empty()) return false;
    try {
        auto bytes = crypto::from_base64(value.get<std::string>());
        if (bytes.empty() || bytes.size() > maximum) return false;
        out = std::move(bytes);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

/// Overwrite a string's characters in place before it is released.
void wipe(std::string& text) {
    if (!text.empty()) sodium_memzero(text.data(), text.size());
}

/// A kSealKeyBytes key from a base64 field, into guarded memory. The encoded
/// field is wiped either way.
[[nodiscard]] bool take_key(json& value, crypto::SecureBuffer& out) {
    if (!value.is_string()) return false;
    auto& encoded = value.get_ref<std::string&>();
    std::vector<uint8_t> bytes;
    try {
        bytes = crypto::from_base64(encoded);
    } catch (const std::exception&) {
        bytes.clear();
    }
    wipe(encoded);
    const bool sized = bytes.size() == security::kSealKeyBytes;
    if (sized) out = crypto::SecureBuffer(bytes);
    if (!bytes.empty()) sodium_memzero(bytes.data(), bytes.size());
    return sized;
}

[[nodiscard]] bool emit_wiped(json& j, const FrameSink& sink) {
    std::string payload = j.dump();
    wipe(j["key"].get_ref<std::string&>());
    std::string frame = encode_frame(FrameKind::Result, payload);
    wipe(payload);
    const bool sent = !frame.empty() && sink(frame);
    wipe(frame);
    return sent;
}

}  // namespace

std::optional<SealRequest> decode_seal_request(std::string_view text) {
    if (text.empty() || text.size() > kMaxRequestBytes) return std::nullopt;
    const json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !has_exact_keys(j, kSealKeys) ||
        !has_version_and_type(j, kSealRequestType) || !j["domain"].is_string() ||
        !security::valid_seal_domain(j["domain"].get<std::string>())) {
        return std::nullopt;
    }
    SealRequest request;
    request.domain = j["domain"].get<std::string>();
    const json& target = j["target"];
    if (target.is_string()) {
        if (target.get<std::string>() != "current") return std::nullopt;
        return request;
    }
    constexpr std::string_view kTargetKeys[] = {"pcr8", "pcr9"};
    static_assert(std::size(kTargetKeys) == security::kSealPcrCount);
    if (!has_exact_keys(target, kTargetKeys)) return std::nullopt;
    security::BootPcrValues values{};
    if (!read_lower_hex(target["pcr8"], values[0]) || !read_lower_hex(target["pcr9"], values[1])) {
        return std::nullopt;
    }
    request.target = values;
    return request;
}

std::string encode_seal_request(const SealRequest& request) {
    json j;
    j["version"] = kAttestdWireVersion;
    j["type"] = std::string(kSealRequestType);
    j["domain"] = request.domain;
    if (request.target) {
        j["target"] = {{"pcr8", hex_of((*request.target)[0])},
                       {"pcr9", hex_of((*request.target)[1])}};
    } else {
        j["target"] = "current";
    }
    return j.dump() + "\n";
}

std::optional<UnsealRequest> decode_unseal_request(std::string_view text) {
    if (text.empty() || text.size() > kMaxRequestBytes) return std::nullopt;
    const json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !has_exact_keys(j, kUnsealKeys) ||
        !has_version_and_type(j, kUnsealRequestType) || !j["domain"].is_string() ||
        !security::valid_seal_domain(j["domain"].get<std::string>())) {
        return std::nullopt;
    }
    UnsealRequest request;
    request.domain = j["domain"].get<std::string>();
    if (!read_lower_hex(j["pcr_digest"], request.object.pcr_digest) ||
        !read_b64(j["tpm_public"], security::kMaxTpmObjectBytes, request.object.tpm_public) ||
        !read_b64(j["tpm_private"], security::kMaxTpmObjectBytes, request.object.tpm_private)) {
        return std::nullopt;
    }
    return request;
}

std::string encode_unseal_request(const UnsealRequest& request) {
    json j;
    j["version"] = kAttestdWireVersion;
    j["type"] = std::string(kUnsealRequestType);
    j["domain"] = request.domain;
    j["pcr_digest"] = hex_of(request.object.pcr_digest);
    j["tpm_public"] = crypto::to_base64(request.object.tpm_public);
    j["tpm_private"] = crypto::to_base64(request.object.tpm_private);
    return j.dump() + "\n";
}

bool emit_seal_result(const security::SealedKeyObject& object, std::span<const uint8_t> key,
                      const FrameSink& sink) {
    json j;
    j["version"] = kAttestdWireVersion;
    j["type"] = std::string(kSealResultType);
    j["pcr_digest"] = hex_of(object.pcr_digest);
    j["tpm_public"] = crypto::to_base64(object.tpm_public);
    j["tpm_private"] = crypto::to_base64(object.tpm_private);
    j["key"] = crypto::to_base64(key);
    return emit_wiped(j, sink);
}

bool emit_unseal_result(std::span<const uint8_t> key, const FrameSink& sink) {
    json j;
    j["version"] = kAttestdWireVersion;
    j["type"] = std::string(kUnsealResultType);
    j["key"] = crypto::to_base64(key);
    return emit_wiped(j, sink);
}

bool emit_bundle(const PlatformEvidenceBundle& bundle, const FrameSink& sink) {
    const std::string evidence = security::encode_platform_evidence(bundle.platform);

    // Refuse before emitting: a Header already sent commits the stream to a
    // length the chunk budget cannot deliver.
    const std::size_t chunks =
        (evidence.size() + kMaxLocalFrameBytes - 1) / kMaxLocalFrameBytes;
    if (chunks > kMaxLocalChunks) return false;

    json head;
    head["version"] = kAttestdWireVersion;
    head["type"] = std::string(kBundleType);
    // The digest the platform evidence is bound to. The caller recomputes it
    // from its own challenge and refuses a mismatch; it is echoed so that
    // refusal is cheap rather than a silent verification failure later.
    head["challenge_digest"] = hex_of(bundle.challenge_digest);
    head["platform_bytes"] = evidence.size();
    if (!sink(encode_frame(FrameKind::Header, head.dump()))) return false;

    for (std::size_t at = 0; at < evidence.size(); at += kMaxLocalFrameBytes) {
        const auto span = std::min(kMaxLocalFrameBytes, evidence.size() - at);
        if (!sink(encode_frame(FrameKind::EvidenceChunk,
                               std::string_view(evidence).substr(at, span)))) {
            return false;
        }
    }

    // End commits to what was sent, so a reader that reassembles anything else
    // finds out here rather than inside a JSON parser.
    std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), reinterpret_cast<const uint8_t*>(evidence.data()),
                       evidence.size());
    json end;
    end["chunks"] = chunks;
    end["platform_sha256"] = hex_of(digest);
    return sink(encode_frame(FrameKind::End, end.dump()));
}

bool emit_activation_result(const std::vector<uint8_t>& activated_secret, const FrameSink& sink) {
    json j;
    j["version"] = kAttestdWireVersion;
    j["type"] = std::string(kActivationResultType);
    j["activated_secret"] = hex_of(activated_secret);
    return sink(encode_frame(FrameKind::Result, j.dump()));
}

bool emit_refusal(Refusal refusal, const FrameSink& sink, std::string_view detail) {
    json j;
    j["version"] = kAttestdWireVersion;
    j["type"] = std::string(kRefusalType);
    j["refusal"] = std::string(refusal_name(refusal));
    j["code"] = static_cast<uint16_t>(refusal);
    j["reason"] = std::string(refusal_reason(refusal));
    if (!detail.empty()) j["detail"] = std::string(detail);
    return sink(encode_frame(FrameKind::Refusal, j.dump()));
}

// --- reassembly ------------------------------------------------------------

bool ResponseAssembler::fail(FrameError e) {
    error_ = e;
    done_ = false;
    return false;
}

bool ResponseAssembler::offer(FrameKind kind, std::string_view payload) {
    if (done_ || error_ != FrameError::None) return fail(FrameError::Malformed);
    if (payload.size() > kMaxLocalFrameBytes) return fail(FrameError::Oversized);

    // Frame headers count too: the bound is on the operation.
    accepted_ += kFrameHeaderBytes + payload.size();
    if (accepted_ > kMaxLocalResponseBytes) return fail(FrameError::TooLarge);

    json j;
    if (kind != FrameKind::EvidenceChunk) {
        j = json::parse(payload, nullptr, false);
        if (j.is_discarded() || !j.is_object()) return fail(FrameError::Malformed);
    }

    switch (kind) {
        case FrameKind::Refusal: {
            if (header_seen_) return fail(FrameError::Malformed);
            if (!j.contains("code") || !j["code"].is_number_unsigned()) {
                return fail(FrameError::Malformed);
            }
            refusal_ = static_cast<Refusal>(j["code"].get<uint16_t>());
            if (refusal_name(refusal_) == "unknown") return fail(FrameError::Malformed);
            if (j.contains("detail") && j["detail"].is_string()) {
                detail_ = j["detail"].get<std::string>();
            }
            done_ = true;
            return false;  // over, and carrying no bundle
        }

        case FrameKind::Header: {
            if (header_seen_) return fail(FrameError::Malformed);
            if (!j.contains("version") || !j["version"].is_number_integer() ||
                j["version"].get<int>() != kAttestdWireVersion) {
                return fail(FrameError::Malformed);
            }
            if (!j.contains("type") || !j["type"].is_string() ||
                j["type"].get<std::string>() != kBundleType) {
                return fail(FrameError::Malformed);
            }
            if (!j.contains("platform_bytes") || !j["platform_bytes"].is_number_unsigned()) {
                return fail(FrameError::Malformed);
            }
            declared_bytes_ = j["platform_bytes"].get<std::size_t>();
            if (declared_bytes_ > kMaxLocalFrameBytes * kMaxLocalChunks) {
                return fail(FrameError::TooLarge);
            }
            std::array<uint8_t, security::kDigestSize> digest{};
            if (!j.contains("challenge_digest") || !j["challenge_digest"].is_string()) {
                return fail(FrameError::Malformed);
            }
            try {
                const auto bytes = crypto::from_hex(j["challenge_digest"].get<std::string>());
                if (bytes.size() != digest.size()) return fail(FrameError::Malformed);
                std::copy(bytes.begin(), bytes.end(), challenge_digest_.begin());
            } catch (const std::exception&) {
                return fail(FrameError::Malformed);
            }
            evidence_.reserve(declared_bytes_);
            header_seen_ = true;
            return true;
        }

        case FrameKind::EvidenceChunk: {
            if (!header_seen_) return fail(FrameError::Malformed);
            if (++chunks_ > kMaxLocalChunks) return fail(FrameError::TooManyChunks);
            if (evidence_.size() + payload.size() > declared_bytes_) {
                return fail(FrameError::TooLarge);
            }
            evidence_.append(payload);
            return true;
        }

        case FrameKind::End: {
            if (!header_seen_) return fail(FrameError::Malformed);
            if (!j.contains("platform_sha256") || !j["platform_sha256"].is_string()) {
                return fail(FrameError::Malformed);
            }
            declared_digest_ = j["platform_sha256"].get<std::string>();
            done_ = true;
            return false;  // complete
        }

        case FrameKind::Result: {
            // One frame, same position Refusal holds: before any other frame.
            if (header_seen_) return fail(FrameError::Malformed);
            if (!j.contains("version") || !j["version"].is_number_integer() ||
                j["version"].get<int>() != kAttestdWireVersion) {
                return fail(FrameError::Malformed);
            }
            if (!j.contains("type") || !j["type"].is_string()) return fail(FrameError::Malformed);
            const std::string type = j["type"].get<std::string>();
            if (type == kSealResultType) {
                security::SealedKeyObject object;
                const bool shaped =
                    has_exact_keys(j, kSealResultKeys) &&
                    read_lower_hex(j["pcr_digest"], object.pcr_digest) &&
                    read_b64(j["tpm_public"], security::kMaxTpmObjectBytes, object.tpm_public) &&
                    read_b64(j["tpm_private"], security::kMaxTpmObjectBytes, object.tpm_private);
                crypto::SecureBuffer key;
                const bool keyed = j.contains("key") && take_key(j["key"], key);
                if (!shaped || !keyed) return fail(FrameError::Malformed);
                result_type_ = type;
                result_object_ = std::move(object);
                result_key_ = std::move(key);
                done_ = true;
                return false;  // over, carrying a sealed key
            }
            if (type == kUnsealResultType) {
                crypto::SecureBuffer key;
                const bool keyed = j.contains("key") && take_key(j["key"], key);
                if (!has_exact_keys(j, kUnsealResultKeys) || !keyed) {
                    return fail(FrameError::Malformed);
                }
                result_type_ = type;
                result_key_ = std::move(key);
                done_ = true;
                return false;  // over, carrying an unsealed key
            }
            if (type != kActivationResultType) return fail(FrameError::Malformed);
            if (!j.contains("activated_secret") || !j["activated_secret"].is_string() ||
                j["activated_secret"].get<std::string>().size() != 2 * security::kDigestSize) {
                return fail(FrameError::Malformed);
            }
            try {
                result_secret_ = crypto::from_hex(j["activated_secret"].get<std::string>());
            } catch (const std::exception&) {
                return fail(FrameError::Malformed);
            }
            done_ = true;
            return false;  // over, carrying a result
        }
    }
    return fail(FrameError::Malformed);
}

std::optional<security::SealedKeyObject> ResponseAssembler::result_object() const {
    if (!done_ || error_ != FrameError::None || result_type_ != kSealResultType) {
        return std::nullopt;
    }
    return result_object_;
}

bool ResponseAssembler::has_result_key() const {
    return done_ && error_ == FrameError::None &&
           (result_type_ == kSealResultType || result_type_ == kUnsealResultType) &&
           !result_key_.empty();
}

crypto::SecureBuffer ResponseAssembler::take_result_key() {
    if (!has_result_key()) return {};
    return std::move(result_key_);
}

std::optional<std::vector<uint8_t>> ResponseAssembler::result_secret() const {
    if (!done_ || error_ != FrameError::None || result_secret_.empty()) return std::nullopt;
    return result_secret_;
}

bool ResponseAssembler::finish(PlatformEvidenceBundle& out) {
    if (!done_ || refusal_ != Refusal::None || !header_seen_) return false;
    if (evidence_.size() != declared_bytes_) {
        error_ = FrameError::Truncated;
        return false;
    }

    std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), reinterpret_cast<const uint8_t*>(evidence_.data()),
                       evidence_.size());
    if (hex_of(digest) != declared_digest_) {
        error_ = FrameError::Malformed;
        return false;
    }

    auto platform = security::decode_platform_evidence(evidence_);
    if (!platform) {
        error_ = FrameError::Malformed;
        return false;
    }
    out.challenge_digest = challenge_digest_;
    out.platform = std::move(*platform);
    return true;
}

}  // namespace nexus::attestd
