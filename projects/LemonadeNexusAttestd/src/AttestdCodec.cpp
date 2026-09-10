#include <LemonadeNexusAttestd/AttestdCodec.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
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

/// Only the two purposes the protocol defines. An unknown value is refused
/// rather than defaulting into Eligibility, which is the weaker context.
[[nodiscard]] bool read_purpose(const json& value, security::AttestationPurpose& out) {
    uint16_t raw = 0;
    if (!read_uint(value, raw)) return false;
    switch (static_cast<security::AttestationPurpose>(raw)) {
        case security::AttestationPurpose::Eligibility:
        case security::AttestationPurpose::FinalEpochReadiness:
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

    // An ID no compiled provider names stays Unknown, which check_challenge
    // refuses. Parsing it faithfully keeps the diagnosis honest.
    c.profile_id = security::is_known_attestation_profile_id(
                       static_cast<security::AttestationProfileId>(profile_id_raw))
                       ? static_cast<security::AttestationProfileId>(profile_id_raw)
                       : security::AttestationProfileId::Unknown;
    return c;
}

bool emit_bundle(const PlatformEvidenceBundle& bundle, const FrameSink& sink) {
    const std::string evidence = security::encode_snp_vtpm_evidence(bundle.platform);

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
            if (refusal_name(refusal_) == "Unknown") return fail(FrameError::Malformed);
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
    }
    return fail(FrameError::Malformed);
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

    auto platform = security::decode_snp_vtpm_evidence(evidence_);
    if (!platform) {
        error_ = FrameError::Malformed;
        return false;
    }
    out.challenge_digest = challenge_digest_;
    out.platform = std::move(*platform);
    return true;
}

}  // namespace nexus::attestd
