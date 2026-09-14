#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace nexus::security {

namespace {

using json = nlohmann::json;

[[nodiscard]] std::string b64(std::span<const uint8_t> bytes) {
    return crypto::to_base64(bytes);
}

// Every reader returns false on a missing, mistyped, or malformed field. The
// caller then discards the whole document.
[[nodiscard]] bool read_u64(const json& object, const char* key, uint64_t& out) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_number_unsigned()) return false;
    out = it->get<uint64_t>();
    return true;
}

[[nodiscard]] bool read_u16(const json& object, const char* key, uint16_t& out) {
    uint64_t value = 0;
    if (!read_u64(object, key, value) || value > 0xFFFF) return false;
    out = static_cast<uint16_t>(value);
    return true;
}

[[nodiscard]] bool read_u32(const json& object, const char* key, uint32_t& out) {
    uint64_t value = 0;
    if (!read_u64(object, key, value) || value > 0xFFFFFFFFu) return false;
    out = static_cast<uint32_t>(value);
    return true;
}

template <std::size_t N>
[[nodiscard]] bool read_b64(const json& object, const char* key, std::array<uint8_t, N>& out) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) return false;
    std::vector<uint8_t> decoded;
    try {
        decoded = crypto::from_base64(it->get<std::string>());
    } catch (...) {
        return false;
    }
    if (decoded.size() != N) return false;
    std::copy(decoded.begin(), decoded.end(), out.begin());
    return true;
}

[[nodiscard]] json qc_to_json(const QuorumCertificate& certificate) {
    json signers = json::array();
    for (const auto& signer : certificate.signers) {
        signers.push_back({{"node_id", b64(signer.node_id.span())},
                           {"signature", b64(signer.signature)}});
    }
    return json{{"qc_format_version", certificate.qc_format_version},
                {"consensus_ruleset", certificate.consensus_ruleset},
                {"network_id", b64(certificate.network_id)},
                {"epoch", certificate.epoch},
                {"height", certificate.height},
                {"view", certificate.view},
                {"proposal_digest", b64(certificate.proposal_digest)},
                {"signers", std::move(signers)}};
}

// The store record is closed: an unexpected key means the file is not what
// this binary writes and must not be acted on.
[[nodiscard]] bool has_unknown_key(const json& object, std::initializer_list<const char*> expected) {
    for (const auto& [key, value] : object.items()) {
        (void)value;
        bool known = false;
        for (const auto* name : expected) {
            if (key == name) {
                known = true;
                break;
            }
        }
        if (!known) return true;
    }
    return false;
}

[[nodiscard]] bool qc_from_json(const json& object, QuorumCertificate& out) {
    if (!object.is_object()) return false;
    if (has_unknown_key(object, {"qc_format_version", "consensus_ruleset", "network_id", "epoch",
                                 "height", "view", "proposal_digest", "signers"})) {
        return false;
    }

    QuorumCertificate certificate{};
    if (!read_u16(object, "qc_format_version", certificate.qc_format_version)) return false;
    if (!read_u16(object, "consensus_ruleset", certificate.consensus_ruleset)) return false;
    if (!read_b64(object, "network_id", certificate.network_id)) return false;
    if (!read_u64(object, "epoch", certificate.epoch)) return false;
    if (!read_u64(object, "height", certificate.height)) return false;
    if (!read_u64(object, "view", certificate.view)) return false;
    if (!read_b64(object, "proposal_digest", certificate.proposal_digest)) return false;

    const auto signers = object.find("signers");
    if (signers == object.end() || !signers->is_array()) return false;
    // The signature bound applies before any per-entry work.
    if (signers->size() > constants::kMaxQcSignatures) return false;
    for (const auto& entry : *signers) {
        if (!entry.is_object()) return false;
        if (has_unknown_key(entry, {"node_id", "signature"})) return false;
        QcSigner signer{};
        if (!read_b64(entry, "node_id", signer.node_id.bytes)) return false;
        if (!read_b64(entry, "signature", signer.signature)) return false;
        certificate.signers.push_back(signer);
    }

    out = std::move(certificate);
    return true;
}

}  // namespace

json hotstuff_state_to_json(const HotStuffState& state) {
    // The record binds its own payload: a byte changed at rest loads as
    // Corrupt, the same convention the epoch store uses for its anchor's
    // record_digest. version/record_digest are envelope fields, outside the
    // payload digest; version is still re-checked on read so a wrong-version
    // record never acts as state.
    return json{{"version", constants::kConsensusStoreFormatVersion},
                {"epoch", state.epoch},
                {"consensus_ruleset", state.consensus_ruleset},
                {"last_voted_view", state.last_voted_view},
                {"high_qc", qc_to_json(state.high_qc)},
                {"locked_qc", qc_to_json(state.locked_qc)},
                {"record_digest",
                 b64(consensus_state_record_digest(state.high_qc, state.locked_qc,
                                                   state.consensus_ruleset, state.epoch,
                                                   state.last_voted_view))}};
}

std::optional<HotStuffState> hotstuff_state_from_json(const json& document) {
    if (!document.is_object()) return std::nullopt;
    if (has_unknown_key(document, {"version", "epoch", "consensus_ruleset", "last_voted_view",
                                   "high_qc", "locked_qc", "record_digest"})) {
        return std::nullopt;
    }

    // The format is new; every file must be exactly this version. There is no
    // legacy layout to accept.
    uint32_t version = 0;
    if (!read_u32(document, "version", version) ||
        version != constants::kConsensusStoreFormatVersion) {
        return std::nullopt;
    }

    HotStuffState state;
    if (!read_u64(document, "epoch", state.epoch)) return std::nullopt;
    if (!read_u16(document, "consensus_ruleset", state.consensus_ruleset)) return std::nullopt;
    if (!read_u64(document, "last_voted_view", state.last_voted_view)) return std::nullopt;

    const auto high = document.find("high_qc");
    if (high == document.end() || !qc_from_json(*high, state.high_qc)) return std::nullopt;
    const auto locked = document.find("locked_qc");
    if (locked == document.end() || !qc_from_json(*locked, state.locked_qc)) {
        return std::nullopt;
    }
    Digest recorded{};
    if (!read_b64(document, "record_digest", recorded) ||
        recorded != consensus_state_record_digest(state.high_qc, state.locked_qc,
                                                  state.consensus_ruleset, state.epoch,
                                                  state.last_voted_view)) {
        return std::nullopt;
    }
    return state;
}

}  // namespace nexus::security
