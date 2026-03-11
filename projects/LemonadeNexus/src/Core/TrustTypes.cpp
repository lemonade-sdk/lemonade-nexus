#include <LemonadeNexus/Core/TrustTypes.hpp>

namespace nexus::core {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// TeeAttestationReport serialization
// ---------------------------------------------------------------------------

std::string canonical_attestation_json(const TeeAttestationReport& r) {
    json j;
    j["binary_hash"]    = r.binary_hash;
    j["nonce"]          = json::binary(std::vector<uint8_t>(r.nonce.begin(), r.nonce.end()));
    j["platform"]       = static_cast<uint8_t>(r.platform);
    j["quote"]          = json::binary(r.quote);
    j["server_pubkey"]  = r.server_pubkey;
    j["timestamp"]      = r.timestamp;
    return j.dump();
}

void to_json(json& j, const TeeAttestationReport& r) {
    j = json{
        {"platform",       static_cast<uint8_t>(r.platform)},
        {"platform_name",  std::string(tee_platform_name(r.platform))},
        {"quote",          json::binary(r.quote)},
        {"nonce",          json::binary(std::vector<uint8_t>(r.nonce.begin(), r.nonce.end()))},
        {"timestamp",      r.timestamp},
        {"server_pubkey",  r.server_pubkey},
        {"binary_hash",    r.binary_hash},
        {"signature",      r.signature},
    };
}

void from_json(const json& j, TeeAttestationReport& r) {
    if (j.contains("platform"))      r.platform = static_cast<TeePlatform>(j.at("platform").get<uint8_t>());
    if (j.contains("timestamp"))     j.at("timestamp").get_to(r.timestamp);
    if (j.contains("server_pubkey")) j.at("server_pubkey").get_to(r.server_pubkey);
    if (j.contains("binary_hash"))   j.at("binary_hash").get_to(r.binary_hash);
    if (j.contains("signature"))     j.at("signature").get_to(r.signature);

    if (j.contains("quote")) {
        if (j["quote"].is_binary()) {
            r.quote = j["quote"].get_binary();
        }
    }
    if (j.contains("nonce")) {
        if (j["nonce"].is_binary()) {
            auto nonce_vec = j["nonce"].get_binary();
            if (nonce_vec.size() == 32) {
                std::copy_n(nonce_vec.begin(), 32, r.nonce.begin());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AttestationToken serialization
// ---------------------------------------------------------------------------

std::string canonical_token_json(const AttestationToken& t) {
    json j;
    j["attestation_hash"]      = t.attestation_hash;
    j["attestation_timestamp"] = t.attestation_timestamp;
    j["binary_hash"]           = t.binary_hash;
    j["platform"]              = static_cast<uint8_t>(t.platform);
    j["server_pubkey"]         = t.server_pubkey;
    j["timestamp"]             = t.timestamp;
    return j.dump();
}

void to_json(json& j, const AttestationToken& t) {
    j = json{
        {"server_pubkey",         t.server_pubkey},
        {"platform",              static_cast<uint8_t>(t.platform)},
        {"platform_name",         std::string(tee_platform_name(t.platform))},
        {"attestation_hash",      t.attestation_hash},
        {"binary_hash",           t.binary_hash},
        {"timestamp",             t.timestamp},
        {"attestation_timestamp", t.attestation_timestamp},
        {"signature",             t.signature},
    };
}

void from_json(const json& j, AttestationToken& t) {
    if (j.contains("server_pubkey"))         j.at("server_pubkey").get_to(t.server_pubkey);
    if (j.contains("platform"))              t.platform = static_cast<TeePlatform>(j.at("platform").get<uint8_t>());
    if (j.contains("attestation_hash"))      j.at("attestation_hash").get_to(t.attestation_hash);
    if (j.contains("binary_hash"))           j.at("binary_hash").get_to(t.binary_hash);
    if (j.contains("timestamp"))             j.at("timestamp").get_to(t.timestamp);
    if (j.contains("attestation_timestamp")) j.at("attestation_timestamp").get_to(t.attestation_timestamp);
    if (j.contains("signature"))             j.at("signature").get_to(t.signature);
}

} // namespace nexus::core
