#include <LemonadeNexus/Security/Attestation/AttestationState.hpp>

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>

#include "../AttestationDetail.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <set>
#include <system_error>

namespace nexus::security {

namespace {

using json = nlohmann::json;
constexpr std::size_t kMaxAttestationStateFileBytes = 2 * 1024 * 1024;
constexpr std::size_t kMaxTpmNameBytes = 64;
constexpr std::size_t kMaxAkSpkiTextBytes = 4096;

template <std::size_t N>
bool read_hex(const json& value, std::array<uint8_t, N>& out) {
    if (!value.is_string()) return false;
    try {
        const auto bytes = crypto::from_hex(value.get<std::string>());
        if (bytes.size() != N) return false;
        std::copy(bytes.begin(), bytes.end(), out.begin());
        return true;
    } catch (...) {
        return false;
    }
}

bool read_hex_vector(const json& value, std::vector<uint8_t>& out,
                     std::size_t maximum = kMaxTpmNameBytes) {
    if (!value.is_string()) return false;
    try {
        out = crypto::from_hex(value.get<std::string>());
        return !out.empty() && out.size() <= maximum;
    } catch (...) {
        return false;
    }
}

bool read_u64(const json& value, uint64_t& out) {
    if (!value.is_number_unsigned()) return false;
    out = value.get<uint64_t>();
    return true;
}

template <typename Tag>
bool read_u64(const json& value, StrongId<Tag>& out) {
    uint64_t raw = 0;
    if (!read_u64(value, raw)) return false;
    out = raw;
    return true;
}

using detail::exact_keys;

bool valid_profile(uint64_t raw) {
    if (raw > UINT16_MAX) return false;
    const auto id = static_cast<AttestationProfileId>(raw);
    return id != AttestationProfileId::Unknown && is_known_attestation_profile_id(id);
}

json encode_checkpoint(const AttestationCheckpoint& c) {
    json paths = json::array();
    for (const auto& path : c.required_paths) {
        paths.push_back({{"path", path.path}, {"sha256", path.sha256}});
    }
    return {
        {"format", c.format_version},
        {"network_id", crypto::to_hex(c.network_id)},
        {"node_id", crypto::to_hex(c.node_id.bytes)},
        {"incarnation", c.incarnation.underlying()},
        {"profile_id", static_cast<uint16_t>(c.profile_id)},
        {"profile_ruleset", c.profile_ruleset},
        {"policy_digest", crypto::to_hex(c.policy_digest)},
        {"launch_measurement", crypto::to_hex(c.launch_measurement)},
        {"ek_name", crypto::to_hex(c.ek_name)},
        {"ak_name", crypto::to_hex(c.ak_name)},
        {"ima_bank", c.ima_bank},
        {"event_count", c.event_count},
        {"pcr10", crypto::to_hex(c.pcr10)},
        {"required_paths", std::move(paths)},
        {"previous_evidence_digest", crypto::to_hex(c.previous_evidence_digest)},
        {"checkpoint_digest", crypto::to_hex(c.checkpoint_digest)},
    };
}

bool decode_checkpoint(const json& j, AttestationCheckpoint& c) {
    if (!exact_keys(j, {"format", "network_id", "node_id", "incarnation",
                        "profile_id", "profile_ruleset", "policy_digest",
                        "launch_measurement", "ek_name", "ak_name", "ima_bank",
                        "event_count", "pcr10", "required_paths",
                        "previous_evidence_digest", "checkpoint_digest"})) {
        return false;
    }
    uint64_t format = 0, profile = 0, ruleset = 0, bank = 0;
    if (!read_u64(j["format"], format) || format != kAttestationCheckpointFormatVersion ||
        !read_hex(j["network_id"], c.network_id) ||
        !read_hex(j["node_id"], c.node_id.bytes) ||
        !read_u64(j["incarnation"], c.incarnation) ||
        !read_u64(j["profile_id"], profile) || !valid_profile(profile) ||
        !read_u64(j["profile_ruleset"], ruleset) || ruleset > UINT16_MAX ||
        !read_hex(j["policy_digest"], c.policy_digest) ||
        !read_hex(j["launch_measurement"], c.launch_measurement) ||
        !read_hex_vector(j["ek_name"], c.ek_name) ||
        !read_hex_vector(j["ak_name"], c.ak_name) ||
        !read_u64(j["ima_bank"], bank) || bank > UINT16_MAX ||
        !read_u64(j["event_count"], c.event_count) ||
        !read_hex(j["pcr10"], c.pcr10) ||
        !read_hex(j["previous_evidence_digest"], c.previous_evidence_digest) ||
        !read_hex(j["checkpoint_digest"], c.checkpoint_digest) ||
        !j["required_paths"].is_array() ||
        j["required_paths"].size() > constants::kMaxSummarisedPaths) {
        return false;
    }
    c.format_version = static_cast<uint32_t>(format);
    c.profile_id = static_cast<AttestationProfileId>(profile);
    c.profile_ruleset = static_cast<AttestationProfileRuleset>(ruleset);
    c.ima_bank = static_cast<uint16_t>(bank);
    for (const auto& item : j["required_paths"]) {
        if (!exact_keys(item, {"path", "sha256"}) ||
            !item["path"].is_string() || !item["sha256"].is_string()) {
            return false;
        }
        c.required_paths.push_back({item["path"].get<std::string>(),
                                    item["sha256"].get<std::string>()});
    }
    return attestation_checkpoint_valid(c);
}

json encode_activation(const SvsmAkActivationRecord& r) {
    return {
        {"format", r.format_version},
        {"network_id", crypto::to_hex(r.network_id)},
        {"node_id", crypto::to_hex(r.node_id.bytes)},
        {"node_key", crypto::to_hex(r.node_key)},
        {"incarnation", r.incarnation.underlying()},
        {"profile_id", static_cast<uint16_t>(r.profile_id)},
        {"profile_ruleset", r.profile_ruleset},
        {"ek_name", crypto::to_hex(r.ek_name)},
        {"ak_name", crypto::to_hex(r.ak_name)},
        {"ak_spki_b64", r.ak_spki_b64},
        {"ak_spki_digest", crypto::to_hex(r.ak_spki_digest)},
        {"activation_receipt", crypto::to_hex(r.activation_receipt)},
        {"enrollment_evidence_digest", crypto::to_hex(r.enrollment_evidence_digest)},
        {"record_digest", crypto::to_hex(r.record_digest)},
    };
}

bool decode_activation(const json& j, SvsmAkActivationRecord& r) {
    if (!exact_keys(j, {"format", "network_id", "node_id", "node_key",
                        "incarnation", "profile_id", "profile_ruleset", "ek_name",
                        "ak_name", "ak_spki_b64", "ak_spki_digest",
                        "activation_receipt", "enrollment_evidence_digest",
                        "record_digest"})) {
        return false;
    }
    uint64_t format = 0, profile = 0, ruleset = 0;
    if (!read_u64(j["format"], format) || format != kSvsmActivationRecordFormatVersion ||
        !read_hex(j["network_id"], r.network_id) ||
        !read_hex(j["node_id"], r.node_id.bytes) ||
        !read_hex(j["node_key"], r.node_key) ||
        !read_u64(j["incarnation"], r.incarnation) ||
        !read_u64(j["profile_id"], profile) || !valid_profile(profile) ||
        !read_u64(j["profile_ruleset"], ruleset) || ruleset > UINT16_MAX ||
        !read_hex_vector(j["ek_name"], r.ek_name) ||
        !read_hex_vector(j["ak_name"], r.ak_name) ||
        !j["ak_spki_b64"].is_string() ||
        j["ak_spki_b64"].get_ref<const std::string&>().size() > kMaxAkSpkiTextBytes ||
        !read_hex(j["ak_spki_digest"], r.ak_spki_digest) ||
        !read_hex(j["activation_receipt"], r.activation_receipt) ||
        !read_hex(j["enrollment_evidence_digest"], r.enrollment_evidence_digest) ||
        !read_hex(j["record_digest"], r.record_digest)) {
        return false;
    }
    r.format_version = static_cast<uint32_t>(format);
    r.profile_id = static_cast<AttestationProfileId>(profile);
    r.profile_ruleset = static_cast<AttestationProfileRuleset>(ruleset);
    r.ak_spki_b64 = j["ak_spki_b64"].get<std::string>();
    return svsm_activation_record_valid(r);
}

template <typename Record, typename Decode>
std::variant<std::vector<Record>, AttestationStateLoadFailure> load_records(
    const std::filesystem::path& path, std::string_view type, std::size_t maximum,
    Decode decode) {
    if (path.empty()) return AttestationStateLoadFailure::Absent;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return AttestationStateLoadFailure::Absent;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > kMaxAttestationStateFileBytes) {
        return AttestationStateLoadFailure::Corrupt;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) return AttestationStateLoadFailure::Corrupt;
    const std::string text{std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>()};
    const json document = json::parse(text, nullptr, false);
    if (!exact_keys(document, {"format", "type", "records"}) ||
        !document["format"].is_number_unsigned() ||
        document["format"].get<uint32_t>() != 1 ||
        !document["type"].is_string() ||
        document["type"].get<std::string>() != type ||
        !document["records"].is_array() || document["records"].size() > maximum) {
        return AttestationStateLoadFailure::Corrupt;
    }
    std::vector<Record> records;
    records.reserve(document["records"].size());
    for (const auto& item : document["records"]) {
        Record record;
        if (!decode(item, record)) return AttestationStateLoadFailure::Corrupt;
        records.push_back(std::move(record));
    }
    return records;
}

template <typename Record, typename Encode>
bool save_records(const std::filesystem::path& path, std::string_view type,
                  const std::vector<Record>& records, std::size_t maximum, Encode encode) {
    if (path.empty() || records.size() > maximum) return false;
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) return false;
    json array = json::array();
    for (const auto& record : records) array.push_back(encode(record));
    const json document{{"format", 1}, {"type", type}, {"records", std::move(array)}};
    const std::string wire = document.dump();
    return wire.size() <= kMaxAttestationStateFileBytes && write_durable(path, wire);
}

bool same_key(const AttestationCheckpoint& a, const AttestationCheckpoint& b) {
    return a.network_id == b.network_id && a.node_id == b.node_id &&
           a.incarnation == b.incarnation && a.profile_id == b.profile_id;
}

bool same_key(const SvsmAkActivationRecord& a, const SvsmAkActivationRecord& b) {
    return a.network_id == b.network_id && a.node_id == b.node_id &&
           a.incarnation == b.incarnation && a.profile_id == b.profile_id;
}

}  // namespace

Digest attestation_checkpoint_digest(const AttestationCheckpoint& c) {
    CanonicalEncoder encoder("LEMONADE-NEXUS-IMA-CHECKPOINT-V1");
    encoder.add_u32(c.format_version);
    encoder.add_bytes(c.network_id);
    encoder.add_bytes(c.node_id.bytes);
    encoder.add_u64(c.incarnation.underlying());
    encoder.add_u16(static_cast<uint16_t>(c.profile_id));
    encoder.add_u16(c.profile_ruleset);
    encoder.add_bytes(c.policy_digest);
    encoder.add_bytes(c.launch_measurement);
    encoder.add_bytes(c.ek_name);
    encoder.add_bytes(c.ak_name);
    encoder.add_u16(c.ima_bank);
    encoder.add_u64(c.event_count);
    encoder.add_bytes(c.pcr10);
    encoder.add_u64(c.required_paths.size());
    for (const auto& path : c.required_paths) {
        encoder.add_string(path.path);
        encoder.add_string(path.sha256);
    }
    encoder.add_bytes(c.previous_evidence_digest);
    return encoder.digest();
}

bool attestation_checkpoint_valid(const AttestationCheckpoint& c) {
    if (c.format_version != kAttestationCheckpointFormatVersion ||
        c.profile_id != AttestationProfileId::SnpSvsmVtpm ||
        c.profile_ruleset != kAttestationProfileRulesetVersion ||
        c.ima_bank != kTpmAlgSha256 || c.ek_name.empty() || c.ak_name.empty() ||
        c.ek_name.size() > kMaxTpmNameBytes || c.ak_name.size() > kMaxTpmNameBytes ||
        c.required_paths.empty() ||
        c.required_paths.size() > constants::kMaxSummarisedPaths ||
        c.checkpoint_digest == Digest{} ||
        c.checkpoint_digest != attestation_checkpoint_digest(c)) {
        return false;
    }
    std::set<std::string> seen;
    for (const auto& path : c.required_paths) {
        if (path.path.empty() || path.sha256.size() != 64 ||
            !seen.insert(path.path).second) {
            return false;
        }
        try {
            if (crypto::from_hex(path.sha256).size() != 32) return false;
        } catch (...) {
            return false;
        }
    }
    return true;
}

Digest svsm_activation_record_digest(const SvsmAkActivationRecord& r) {
    CanonicalEncoder encoder("LEMONADE-NEXUS-SVSM-AK-ACTIVATION-RECORD-V1");
    encoder.add_u32(r.format_version);
    encoder.add_bytes(r.network_id);
    encoder.add_bytes(r.node_id.bytes);
    encoder.add_bytes(r.node_key);
    encoder.add_u64(r.incarnation.underlying());
    encoder.add_u16(static_cast<uint16_t>(r.profile_id));
    encoder.add_u16(r.profile_ruleset);
    encoder.add_bytes(r.ek_name);
    encoder.add_bytes(r.ak_name);
    encoder.add_string(r.ak_spki_b64);
    encoder.add_bytes(r.ak_spki_digest);
    encoder.add_bytes(r.activation_receipt);
    encoder.add_bytes(r.enrollment_evidence_digest);
    return encoder.digest();
}

bool svsm_activation_record_valid(const SvsmAkActivationRecord& r) {
    if (r.format_version != kSvsmActivationRecordFormatVersion ||
        r.profile_id != AttestationProfileId::SnpSvsmVtpm ||
        r.profile_ruleset != kAttestationProfileRulesetVersion ||
        r.node_key != r.node_id.bytes || r.ek_name.empty() || r.ak_name.empty() ||
        r.ek_name.size() > kMaxTpmNameBytes || r.ak_name.size() > kMaxTpmNameBytes ||
        r.ak_spki_b64.empty() || r.ak_spki_b64.size() > kMaxAkSpkiTextBytes ||
        r.ak_spki_digest == Digest{} || r.activation_receipt == Digest{} ||
        r.enrollment_evidence_digest == Digest{} || r.record_digest == Digest{} ||
        r.record_digest != svsm_activation_record_digest(r)) {
        return false;
    }
    try {
        const auto spki = crypto::from_base64(r.ak_spki_b64);
        return !spki.empty() && raw_ima_digest(spki) == r.ak_spki_digest;
    } catch (...) {
        return false;
    }
}

AttestationCheckpointStore::AttestationCheckpointStore(std::filesystem::path directory)
    : directory_(std::move(directory)) {}

CheckpointLoadResult AttestationCheckpointStore::load(
    const NetworkId& network_id, const NodeId& node_id, IncarnationId incarnation,
    AttestationProfileId profile_id) const {
    auto loaded = load_records<AttestationCheckpoint>(
        directory_ / "ima-checkpoints.json", "ima-checkpoints",
        constants::kMaxAttestationCheckpoints, decode_checkpoint);
    if (const auto* failure = std::get_if<AttestationStateLoadFailure>(&loaded)) {
        return *failure;
    }
    const auto& records = std::get<std::vector<AttestationCheckpoint>>(loaded);
    const auto it = std::find_if(records.begin(), records.end(), [&](const auto& c) {
        return c.network_id == network_id && c.node_id == node_id &&
               c.incarnation == incarnation && c.profile_id == profile_id;
    });
    return it == records.end() ? CheckpointLoadResult{AttestationStateLoadFailure::Absent}
                               : CheckpointLoadResult{*it};
}

bool AttestationCheckpointStore::store(AttestationCheckpoint checkpoint) {
    checkpoint.checkpoint_digest = attestation_checkpoint_digest(checkpoint);
    if (!attestation_checkpoint_valid(checkpoint)) return false;
    auto loaded = load_records<AttestationCheckpoint>(
        directory_ / "ima-checkpoints.json", "ima-checkpoints",
        constants::kMaxAttestationCheckpoints, decode_checkpoint);
    std::vector<AttestationCheckpoint> records;
    if (const auto* existing = std::get_if<std::vector<AttestationCheckpoint>>(&loaded)) {
        records = *existing;
    } else if (std::get<AttestationStateLoadFailure>(loaded) ==
               AttestationStateLoadFailure::Corrupt) {
        return false;
    }
    const auto it = std::find_if(records.begin(), records.end(),
                                 [&](const auto& old) { return same_key(old, checkpoint); });
    if (it != records.end()) *it = checkpoint;
    else if (records.size() < constants::kMaxAttestationCheckpoints) records.push_back(checkpoint);
    else return false;
    return save_records(directory_ / "ima-checkpoints.json", "ima-checkpoints", records,
                        constants::kMaxAttestationCheckpoints, encode_checkpoint);
}

SvsmActivationStore::SvsmActivationStore(std::filesystem::path directory)
    : directory_(std::move(directory)) {}

ActivationLoadResult SvsmActivationStore::load(
    const NetworkId& network_id, const NodeId& node_id, IncarnationId incarnation,
    AttestationProfileId profile_id) const {
    auto loaded = load_records<SvsmAkActivationRecord>(
        directory_ / "svsm-ak-activations.json", "svsm-ak-activations",
        constants::kMaxSvsmActivationRecords, decode_activation);
    if (const auto* failure = std::get_if<AttestationStateLoadFailure>(&loaded)) {
        return *failure;
    }
    const auto& records = std::get<std::vector<SvsmAkActivationRecord>>(loaded);
    const auto it = std::find_if(records.begin(), records.end(), [&](const auto& r) {
        return r.network_id == network_id && r.node_id == node_id &&
               r.incarnation == incarnation && r.profile_id == profile_id;
    });
    return it == records.end() ? ActivationLoadResult{AttestationStateLoadFailure::Absent}
                               : ActivationLoadResult{*it};
}

bool SvsmActivationStore::remove(const NetworkId& network_id, const NodeId& node_id,
                                 IncarnationId incarnation, AttestationProfileId profile_id) {
    auto loaded = load_records<SvsmAkActivationRecord>(
        directory_ / "svsm-ak-activations.json", "svsm-ak-activations",
        constants::kMaxSvsmActivationRecords, decode_activation);
    const auto* records = std::get_if<std::vector<SvsmAkActivationRecord>>(&loaded);
    if (!records) return false;
    std::vector<SvsmAkActivationRecord> kept;
    for (const auto& r : *records) {
        if (!(r.network_id == network_id && r.node_id == node_id &&
              r.incarnation == incarnation && r.profile_id == profile_id)) {
            kept.push_back(r);
        }
    }
    if (kept.size() == records->size()) return false;
    return save_records(directory_ / "svsm-ak-activations.json", "svsm-ak-activations",
                        kept, constants::kMaxSvsmActivationRecords, encode_activation);
}

bool SvsmActivationStore::store(SvsmAkActivationRecord record) {
    record.record_digest = svsm_activation_record_digest(record);
    if (!svsm_activation_record_valid(record)) return false;
    auto loaded = load_records<SvsmAkActivationRecord>(
        directory_ / "svsm-ak-activations.json", "svsm-ak-activations",
        constants::kMaxSvsmActivationRecords, decode_activation);
    std::vector<SvsmAkActivationRecord> records;
    if (const auto* existing = std::get_if<std::vector<SvsmAkActivationRecord>>(&loaded)) {
        records = *existing;
    } else if (std::get<AttestationStateLoadFailure>(loaded) ==
               AttestationStateLoadFailure::Corrupt) {
        return false;
    }
    const auto it = std::find_if(records.begin(), records.end(),
                                 [&](const auto& old) { return same_key(old, record); });
    if (it != records.end()) *it = record;
    else if (records.size() < constants::kMaxSvsmActivationRecords) records.push_back(record);
    else return false;
    return save_records(directory_ / "svsm-ak-activations.json", "svsm-ak-activations",
                        records, constants::kMaxSvsmActivationRecords, encode_activation);
}

}  // namespace nexus::security
