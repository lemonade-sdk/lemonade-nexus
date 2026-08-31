#include <LemonadeNexus/Security/Eligibility/EligibilityStore.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <nlohmann/json.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <utility>

namespace nexus::security {

namespace {

using json = nlohmann::json;

constexpr uint32_t kFormatVersion = 1;

/// A record is small and fixed-shape; the cap stops a damaged or hostile file
/// from allocating before anything has been validated.
constexpr std::size_t kMaxStoredRecords = 64 * 1024;

[[nodiscard]] std::string hex_of(std::span<const uint8_t> bytes) {
    return crypto::to_hex(bytes);
}

template <std::size_t N>
[[nodiscard]] bool read_hex(const json& value, std::array<uint8_t, N>& out) {
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

[[nodiscard]] bool read_u64(const json& value, uint64_t& out) {
    if (!value.is_number_unsigned()) return false;
    out = value.get<uint64_t>();
    return true;
}

[[nodiscard]] json encode(const EligibilityLedger::PersistedRecord& record) {
    const EligibilityObservation& o = record.latest;
    json attestations = json::array();
    for (const auto& digest : record.attestations) {
        attestations.push_back(hex_of(digest));
    }
    return json{
        {"network_id", hex_of(o.network_id)},
        {"epoch", o.epoch},
        {"subject", hex_of(o.subject.bytes)},
        {"subject_incarnation", o.subject_incarnation},
        {"kind", static_cast<uint16_t>(o.kind)},
        {"attestation_digest", hex_of(o.attestation_digest)},
        {"profile_id", static_cast<uint16_t>(o.claims.profile_id)},
        {"profile_ruleset", o.claims.profile_ruleset},
        {"claim_bits", platform_claim_bits(o.claims)},
        {"height", o.height},
        {"state_reference", hex_of(o.state_reference)},
        {"observer", hex_of(o.observer.bytes)},
        {"signature", hex_of(o.signature)},
        {"incarnation", record.incarnation},
        {"attestations", attestations},
    };
}

[[nodiscard]] bool decode(const json& j, EligibilityLedger::PersistedRecord& record) {
    if (!j.is_object()) return false;
    EligibilityObservation& o = record.latest;
    uint64_t kind = 0;
    if (!(j.contains("network_id") && read_hex(j["network_id"], o.network_id) &&
          j.contains("epoch") && read_u64(j["epoch"], o.epoch) &&
          j.contains("subject") && read_hex(j["subject"], o.subject.bytes) &&
          j.contains("subject_incarnation") &&
          read_u64(j["subject_incarnation"], o.subject_incarnation) &&
          j.contains("kind") && read_u64(j["kind"], kind) &&
          j.contains("attestation_digest") &&
          read_hex(j["attestation_digest"], o.attestation_digest) &&
          j.contains("height") && read_u64(j["height"], o.height) &&
          j.contains("state_reference") && read_hex(j["state_reference"], o.state_reference) &&
          j.contains("observer") && read_hex(j["observer"], o.observer.bytes) &&
          j.contains("signature") && read_hex(j["signature"], o.signature) &&
          j.contains("incarnation") && read_u64(j["incarnation"], record.incarnation))) {
        return false;
    }
    if (kind > static_cast<uint64_t>(ObservationKind::Participation)) {
        return false;
    }
    o.kind = static_cast<ObservationKind>(kind);

    uint64_t profile_id = 0;
    uint64_t profile_ruleset = 0;
    uint64_t claim_bits = 0;
    if (!(j.contains("profile_id") && read_u64(j["profile_id"], profile_id) &&
          j.contains("profile_ruleset") && read_u64(j["profile_ruleset"], profile_ruleset) &&
          j.contains("claim_bits") && read_u64(j["claim_bits"], claim_bits))) {
        return false;
    }
    // A profile or claim bit this binary does not name is refused, never
    // folded: a stored value must decode to what was signed or to nothing.
    const auto named = static_cast<AttestationProfileId>(profile_id);
    if (profile_id > UINT16_MAX || profile_ruleset > UINT16_MAX ||
        (claim_bits & ~static_cast<uint64_t>(kPlatformClaimBitMask)) != 0 ||
        (named != AttestationProfileId::Unknown && !is_known_attestation_profile_id(named))) {
        return false;
    }
    o.claims = platform_claims_from_bits(
        named, static_cast<AttestationProfileRuleset>(profile_ruleset),
        static_cast<uint16_t>(claim_bits));

    if (!j.contains("attestations") || !j["attestations"].is_array()) return false;
    if (j["attestations"].size() > constants::kMaxContinuityAttestations) return false;
    for (const auto& entry : j["attestations"]) {
        Digest digest{};
        if (!read_hex(entry, digest)) return false;
        record.attestations.push_back(digest);
    }
    return true;
}

[[nodiscard]] bool write_atomic(const std::filesystem::path& path, const std::string& content) {
    const std::filesystem::path temp = path.string() + ".tmp";
    const int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return false;
    }
    std::size_t written = 0;
    while (written < content.size()) {
        const ssize_t n = ::write(fd, content.data() + written, content.size() - written);
        if (n <= 0) {
            ::close(fd);
            return false;
        }
        written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        return false;
    }
    ::close(fd);

    std::error_code ec;
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        std::filesystem::remove(temp, ec);
        return false;
    }
    return true;
}

}  // namespace

EligibilityStore::EligibilityStore(std::filesystem::path directory)
    : directory_(std::move(directory)) {}

std::filesystem::path EligibilityStore::path_for(EpochId epoch) const {
    return directory_ / ("observations-" + std::to_string(epoch) + ".json");
}

bool EligibilityStore::store(EpochId epoch,
                             const std::vector<EligibilityLedger::PersistedRecord>& records) {
    if (records.size() > kMaxStoredRecords) {
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
    if (ec) {
        return false;
    }
    json entries = json::array();
    for (const auto& record : records) {
        entries.push_back(encode(record));
    }
    const json document{
        {"format", kFormatVersion},
        {"epoch", epoch},
        {"records", std::move(entries)},
    };
    return write_atomic(path_for(epoch), document.dump());
}

std::variant<std::monostate, EligibilityLoadResult> EligibilityStore::load(
    EpochId epoch, const MeshFactContext& context, EligibilityLedger& ledger) const {
    std::ifstream in(path_for(epoch));
    if (!in) {
        return EligibilityLoadResult::Absent;
    }
    const std::string text{std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>()};

    const json document = json::parse(text, nullptr, false);
    if (!document.is_object() || !document.contains("records") ||
        !document["records"].is_array() || !document.contains("format") ||
        !document["format"].is_number_unsigned() ||
        document["format"].get<uint32_t>() != kFormatVersion) {
        return EligibilityLoadResult::Corrupt;
    }
    uint64_t stored_epoch = 0;
    if (!document.contains("epoch") || !read_u64(document["epoch"], stored_epoch) ||
        stored_epoch != epoch) {
        return EligibilityLoadResult::Corrupt;
    }
    // Bounded before anything is built from attacker-reachable content.
    if (document["records"].size() > kMaxStoredRecords) {
        return EligibilityLoadResult::Corrupt;
    }

    std::vector<EligibilityLedger::PersistedRecord> records;
    records.reserve(document["records"].size());
    for (const auto& entry : document["records"]) {
        EligibilityLedger::PersistedRecord record;
        if (!decode(entry, record)) {
            return EligibilityLoadResult::Corrupt;
        }
        records.push_back(std::move(record));
    }

    // The signatures decide, not the file. A record that no longer satisfies
    // the rules — a forged signature, an observer outside the set, a claim with
    // nothing behind it — makes the whole file corrupt rather than partly
    // usable, because a partly restored history is a history nobody made.
    if (!ledger.restore(records, context)) {
        return EligibilityLoadResult::Corrupt;
    }
    return std::monostate{};
}

bool EligibilityStore::store_faults(const std::map<NodeId, std::set<ObjectiveFault>>& faults) {
    if (faults.size() > kMaxStoredRecords) {
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
    if (ec) {
        return false;
    }
    json entries = json::array();
    for (const auto& [node, kinds] : faults) {
        json values = json::array();
        for (const auto fault : kinds) {
            values.push_back(static_cast<uint16_t>(fault));
        }
        entries.push_back(json{{"node", crypto::to_hex(node.bytes)}, {"faults", std::move(values)}});
    }
    const json document{{"format", kFormatVersion}, {"faults", std::move(entries)}};
    return write_atomic(directory_ / "faults.json", document.dump());
}

std::variant<std::map<NodeId, std::set<ObjectiveFault>>, EligibilityLoadResult>
EligibilityStore::load_faults() const {
    std::ifstream in(directory_ / "faults.json");
    if (!in) {
        return EligibilityLoadResult::Absent;
    }
    const std::string text{std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>()};
    const json document = json::parse(text, nullptr, false);
    if (!document.is_object() || !document.contains("format") ||
        !document["format"].is_number_unsigned() ||
        document["format"].get<uint32_t>() != kFormatVersion || !document.contains("faults") ||
        !document["faults"].is_array() || document["faults"].size() > kMaxStoredRecords) {
        return EligibilityLoadResult::Corrupt;
    }

    std::map<NodeId, std::set<ObjectiveFault>> faults;
    for (const auto& entry : document["faults"]) {
        NodeId node;
        if (!entry.is_object() || !entry.contains("node") || !read_hex(entry["node"], node.bytes) ||
            !entry.contains("faults") || !entry["faults"].is_array()) {
            return EligibilityLoadResult::Corrupt;
        }
        std::set<ObjectiveFault> kinds;
        for (const auto& value : entry["faults"]) {
            uint64_t raw = 0;
            if (!read_u64(value, raw) ||
                raw > static_cast<uint64_t>(ObjectiveFault::InvalidConsensusBehavior)) {
                return EligibilityLoadResult::Corrupt;
            }
            kinds.insert(static_cast<ObjectiveFault>(raw));
        }
        if (kinds.empty() || !faults.emplace(node, std::move(kinds)).second) {
            return EligibilityLoadResult::Corrupt;
        }
    }
    return faults;
}

void EligibilityStore::discard_before(EpochId epoch) {
    std::error_code ec;
    if (!std::filesystem::exists(directory_, ec)) {
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(directory_, ec)) {
        const std::string name = entry.path().filename().string();
        if (!name.starts_with("observations-") || !name.ends_with(".json")) {
            continue;
        }
        const std::string number =
            name.substr(std::string("observations-").size(),
                        name.size() - std::string("observations-.json").size());
        try {
            if (std::stoull(number) < epoch) {
                std::filesystem::remove(entry.path(), ec);
            }
        } catch (...) {
            // A name that is not a number is not one of ours; leave it alone.
        }
    }
}

}  // namespace nexus::security
