#include <LemonadeNexus/Security/Epoch/EpochStore.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>

namespace nexus::security {

namespace {

using json = nlohmann::json;

constexpr const char* kBootstrapFile = "bootstrap-certificate.json";
constexpr const char* kEpochFile = "epoch-current.json";
constexpr const char* kHistoryFile = "authority-history.json";
constexpr const char* kAnchorFile = "authority-anchor.json";
constexpr const char* kChainFile = "handoff-chain.json";
constexpr const char* kChainBaseFile = "chain-base.json";

template <std::size_t N>
std::string b64(const std::array<uint8_t, N>& bytes) {
    return crypto::to_base64(bytes);
}

template <std::size_t N>
bool from_b64(const json& value, std::array<uint8_t, N>& out) {
    if (!value.is_string()) {
        return false;
    }
    const auto bytes = crypto::from_base64(value.get<std::string>());
    if (bytes.size() != N) {
        return false;
    }
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return true;
}

bool get_u64(const json& value, uint64_t& out) {
    if (!value.is_number_unsigned()) {
        return false;
    }
    out = value.get<uint64_t>();
    return true;
}

// StrongId overload: same validation, typed store.
template <typename Tag>
bool get_u64(const json& value, StrongId<Tag>& out) {
    uint64_t raw = 0;
    if (!get_u64(value, raw)) return false;
    out = raw;
    return true;
}

bool get_u16(const json& value, uint16_t& out) {
    uint64_t wide = 0;
    if (!get_u64(value, wide) || wide > 0xFFFF) {
        return false;
    }
    out = static_cast<uint16_t>(wide);
    return true;
}

constexpr std::string_view kVoteKeyPrefix = "vote-key-";
constexpr std::string_view kMachineBoundSuffix = ".json";
constexpr std::string_view kSealedCopySuffix = ".sealed.json";

std::string vote_key_file(EpochId epoch) {
    return std::string(kVoteKeyPrefix) + std::to_string(epoch.underlying()) +
           std::string(kMachineBoundSuffix);
}

std::string sealed_vote_key_file(EpochId epoch) {
    return std::string(kVoteKeyPrefix) + std::to_string(epoch.underlying()) +
           std::string(kSealedCopySuffix);
}

// --- Vote-key sealing ---------------------------------------------------------

constexpr uint32_t kWrapStateVersion = 1;
constexpr uint32_t kSealedCopyFormat = 1;
constexpr std::string_view kPendingName = "sealed-pending";
constexpr std::string_view kSealedName = "sealed";
constexpr std::size_t kWrapKeyBytes = 32;
// The HKDF salt and info strings separate the two outputs of the wrapping key
// from each other and from every other key in the system.
constexpr std::string_view kWrapSalt = "LEMONADE-NEXUS-VOTE-KEY-WRAP-V1";
constexpr std::string_view kFileKeyInfo = "lemonade-nexus-vote-key-file-key-v1";
constexpr std::string_view kKeyIdInfo = "lemonade-nexus-vote-key-wrap-id-v1";

std::span<const uint8_t> as_bytes(std::string_view text) {
    return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

struct WrapState {
    VoteKeyProtection protection = VoteKeyProtection::SealedPending;
    std::string sealed_boot_id;
    std::array<uint8_t, 16> key_id{};
};

std::filesystem::path wrap_state_path(const SealedBlobStore& sealed) {
    return sealed.current_path(kVoteKeyWrapSealDomain).parent_path() /
           (std::string(kVoteKeyWrapSealDomain) + ".state.json");
}

std::optional<WrapState> read_wrap_state(const std::filesystem::path& path, bool& unreadable) {
    unreadable = false;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return std::nullopt;
    std::ifstream in(path, std::ios::binary);
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const json j = json::parse(text, nullptr, false);
    unreadable = true;
    if (j.is_discarded() || !j.is_object() || j.size() != 4 || !j.contains("version") ||
        !j["version"].is_number_unsigned() || j["version"].get<uint64_t>() != kWrapStateVersion ||
        !j.contains("protection") || !j["protection"].is_string() ||
        !j.contains("sealed_boot_id") || !j["sealed_boot_id"].is_string() ||
        !j.contains("key_id")) {
        return std::nullopt;
    }
    WrapState state;
    const auto protection = j["protection"].get<std::string>();
    if (protection == kPendingName) {
        state.protection = VoteKeyProtection::SealedPending;
    } else if (protection == kSealedName) {
        state.protection = VoteKeyProtection::Sealed;
    } else {
        return std::nullopt;
    }
    if (!from_b64(j["key_id"], state.key_id)) return std::nullopt;
    state.sealed_boot_id = j["sealed_boot_id"].get<std::string>();
    unreadable = false;
    return state;
}

bool write_wrap_state(const std::filesystem::path& path, const WrapState& state) {
    json j;
    j["version"] = kWrapStateVersion;
    j["protection"] = std::string(state.protection == VoteKeyProtection::Sealed ? kSealedName
                                                                               : kPendingName);
    j["sealed_boot_id"] = state.sealed_boot_id;
    j["key_id"] = b64(state.key_id);
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (!write_durable(path, j.dump())) return false;
    std::filesystem::permissions(path,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return true;
}

/// The 64-byte Ed25519 secret key carries its public key as the second half.
bool secret_matches(std::span<const uint8_t> secret, const crypto::Ed25519PublicKey& pubkey) {
    if (secret.size() != crypto::kEd25519PrivateKeySize) return false;
    crypto::Ed25519PublicKey derived{};
    crypto_sign_ed25519_sk_to_pk(derived.data(), secret.data());
    return derived == pubkey;
}

bool same_key(const EpochVoteKey& a, const EpochVoteKey& b) {
    return a.epoch == b.epoch && a.node_id == b.node_id && a.public_key == b.public_key &&
           a.private_key.size() == b.private_key.size() &&
           sodium_memcmp(a.private_key.data(), b.private_key.data(), a.private_key.size()) == 0;
}

std::vector<uint8_t> vote_key_aad(EpochId epoch, const NodeId& node,
                                  const crypto::Ed25519PublicKey& pubkey) {
    std::array<uint8_t, 8> epoch_le{};
    const uint64_t raw = epoch.underlying();
    for (std::size_t i = 0; i < epoch_le.size(); ++i) {
        epoch_le[i] = static_cast<uint8_t>((raw >> (8 * i)) & 0xFF);
    }
    return crypto::aead_aad(crypto::aead_purpose::kVoteKeyAtRest,
                            {std::span<const uint8_t>(epoch_le),
                             std::span<const uint8_t>(node.bytes),
                             std::span<const uint8_t>(pubkey)});
}

std::string recovery_text(SealStatus status, const std::string& detail,
                          const SealedBlobStore& sealed) {
    const auto blob = sealed.current_path(kVoteKeyWrapSealDomain).string();
    const std::string why = std::string(seal_status_name(status)) +
                            (detail.empty() ? "" : " (" + detail + ")");
    switch (status) {
        case SealStatus::PolicyMismatch:
            return "the sealed vote-key wrapping key does not unseal: " + why +
                   ". PCR 8/9 differ from every sealed copy, so the boot chain changed without "
                   "an approved release staging a copy for it. Boot the previous boot entry";
        case SealStatus::Corrupt:
            return "the sealed vote-key wrapping key does not unseal on this TPM: " + why +
                   ". Restore " + blob + " from a backup of this host";
        case SealStatus::Unavailable:
        case SealStatus::Unreachable:
            return "nexus-attestd cannot unseal the vote-key wrapping key: " + why +
                   ". Start nexus-attestd on this host";
        default:
            return "the sealed vote-key wrapping key does not unseal: " + why;
    }
}

UnsealReply unseal_waiting(SealedBlobStore& sealed, const VoteKeySealing& sealing) {
    auto reply = sealed.unseal(kVoteKeyWrapSealDomain);
    for (int attempt = 1;
         reply.status == SealStatus::Unreachable && attempt < sealing.unreachable_attempts;
         ++attempt) {
        if (attempt == 1) {
            spdlog::warn("[epoch-store] nexus-attestd is unreachable ({}); waiting to unseal the "
                         "vote-key wrapping key",
                         reply.detail);
        }
        std::this_thread::sleep_for(sealing.retry_delay);
        reply = sealed.unseal(kVoteKeyWrapSealDomain);
    }
    return reply;
}

}  // namespace

std::string_view vote_key_protection_name(VoteKeyProtection value) {
    switch (value) {
        case VoteKeyProtection::MachineBound:  return "machine-bound";
        case VoteKeyProtection::SealedPending: return kPendingName;
        case VoteKeyProtection::Sealed:        return kSealedName;
        case VoteKeyProtection::Refused:       return "refused";
    }
    return "unknown";
}

EpochStore::EpochStore(std::filesystem::path directory, crypto::KeyWrappingService* wrapping)
    : directory_(std::move(directory)), wrapping_(wrapping) {
    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
}

// The state a node acts on after a restart must be exactly one complete
// version; the shared helper also makes the rename itself durable, which this
// store previously left best-effort.
bool EpochStore::write_atomic(const std::filesystem::path& path, const std::string& content) const {
    return write_durable(path, content);
}

std::optional<std::string> EpochStore::read_all(const std::filesystem::path& path) const {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// --- Bootstrap certificate --------------------------------------------------

bool EpochStore::store_bootstrap(const BootstrapCertificate& c) {
    json j;
    j["network_id"] = b64(c.network_id);
    j["epoch"] = c.epoch.underlying();
    j["tier1_set_digest"] = b64(c.tier1_set_digest);
    j["authority_threshold"] = static_cast<uint64_t>(c.authority_threshold);
    j["authority_public_key"] = b64(c.authority_public_key);
    j["dkg_transcript_digest"] = b64(c.dkg_transcript_digest);
    j["attestation_root"] = b64(c.attestation_root);
    j["founding_eligibility_digest"] = b64(c.founding_eligibility_digest);
    j["vote_key_set_digest"] = b64(c.vote_key_set_digest);
    j["release_approval_digest"] = b64(c.release_approval_digest);
    j["security_ruleset"] = c.security_ruleset;
    j["consensus_ruleset"] = c.consensus_ruleset;
    j["genesis_signature"] = b64(c.genesis_signature);
    return write_atomic(directory_ / kBootstrapFile, j.dump());
}

std::variant<BootstrapCertificate, EpochLoadResult> EpochStore::load_bootstrap() const {
    const auto text = read_all(directory_ / kBootstrapFile);
    if (!text.has_value()) {
        return EpochLoadResult::Absent;
    }
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_object()) {
        return EpochLoadResult::Corrupt;
    }
    BootstrapCertificate c;
    uint64_t threshold = 0;
    if (!(j.contains("network_id") && from_b64(j["network_id"], c.network_id) &&
          j.contains("epoch") && get_u64(j["epoch"], c.epoch) &&
          j.contains("tier1_set_digest") && from_b64(j["tier1_set_digest"], c.tier1_set_digest) &&
          j.contains("authority_threshold") && get_u64(j["authority_threshold"], threshold) &&
          j.contains("authority_public_key") &&
          from_b64(j["authority_public_key"], c.authority_public_key) &&
          j.contains("dkg_transcript_digest") &&
          from_b64(j["dkg_transcript_digest"], c.dkg_transcript_digest) &&
          j.contains("attestation_root") && from_b64(j["attestation_root"], c.attestation_root) &&
          j.contains("founding_eligibility_digest") &&
          from_b64(j["founding_eligibility_digest"], c.founding_eligibility_digest) &&
          j.contains("vote_key_set_digest") &&
          from_b64(j["vote_key_set_digest"], c.vote_key_set_digest) &&
          j.contains("release_approval_digest") &&
          from_b64(j["release_approval_digest"], c.release_approval_digest) &&
          j.contains("security_ruleset") && get_u16(j["security_ruleset"], c.security_ruleset) &&
          j.contains("consensus_ruleset") && get_u16(j["consensus_ruleset"], c.consensus_ruleset) &&
          j.contains("genesis_signature") && from_b64(j["genesis_signature"], c.genesis_signature))) {
        return EpochLoadResult::Corrupt;
    }
    c.authority_threshold = static_cast<std::size_t>(threshold);
    return c;
}

// --- Current epoch ----------------------------------------------------------

bool EpochStore::store_epoch(const StoredEpoch& epoch) {
    json j;
    j["id"] = epoch.state.id.underlying();
    j["network_id"] = b64(epoch.state.network_id);
    json members = json::array();
    for (const auto& node : epoch.state.tier1_members.members()) {
        members.push_back(b64(node.bytes));
    }
    j["members"] = members;
    j["authority_public_key"] = b64(epoch.state.authority_public_key);
    j["attestation_root"] = b64(epoch.state.attestation_root);
    json keys = json::object();
    for (const auto& [node, key] : epoch.vote_keys) {
        keys[b64(node.bytes)] = b64(key);
    }
    j["vote_keys"] = keys;
    j["checkpoint"] = b64(epoch.checkpoint);
    return write_atomic(directory_ / kEpochFile, j.dump());
}

std::variant<StoredEpoch, EpochLoadResult> EpochStore::load_epoch() const {
    const auto text = read_all(directory_ / kEpochFile);
    if (!text.has_value()) {
        return EpochLoadResult::Absent;
    }
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_object() || !j.contains("members") || !j["members"].is_array() ||
        !j.contains("vote_keys") || !j["vote_keys"].is_object()) {
        return EpochLoadResult::Corrupt;
    }
    EpochId id = 0;
    NetworkId network{};
    crypto::Ed25519PublicKey authority{};
    Digest root{};
    Digest checkpoint{};
    if (!(j.contains("id") && get_u64(j["id"], id) && j.contains("network_id") &&
          from_b64(j["network_id"], network) && j.contains("authority_public_key") &&
          from_b64(j["authority_public_key"], authority) && j.contains("attestation_root") &&
          from_b64(j["attestation_root"], root) && j.contains("checkpoint") &&
          from_b64(j["checkpoint"], checkpoint))) {
        return EpochLoadResult::Corrupt;
    }
    if (j["members"].size() > constants::kMaxActiveTier1) {
        return EpochLoadResult::Corrupt;
    }
    std::vector<NodeId> members;
    for (const auto& entry : j["members"]) {
        NodeId node;
        if (!from_b64(entry, node.bytes)) {
            return EpochLoadResult::Corrupt;
        }
        members.push_back(node);
    }
    auto set = Tier1Set::from_nodes(members);
    if (!set.has_value()) {
        return EpochLoadResult::Corrupt;
    }
    std::map<NodeId, crypto::Ed25519PublicKey> vote_keys;
    for (const auto& [node_b64, key] : j["vote_keys"].items()) {
        NodeId node;
        crypto::Ed25519PublicKey pubkey{};
        if (!from_b64(json(node_b64), node.bytes) || !from_b64(key, pubkey)) {
            return EpochLoadResult::Corrupt;
        }
        vote_keys[node] = pubkey;
    }
    // The thresholds are recomputed from the compiled formulas, never read
    // from disk.
    StoredEpoch stored{make_epoch_state(id, network, std::move(*set), authority, root),
                       std::move(vote_keys), checkpoint};
    return stored;
}

// --- Authority history ------------------------------------------------------

bool EpochStore::append_authority(const EpochAuthorityRecord& record) {
    auto history = load_authority_history();
    if (std::holds_alternative<EpochLoadResult>(history) &&
        std::get<EpochLoadResult>(history) == EpochLoadResult::Corrupt) {
        return false;
    }
    std::vector<EpochAuthorityRecord> records;
    if (auto* existing = std::get_if<std::vector<EpochAuthorityRecord>>(&history)) {
        records = std::move(*existing);
    }
    for (const auto& r : records) {
        if (r.epoch == record.epoch) {
            // One authority per epoch; a second record for the same epoch is
            // either a replay or a corruption.
            return r.group_public_key == record.group_public_key;
        }
    }
    records.push_back(record);

    json j = json::array();
    for (const auto& r : records) {
        json entry;
        entry["epoch"] = r.epoch.underlying();
        entry["group_public_key"] = b64(r.group_public_key);
        entry["tier1_set_digest"] = b64(r.tier1_set_digest);
        entry["dkg_transcript_digest"] = b64(r.dkg_transcript_digest);
        j.push_back(entry);
    }
    return write_atomic(directory_ / kHistoryFile, j.dump());
}

std::variant<std::vector<EpochAuthorityRecord>, EpochLoadResult>
EpochStore::load_authority_history() const {
    const auto text = read_all(directory_ / kHistoryFile);
    if (!text.has_value()) {
        return EpochLoadResult::Absent;
    }
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_array()) {
        return EpochLoadResult::Corrupt;
    }
    std::vector<EpochAuthorityRecord> records;
    for (const auto& entry : j) {
        EpochAuthorityRecord r;
        if (!(entry.is_object() && entry.contains("epoch") && get_u64(entry["epoch"], r.epoch) &&
              entry.contains("group_public_key") &&
              from_b64(entry["group_public_key"], r.group_public_key) &&
              entry.contains("tier1_set_digest") &&
              from_b64(entry["tier1_set_digest"], r.tier1_set_digest) &&
              entry.contains("dkg_transcript_digest") &&
              from_b64(entry["dkg_transcript_digest"], r.dkg_transcript_digest))) {
            return EpochLoadResult::Corrupt;
        }
        records.push_back(r);
    }
    return records;
}

// --- Verified authority anchor ----------------------------------------------

bool EpochStore::store_authority_anchor(const VerifiedEpochAuthority& anchor) {
    json j;
    j["network_id"] = b64(anchor.network_id);
    j["epoch"] = anchor.epoch.underlying();
    json members = json::array();
    for (const auto& node : anchor.members) {
        json entry;
        entry["node"] = b64(node.bytes);
        const auto incarnation = anchor.incarnations.find(node);
        entry["incarnation"] =
            incarnation != anchor.incarnations.end() ? incarnation->second.underlying() : 0u;
        const auto key = anchor.vote_keys.find(node);
        if (key == anchor.vote_keys.end()) {
            return false;
        }
        entry["vote_key"] = b64(key->second);
        members.push_back(entry);
    }
    j["members"] = members;
    j["consensus_quorum"] = static_cast<uint64_t>(anchor.consensus_quorum);
    j["authority_threshold"] = static_cast<uint64_t>(anchor.authority_threshold);
    j["security_ruleset"] = anchor.security_ruleset;
    j["consensus_ruleset"] = anchor.consensus_ruleset;
    j["group_public_key"] = b64(anchor.group_public_key);
    j["key_generation"] = anchor.key_generation.underlying();
    j["attestation_root"] = b64(anchor.attestation_root);
    j["checkpoint"] = b64(anchor.checkpoint);
    j["previous_anchor"] = b64(anchor.previous_anchor);
    j["anchor_digest"] = b64(anchor.anchor_digest);
    // This detects accidental corruption. It is publicly recomputable and is
    // not proof that the record came from the authority chain.
    j["record_digest"] = b64(verified_epoch_authority_digest(anchor));
    return write_atomic(directory_ / kAnchorFile, j.dump());
}

std::variant<VerifiedEpochAuthority, EpochLoadResult> EpochStore::load_authority_anchor() const {
    const auto text = read_all(directory_ / kAnchorFile);
    if (!text.has_value()) {
        return EpochLoadResult::Absent;
    }
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_object() || !j.contains("members") || !j["members"].is_array()) {
        return EpochLoadResult::Corrupt;
    }
    VerifiedEpochAuthority anchor;
    uint64_t quorum = 0;
    uint64_t threshold = 0;
    if (!(j.contains("network_id") && from_b64(j["network_id"], anchor.network_id) &&
          j.contains("epoch") && get_u64(j["epoch"], anchor.epoch) &&
          j.contains("consensus_quorum") && get_u64(j["consensus_quorum"], quorum) &&
          j.contains("authority_threshold") && get_u64(j["authority_threshold"], threshold) &&
          j.contains("security_ruleset") && get_u16(j["security_ruleset"], anchor.security_ruleset) &&
          j.contains("consensus_ruleset") &&
          get_u16(j["consensus_ruleset"], anchor.consensus_ruleset) &&
          j.contains("group_public_key") &&
          from_b64(j["group_public_key"], anchor.group_public_key) &&
          j.contains("key_generation") && get_u64(j["key_generation"], anchor.key_generation) &&
          j.contains("attestation_root") && from_b64(j["attestation_root"], anchor.attestation_root) &&
          j.contains("checkpoint") && from_b64(j["checkpoint"], anchor.checkpoint) &&
          j.contains("previous_anchor") && from_b64(j["previous_anchor"], anchor.previous_anchor) &&
          j.contains("anchor_digest") && from_b64(j["anchor_digest"], anchor.anchor_digest))) {
        return EpochLoadResult::Corrupt;
    }
    anchor.consensus_quorum = static_cast<std::size_t>(quorum);
    anchor.authority_threshold = static_cast<std::size_t>(threshold);
    for (const auto& entry : j["members"]) {
        NodeId node;
        uint64_t incarnation = 0;
        nexus::crypto::Ed25519PublicKey key{};
        if (!(entry.is_object() && entry.contains("node") && from_b64(entry["node"], node.bytes) &&
              entry.contains("incarnation") && get_u64(entry["incarnation"], incarnation) &&
              entry.contains("vote_key") && from_b64(entry["vote_key"], key))) {
            return EpochLoadResult::Corrupt;
        }
        anchor.members.push_back(node);
        anchor.incarnations[node] = incarnation;
        anchor.vote_keys[node] = key;
    }
    Digest recorded{};
    if (!j.contains("record_digest") || !from_b64(j["record_digest"], recorded) ||
        recorded != verified_epoch_authority_digest(anchor)) {
        return EpochLoadResult::Corrupt;
    }
    return anchor;
}

// --- Handoff chain links -----------------------------------------------------

bool EpochStore::append_chain_link(std::span<const uint8_t> encoded) {
    std::vector<std::vector<uint8_t>> links;
    auto existing = load_chain_links();
    if (std::get_if<EpochLoadResult>(&existing) != nullptr) {
        if (std::get<EpochLoadResult>(existing) == EpochLoadResult::Corrupt) {
            return false;
        }
    } else {
        links = std::move(std::get<std::vector<std::vector<uint8_t>>>(existing));
    }
    links.emplace_back(encoded.begin(), encoded.end());
    json j = json::array();
    for (const auto& link : links) {
        j.push_back(crypto::to_base64(link));
    }
    return write_atomic(directory_ / kChainFile, j.dump());
}

std::variant<std::vector<std::vector<uint8_t>>, EpochLoadResult>
EpochStore::load_chain_links() const {
    const auto text = read_all(directory_ / kChainFile);
    if (!text.has_value()) {
        return EpochLoadResult::Absent;
    }
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_array()) {
        return EpochLoadResult::Corrupt;
    }
    std::vector<std::vector<uint8_t>> links;
    for (const auto& entry : j) {
        if (!entry.is_string()) {
            return EpochLoadResult::Corrupt;
        }
        auto bytes = crypto::from_base64(entry.get<std::string>());
        if (bytes.empty()) {
            return EpochLoadResult::Corrupt;
        }
        links.push_back(std::move(bytes));
    }
    return links;
}

// --- Epoch-1 chain base ------------------------------------------------------

bool EpochStore::store_chain_base(
    const std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>>& listing) {
    json j = json::array();
    for (const auto& [node, key] : listing) {
        json entry;
        entry["node"] = b64(node.bytes);
        entry["vote_key"] = b64(key);
        j.push_back(entry);
    }
    return write_atomic(directory_ / kChainBaseFile, j.dump());
}

std::variant<std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>>, EpochLoadResult>
EpochStore::load_chain_base() const {
    const auto text = read_all(directory_ / kChainBaseFile);
    if (!text.has_value()) {
        return EpochLoadResult::Absent;
    }
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_array()) {
        return EpochLoadResult::Corrupt;
    }
    std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>> listing;
    for (const auto& entry : j) {
        NodeId node;
        nexus::crypto::Ed25519PublicKey key{};
        if (!(entry.is_object() && entry.contains("node") && from_b64(entry["node"], node.bytes) &&
              entry.contains("vote_key") && from_b64(entry["vote_key"], key))) {
            return EpochLoadResult::Corrupt;
        }
        listing.emplace_back(node, key);
    }
    return listing;
}


// --- Own vote key -----------------------------------------------------------

std::filesystem::path EpochStore::machine_bound_path(EpochId epoch) const {
    return directory_ / vote_key_file(epoch);
}

std::filesystem::path EpochStore::sealed_copy_path(EpochId epoch) const {
    return directory_ / sealed_vote_key_file(epoch);
}

bool EpochStore::write_machine_bound(const EpochVoteKey& key) const {
    if (wrapping_ == nullptr || key.private_key.size() != crypto::kEd25519PrivateKeySize) {
        return false;
    }
    crypto::Ed25519PrivateKey secret{};
    std::copy(key.private_key.data(), key.private_key.data() + secret.size(), secret.begin());
    const auto wrapped = wrapping_->wrap_key(secret, {}, key.public_key);
    sodium_memzero(secret.data(), secret.size());

    json j;
    j["epoch"] = key.epoch.underlying();
    j["node_id"] = b64(key.node_id.bytes);
    j["public_key"] = b64(key.public_key);
    j["crypto_version"] = static_cast<unsigned>(wrapped.ciphertext.version);
    j["ciphertext"] = crypto::to_base64(wrapped.ciphertext.ciphertext);
    j["nonce"] = crypto::to_base64(wrapped.ciphertext.nonce);
    return write_atomic(machine_bound_path(key.epoch), j.dump());
}

std::optional<EpochVoteKey> EpochStore::read_machine_bound(EpochId epoch) const {
    if (wrapping_ == nullptr) {
        return std::nullopt;
    }
    const auto text = read_all(machine_bound_path(epoch));
    if (!text.has_value()) {
        return std::nullopt;
    }
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_object() || !j.contains("epoch") || !j.contains("node_id") ||
        !j.contains("public_key") || !j.contains("ciphertext") || !j.contains("nonce") ||
        !j["ciphertext"].is_string() || !j["nonce"].is_string()) {
        return std::nullopt;
    }
    uint64_t stored_epoch = 0;
    NodeId stored_node;
    crypto::Ed25519PublicKey pubkey{};
    if (!get_u64(j["epoch"], stored_epoch) || stored_epoch != epoch ||
        !from_b64(j["node_id"], stored_node.bytes) || !from_b64(j["public_key"], pubkey)) {
        return std::nullopt;
    }
    // Named construction, then exact lengths — nothing is inferred from widths.
    if (!j.contains("crypto_version") || !j["crypto_version"].is_number_unsigned() ||
        j["crypto_version"].get<unsigned>() != crypto::kEncryptedBlobVersion) {
        return std::nullopt;
    }
    crypto::WrappedKey wrapped;
    wrapped.ciphertext.ciphertext = crypto::from_base64(j["ciphertext"].get<std::string>());
    wrapped.ciphertext.version = crypto::kEncryptedBlobVersion;
    wrapped.ciphertext.nonce = crypto::from_base64(j["nonce"].get<std::string>());
    if (wrapped.ciphertext.nonce.size() != crypto::kAeadNonceSize) return std::nullopt;
    auto secret = wrapping_->unwrap_key(wrapped, {}, pubkey);
    if (!secret.has_value()) {
        return std::nullopt;
    }
    const bool consistent = secret_matches(*secret, pubkey);

    EpochVoteKey key;
    key.epoch = epoch;
    key.node_id = stored_node;
    key.public_key = pubkey;
    key.private_key = crypto::SecureBuffer(std::span<const uint8_t>(*secret));
    sodium_memzero(secret->data(), secret->size());
    if (!consistent) return std::nullopt;
    return key;
}

bool EpochStore::write_sealed_copy(const EpochVoteKey& key) const {
    if (crypto_ == nullptr || file_key_.size() != crypto::kAeadKeySize ||
        key.private_key.size() != crypto::kEd25519PrivateKeySize) {
        return false;
    }
    crypto::AeadKey aead_key{};
    std::memcpy(aead_key.data(), file_key_.data(), aead_key.size());
    const auto aad = vote_key_aad(key.epoch, key.node_id, key.public_key);
    const auto blob = crypto_->aead_encrypt(aead_key, key.private_key.span(), aad);
    sodium_memzero(aead_key.data(), aead_key.size());

    json j;
    j["format"] = kSealedCopyFormat;
    j["epoch"] = key.epoch.underlying();
    j["node_id"] = b64(key.node_id.bytes);
    j["public_key"] = b64(key.public_key);
    j["key_id"] = b64(key_id_);
    j["crypto_version"] = static_cast<unsigned>(blob.version);
    j["ciphertext"] = crypto::to_base64(blob.ciphertext);
    j["nonce"] = crypto::to_base64(blob.nonce);
    const auto path = sealed_copy_path(key.epoch);
    if (!write_atomic(path, j.dump())) return false;
    std::error_code ec;
    std::filesystem::permissions(path,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return true;
}

std::optional<EpochVoteKey> EpochStore::read_sealed_copy(EpochId epoch) const {
    if (crypto_ == nullptr || file_key_.size() != crypto::kAeadKeySize) {
        return std::nullopt;
    }
    const auto text = read_all(sealed_copy_path(epoch));
    if (!text.has_value()) {
        return std::nullopt;
    }
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_object() || j.size() != 8 || !j.contains("format") || !j.contains("epoch") ||
        !j.contains("node_id") || !j.contains("public_key") || !j.contains("key_id") ||
        !j.contains("crypto_version") || !j.contains("ciphertext") || !j.contains("nonce") ||
        !j["ciphertext"].is_string() || !j["nonce"].is_string() ||
        !j["format"].is_number_unsigned() || j["format"].get<uint64_t>() != kSealedCopyFormat ||
        !j["crypto_version"].is_number_unsigned() ||
        j["crypto_version"].get<uint64_t>() != crypto::kEncryptedBlobVersion) {
        return std::nullopt;
    }
    uint64_t stored_epoch = 0;
    NodeId stored_node;
    crypto::Ed25519PublicKey pubkey{};
    std::array<uint8_t, 16> key_id{};
    if (!get_u64(j["epoch"], stored_epoch) || stored_epoch != epoch ||
        !from_b64(j["node_id"], stored_node.bytes) || !from_b64(j["public_key"], pubkey) ||
        !from_b64(j["key_id"], key_id) || key_id != key_id_) {
        return std::nullopt;
    }
    crypto::EncryptedBlob blob;
    blob.version = crypto::kEncryptedBlobVersion;
    blob.ciphertext = crypto::from_base64(j["ciphertext"].get<std::string>());
    blob.nonce = crypto::from_base64(j["nonce"].get<std::string>());
    if (blob.nonce.size() != crypto::kAeadNonceSize) return std::nullopt;

    crypto::AeadKey aead_key{};
    std::memcpy(aead_key.data(), file_key_.data(), aead_key.size());
    // The associated data binds the epoch, node, and public key, so a copy
    // moved to another epoch file or edited in place does not open.
    auto secret = crypto_->aead_decrypt(aead_key, blob, vote_key_aad(epoch, stored_node, pubkey));
    sodium_memzero(aead_key.data(), aead_key.size());
    if (!secret.has_value()) return std::nullopt;
    const bool consistent = secret_matches(*secret, pubkey);

    EpochVoteKey key;
    key.epoch = epoch;
    key.node_id = stored_node;
    key.public_key = pubkey;
    key.private_key = crypto::SecureBuffer(std::span<const uint8_t>(*secret));
    sodium_memzero(secret->data(), secret->size());
    if (!consistent) return std::nullopt;
    return key;
}

std::vector<EpochId> EpochStore::machine_bound_epochs() const {
    std::vector<EpochId> epochs;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(directory_, ec)) {
        const auto name = entry.path().filename().string();
        if (name.size() <= kVoteKeyPrefix.size() + kMachineBoundSuffix.size() ||
            name.compare(0, kVoteKeyPrefix.size(), kVoteKeyPrefix) != 0 ||
            name.compare(name.size() - kMachineBoundSuffix.size(), kMachineBoundSuffix.size(),
                         kMachineBoundSuffix) != 0) {
            continue;
        }
        const auto digits = std::string_view(name).substr(
            kVoteKeyPrefix.size(), name.size() - kVoteKeyPrefix.size() - kMachineBoundSuffix.size());
        uint64_t raw = 0;
        const auto [end, parsed] = std::from_chars(digits.data(), digits.data() + digits.size(), raw);
        // Only the exact name this store writes counts; ".sealed.json" and
        // temporary files do not parse as a number.
        if (parsed != std::errc{} || end != digits.data() + digits.size() ||
            vote_key_file(EpochId{raw}) != name) {
            continue;
        }
        epochs.push_back(EpochId{raw});
    }
    std::sort(epochs.begin(), epochs.end());
    return epochs;
}

bool EpochStore::copy_into_sealed() const {
    bool complete = true;
    for (const EpochId epoch : machine_bound_epochs()) {
        const auto machine = read_machine_bound(epoch);
        if (!machine.has_value()) {
            spdlog::warn("[epoch-store] {} does not open; it is left as it is",
                         vote_key_file(epoch));
            continue;
        }
        const auto existing = read_sealed_copy(epoch);
        if (existing.has_value() && same_key(*existing, *machine)) continue;
        const auto written = write_sealed_copy(*machine) ? read_sealed_copy(epoch) : std::nullopt;
        if (!written.has_value() || !same_key(*written, *machine)) {
            spdlog::warn("[epoch-store] could not write a verified sealed copy of {}",
                         vote_key_file(epoch));
            complete = false;
        }
    }
    return complete;
}

void EpochStore::drop_machine_bound() const {
    for (const EpochId epoch : machine_bound_epochs()) {
        const auto sealed = read_sealed_copy(epoch);
        if (!sealed.has_value()) {
            // After the migration a machine-bound copy is never read, and it
            // never becomes a sealed copy: a planted file must not gain the
            // protection of the boot set.
            spdlog::warn("[epoch-store] {} has no sealed copy and is not used",
                         vote_key_file(epoch));
            continue;
        }
        const auto machine = read_machine_bound(epoch);
        if (machine.has_value() && !same_key(*sealed, *machine)) {
            spdlog::warn("[epoch-store] {} disagrees with its sealed copy and is not used",
                         vote_key_file(epoch));
            continue;
        }
        if (!scrub_file(machine_bound_path(epoch))) {
            spdlog::warn("[epoch-store] could not remove {}", vote_key_file(epoch));
        }
    }
}

void EpochStore::use_wrap_key(std::span<const uint8_t> wrap_key) {
    auto file_key = crypto_->hkdf_sha256(wrap_key, as_bytes(kWrapSalt), as_bytes(kFileKeyInfo),
                                         crypto::kAeadKeySize);
    file_key_ = crypto::SecureBuffer(std::span<const uint8_t>(file_key));
    sodium_memzero(file_key.data(), file_key.size());
    const auto id = crypto_->hkdf_sha256(wrap_key, as_bytes(kWrapSalt), as_bytes(kKeyIdInfo),
                                         key_id_.size());
    std::copy_n(id.begin(), std::min(id.size(), key_id_.size()), key_id_.begin());
}

VoteKeyProtection EpochStore::seal_new_wrap_key(SealedBlobStore& sealed,
                                                const VoteKeySealing& sealing,
                                                const std::filesystem::path& state_file) {
    file_key_ = crypto::SecureBuffer{};
    key_id_ = {};
    if (!sealed.sealing_available()) return VoteKeyProtection::MachineBound;

    crypto::SecureBuffer wrap_key(kWrapKeyBytes);
    crypto_->random_bytes(wrap_key.span());
    const auto reply = sealed.seal(kVoteKeyWrapSealDomain, wrap_key.span());
    if (reply.status != SealStatus::Ok) {
        if (reply.status == SealStatus::Unavailable || reply.status == SealStatus::Unreachable) {
            spdlog::info("[epoch-store] this host cannot seal ({}); the vote keys keep the "
                         "machine-bound wrapping",
                         reply.detail);
        } else {
            spdlog::warn("[epoch-store] sealing the vote-key wrapping key failed: {}{}{}; the "
                         "vote keys keep the machine-bound wrapping",
                         seal_status_name(reply.status), reply.detail.empty() ? "" : " — ",
                         reply.detail);
        }
        return VoteKeyProtection::MachineBound;
    }
    // Prove the sealed copy unseals to the same bytes before anything depends
    // on it.
    const auto check = sealed.unseal(kVoteKeyWrapSealDomain);
    if (check.status != SealStatus::Ok || check.plaintext.size() != wrap_key.size() ||
        sodium_memcmp(check.plaintext.data(), wrap_key.data(), wrap_key.size()) != 0) {
        spdlog::warn("[epoch-store] the sealed vote-key wrapping key did not unseal to the same "
                     "key ({}); removing it and keeping the machine-bound wrapping",
                     seal_status_name(check.status));
        (void)sealed.remove(kVoteKeyWrapSealDomain);
        std::error_code ec;
        std::filesystem::remove(state_file, ec);
        return VoteKeyProtection::MachineBound;
    }
    use_wrap_key(wrap_key.span());
    WrapState state;
    state.protection = VoteKeyProtection::SealedPending;
    state.sealed_boot_id = sealing.boot_id ? sealing.boot_id() : std::string{};
    state.key_id = key_id_;
    if (!write_wrap_state(state_file, state)) {
        spdlog::warn("[epoch-store] could not record the vote-key sealing state; keeping the "
                     "machine-bound wrapping");
        file_key_ = crypto::SecureBuffer{};
        key_id_ = {};
        return VoteKeyProtection::MachineBound;
    }
    if (!copy_into_sealed()) {
        spdlog::warn("[epoch-store] some vote keys have no sealed copy yet; the next start "
                     "tries again");
    }
    spdlog::info("[epoch-store] sealed the vote-key wrapping key; the machine-bound vote-key "
                 "copies are removed after the sealed key unseals in a later boot");
    return VoteKeyProtection::SealedPending;
}

VoteKeyProtection EpochStore::open_vote_key_sealing(const VoteKeySealing& sealing,
                                                    std::string& error) {
    error.clear();
    file_key_ = crypto::SecureBuffer{};
    key_id_ = {};
    protection_ = VoteKeyProtection::MachineBound;
    if (sealing.sealed == nullptr || sealing.crypto == nullptr || wrapping_ == nullptr) {
        return protection_;
    }
    crypto_ = sealing.crypto;
    SealedBlobStore& sealed = *sealing.sealed;
    const auto state_file = wrap_state_path(sealed);

    bool unreadable = false;
    const auto state = read_wrap_state(state_file, unreadable);
    if (unreadable) {
        error = "the vote-key sealing state file " + state_file.string() + " is unreadable";
        return protection_ = VoteKeyProtection::Refused;
    }
    const bool complete = state.has_value() && state->protection == VoteKeyProtection::Sealed;

    if (sealed.contains(kVoteKeyWrapSealDomain)) {
        const auto reply = unseal_waiting(sealed, sealing);
        if (reply.status == SealStatus::Ok && reply.plaintext.size() == kWrapKeyBytes) {
            use_wrap_key(reply.plaintext.span());
            if (state.has_value() && state->key_id != key_id_) {
                file_key_ = crypto::SecureBuffer{};
                error = "the vote-key sealing state file " + state_file.string() +
                        " names a different key than the sealed vote-key wrapping key";
                return protection_ = VoteKeyProtection::Refused;
            }
            if (complete) {
                protection_ = VoteKeyProtection::Sealed;
                // A crash after the state was recorded can leave machine-bound
                // copies behind.
                drop_machine_bound();
                return protection_;
            }
            const std::string boot = sealing.boot_id ? sealing.boot_id() : std::string{};
            const bool later_boot = state.has_value() && !state->sealed_boot_id.empty() &&
                                    !boot.empty() && boot != state->sealed_boot_id;
            protection_ = VoteKeyProtection::SealedPending;
            if (later_boot) {
                // Every vote key gets a verified sealed copy before Sealed is
                // recorded, and Sealed is recorded before any machine-bound
                // copy goes: a crash between two steps leaves an extra copy,
                // never a missing key.
                if (!copy_into_sealed()) {
                    spdlog::warn("[epoch-store] not every vote key has a sealed copy; the "
                                 "machine-bound copies stay");
                    return protection_;
                }
                WrapState next;
                next.protection = VoteKeyProtection::Sealed;
                next.sealed_boot_id = state->sealed_boot_id;
                next.key_id = key_id_;
                if (!write_wrap_state(state_file, next)) {
                    file_key_ = crypto::SecureBuffer{};
                    error = "could not record the vote-key sealing state in " +
                            state_file.string();
                    return protection_ = VoteKeyProtection::Refused;
                }
                protection_ = VoteKeyProtection::Sealed;
                drop_machine_bound();
                spdlog::info("[epoch-store] the sealed vote-key wrapping key unsealed after a "
                             "reboot; removed the machine-bound vote-key copies");
                return protection_;
            }
            if (!state.has_value()) {
                WrapState next;
                next.protection = VoteKeyProtection::SealedPending;
                next.sealed_boot_id = boot;
                next.key_id = key_id_;
                if (!write_wrap_state(state_file, next)) {
                    spdlog::warn("[epoch-store] could not record the vote-key sealing state");
                }
            }
            if (!copy_into_sealed()) {
                spdlog::warn("[epoch-store] some vote keys have no sealed copy yet; the next "
                             "start tries again");
            }
            return protection_;
        }
        const auto status =
            reply.status == SealStatus::Ok ? SealStatus::Corrupt : reply.status;
        if (!complete) {
            // While the migration is pending the machine-bound copies hold
            // every vote key, so a new wrapping key loses nothing.
            spdlog::warn("[epoch-store] the sealed vote-key wrapping key did not unseal ({}{}{}); "
                         "using the machine-bound vote-key copies and sealing a new key",
                         seal_status_name(status), reply.detail.empty() ? "" : " — ",
                         reply.detail);
            return protection_ = seal_new_wrap_key(sealed, sealing, state_file);
        }
        error = recovery_text(status, reply.detail, sealed);
        return protection_ = VoteKeyProtection::Refused;
    }

    if (complete) {
        error = "the sealed vote-key wrapping key is missing from " +
                sealed.current_path(kVoteKeyWrapSealDomain).string() +
                ". Restore it from a backup of this host. To start over with a new wrapping "
                "key, remove " +
                state_file.string() +
                "; the vote keys in vote-key-<epoch>.sealed.json are then lost, and this server "
                "votes again from the next epoch it joins";
        return protection_ = VoteKeyProtection::Refused;
    }
    return protection_ = seal_new_wrap_key(sealed, sealing, state_file);
}

bool EpochStore::store_vote_key(const EpochVoteKey& key) {
    if (key.private_key.size() != crypto::kEd25519PrivateKeySize) {
        return false;
    }
    switch (protection_) {
        case VoteKeyProtection::Refused:
            return false;
        case VoteKeyProtection::Sealed: {
            if (!write_sealed_copy(key)) return false;
            // A machine-bound copy for this epoch (from an older binary) holds
            // a key that is now replaced.
            std::error_code ec;
            if (std::filesystem::exists(machine_bound_path(key.epoch), ec)) {
                (void)scrub_file(machine_bound_path(key.epoch));
            }
            return true;
        }
        case VoteKeyProtection::SealedPending:
            // The machine-bound copy first: it is what the next start falls
            // back to if the sealed wrapping key does not survive a reboot.
            if (!write_machine_bound(key)) return false;
            if (!write_sealed_copy(key)) {
                spdlog::warn("[epoch-store] could not write the sealed copy of {}; the next "
                             "start tries again",
                             vote_key_file(key.epoch));
            }
            return true;
        case VoteKeyProtection::MachineBound:
            return write_machine_bound(key);
    }
    return false;
}

std::optional<EpochVoteKey> EpochStore::load_vote_key(EpochId epoch, const NodeId& node) const {
    std::optional<EpochVoteKey> found;
    switch (protection_) {
        case VoteKeyProtection::Refused:
            return std::nullopt;
        case VoteKeyProtection::Sealed:
            found = read_sealed_copy(epoch);
            break;
        case VoteKeyProtection::MachineBound:
            found = read_machine_bound(epoch);
            break;
        case VoteKeyProtection::SealedPending: {
            auto machine = read_machine_bound(epoch);
            auto sealed = read_sealed_copy(epoch);
            if (machine.has_value() && sealed.has_value() && !same_key(*machine, *sealed)) {
                // Two different keys for one epoch: neither is chosen.
                spdlog::warn("[epoch-store] the two copies of {} disagree; neither is used",
                             vote_key_file(epoch));
                return std::nullopt;
            }
            found = sealed.has_value() ? std::move(sealed) : std::move(machine);
            break;
        }
    }
    if (!found.has_value() || found->node_id != node) {
        return std::nullopt;
    }
    return found;
}

void EpochStore::discard_vote_key(EpochId epoch) {
    (void)scrub_file(machine_bound_path(epoch));
    (void)scrub_file(sealed_copy_path(epoch));
}

}  // namespace nexus::security
