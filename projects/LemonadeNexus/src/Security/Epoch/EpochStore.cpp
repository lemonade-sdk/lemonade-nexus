#include <LemonadeNexus/Security/Epoch/EpochStore.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <fcntl.h>
#include <unistd.h>

#include <fstream>
#include <sstream>

namespace nexus::security {

namespace {

using json = nlohmann::json;

constexpr const char* kBootstrapFile = "bootstrap-certificate.json";
constexpr const char* kEpochFile = "epoch-current.json";
constexpr const char* kHistoryFile = "authority-history.json";

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

bool get_u16(const json& value, uint16_t& out) {
    uint64_t wide = 0;
    if (!get_u64(value, wide) || wide > 0xFFFF) {
        return false;
    }
    out = static_cast<uint16_t>(wide);
    return true;
}

std::string vote_key_file(EpochId epoch) {
    return "vote-key-" + std::to_string(epoch) + ".json";
}

}  // namespace

EpochStore::EpochStore(std::filesystem::path directory, crypto::KeyWrappingService* wrapping)
    : directory_(std::move(directory)), wrapping_(wrapping) {
    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
}

// Temp file, fsync, rename, directory fsync: the state a node acts on after
// a restart must be exactly one complete version.
bool EpochStore::write_atomic(const std::filesystem::path& path, const std::string& content) const {
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
        return false;
    }
    const int dir = ::open(directory_.c_str(), O_RDONLY);
    if (dir >= 0) {
        ::fsync(dir);
        ::close(dir);
    }
    return true;
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
    j["epoch"] = c.epoch;
    j["tier1_set_digest"] = b64(c.tier1_set_digest);
    j["authority_threshold"] = static_cast<uint64_t>(c.authority_threshold);
    j["authority_public_key"] = b64(c.authority_public_key);
    j["dkg_transcript_digest"] = b64(c.dkg_transcript_digest);
    j["attestation_root"] = b64(c.attestation_root);
    j["founding_eligibility_digest"] = b64(c.founding_eligibility_digest);
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
    j["id"] = epoch.state.id;
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
        entry["epoch"] = r.epoch;
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

// --- Own vote key -----------------------------------------------------------

bool EpochStore::store_vote_key(const EpochVoteKey& key) {
    if (wrapping_ == nullptr || key.private_key.size() != crypto::kEd25519PrivateKeySize) {
        return false;
    }
    crypto::Ed25519PrivateKey secret{};
    std::copy(key.private_key.data(), key.private_key.data() + secret.size(), secret.begin());
    const auto wrapped = wrapping_->wrap_key(secret, {}, key.public_key);
    sodium_memzero(secret.data(), secret.size());

    json j;
    j["epoch"] = key.epoch;
    j["node_id"] = b64(key.node_id.bytes);
    j["public_key"] = b64(key.public_key);
    j["ciphertext"] = crypto::to_base64(wrapped.ciphertext.ciphertext);
    j["nonce"] = crypto::to_base64(wrapped.ciphertext.nonce);
    return write_atomic(directory_ / vote_key_file(key.epoch), j.dump());
}

std::optional<EpochVoteKey> EpochStore::load_vote_key(EpochId epoch, const NodeId& node) const {
    if (wrapping_ == nullptr) {
        return std::nullopt;
    }
    const auto text = read_all(directory_ / vote_key_file(epoch));
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
        !from_b64(j["node_id"], stored_node.bytes) || stored_node != node ||
        !from_b64(j["public_key"], pubkey)) {
        return std::nullopt;
    }
    crypto::WrappedKey wrapped;
    wrapped.ciphertext.ciphertext = crypto::from_base64(j["ciphertext"].get<std::string>());
    wrapped.ciphertext.nonce = crypto::from_base64(j["nonce"].get<std::string>());
    auto secret = wrapping_->unwrap_key(wrapped, {}, pubkey);
    if (!secret.has_value()) {
        return std::nullopt;
    }

    EpochVoteKey key;
    key.epoch = epoch;
    key.node_id = node;
    key.public_key = pubkey;
    key.private_key = crypto::SecureBuffer(std::span<const uint8_t>(*secret));
    sodium_memzero(secret->data(), secret->size());
    return key;
}

void EpochStore::discard_vote_key(EpochId epoch) {
    std::error_code ec;
    std::filesystem::remove(directory_ / vote_key_file(epoch), ec);
}

}  // namespace nexus::security
