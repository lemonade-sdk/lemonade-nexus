#include <LemonadeNexus/Security/Consensus/ConsensusStore.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace nexus::security {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

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

[[nodiscard]] std::optional<std::string> read_file(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::nullopt;
    std::string content((std::istreambuf_iterator<char>(stream)),
                        std::istreambuf_iterator<char>());
    if (stream.bad()) return std::nullopt;
    return content;
}

// Parses without exceptions; a discarded document means corrupt input.
[[nodiscard]] std::optional<json> parse_file(const fs::path& path) {
    const auto content = read_file(path);
    if (!content) return std::nullopt;
    json document = json::parse(*content, nullptr, false);
    if (document.is_discarded()) return std::nullopt;
    return document;
}

[[nodiscard]] bool read_u64(const json& object, const char* key, uint64_t& out) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_number_unsigned()) return false;
    out = it->get<uint64_t>();
    return true;
}

// StrongId overload: same validation, typed store.
template <typename Tag>
[[nodiscard]] bool read_u64(const json& object, const char* key, StrongId<Tag>& out) {
    uint64_t raw = 0;
    if (!read_u64(object, key, raw)) return false;
    out = raw;
    return true;
}

[[nodiscard]] bool read_digest(const json& object, const char* key, Digest& out) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) return false;
    std::vector<uint8_t> decoded;
    try {
        decoded = crypto::from_base64(it->get<std::string>());
    } catch (...) {
        return false;
    }
    if (decoded.size() != out.size()) return false;
    std::copy(decoded.begin(), decoded.end(), out.begin());
    return true;
}

[[nodiscard]] json commit_to_json(const ConsensusCommit& commit) {
    // Same record_digest convention as the safety record and the epoch
    // store's anchor: the digest covers the payload (version included,
    // digest excluded) through the shared canonical encoder.
    return json{{"version", constants::kConsensusStoreFormatVersion},
                {"epoch", commit.epoch.underlying()},
                {"height", commit.height.underlying()},
                {"view", commit.view.underlying()},
                {"proposal_digest", crypto::to_base64(commit.proposal_digest)},
                {"proposed_state_root", crypto::to_base64(commit.proposed_state_root)},
                {"transitions_digest", crypto::to_base64(commit.transitions_digest)},
                {"qc_digest", crypto::to_base64(commit.qc_digest)},
                {"record_digest", crypto::to_base64(consensus_commit_record_digest(commit))}};
}

[[nodiscard]] std::optional<ConsensusCommit> commit_from_json(const json& document) {
    if (!document.is_object()) return std::nullopt;
    if (has_unknown_key(document, {"version", "epoch", "height", "view", "proposal_digest",
                                   "proposed_state_root", "transitions_digest", "qc_digest",
                                   "record_digest"})) {
        return std::nullopt;
    }
    // The format is new; every file must be exactly this version.
    const auto version_it = document.find("version");
    if (version_it == document.end() || !version_it->is_number_unsigned() ||
        version_it->get<uint64_t>() > 0xFFFFFFFFu ||
        version_it->get<uint64_t>() != constants::kConsensusStoreFormatVersion) {
        return std::nullopt;
    }

    ConsensusCommit commit{};
    if (!read_u64(document, "epoch", commit.epoch)) return std::nullopt;
    if (!read_u64(document, "height", commit.height)) return std::nullopt;
    if (!read_u64(document, "view", commit.view)) return std::nullopt;
    if (!read_digest(document, "proposal_digest", commit.proposal_digest)) return std::nullopt;
    if (!read_digest(document, "proposed_state_root", commit.proposed_state_root)) {
        return std::nullopt;
    }
    // Every field of the record is load-bearing: transitions_digest feeds the
    // record digest, so a file without it is corrupt, not "old".
    if (!read_digest(document, "transitions_digest", commit.transitions_digest)) return std::nullopt;
    if (!read_digest(document, "qc_digest", commit.qc_digest)) return std::nullopt;

    Digest recorded{};
    if (!read_digest(document, "record_digest", recorded) ||
        recorded != consensus_commit_record_digest(commit)) {
        return std::nullopt;
    }
    return commit;
}

[[nodiscard]] json chain_to_json(EpochId epoch, const CertifiedChain& chain) {
    json blocks = json::array();
    for (const auto& [proposal, justify] : chain.chain) {
        blocks.push_back(json{{"proposal", proposal_to_json(proposal)},
                              {"justify", quorum_certificate_to_json(justify)}});
    }
    return json{{"version", constants::kConsensusStoreFormatVersion},
                {"epoch", epoch.underlying()},
                {"blocks", std::move(blocks)},
                {"certifying", quorum_certificate_to_json(chain.certifying)},
                {"record_digest", crypto::to_base64(consensus_chain_record_digest(epoch, chain))}};
}

[[nodiscard]] std::optional<CertifiedChain> chain_from_json(const json& document, EpochId epoch) {
    if (!document.is_object()) return std::nullopt;
    if (has_unknown_key(document, {"version", "epoch", "blocks", "certifying", "record_digest"})) {
        return std::nullopt;
    }
    uint64_t version = 0;
    if (!read_u64(document, "version", version) ||
        version != constants::kConsensusStoreFormatVersion) {
        return std::nullopt;
    }
    EpochId stored_epoch = 0;
    if (!read_u64(document, "epoch", stored_epoch) || stored_epoch != epoch) return std::nullopt;

    const auto blocks = document.find("blocks");
    // The length bound applies before any per-entry work.
    if (blocks == document.end() || !blocks->is_array() || blocks->empty() ||
        blocks->size() > constants::kMaxSyncChainBlocks) {
        return std::nullopt;
    }
    CertifiedChain chain;
    for (const auto& entry : *blocks) {
        if (!entry.is_object() || has_unknown_key(entry, {"proposal", "justify"}) ||
            !entry.contains("proposal") || !entry.contains("justify")) {
            return std::nullopt;
        }
        auto proposal = proposal_from_json(entry["proposal"]);
        auto justify = quorum_certificate_from_json(entry["justify"]);
        if (!proposal || !justify) return std::nullopt;
        chain.chain.emplace_back(std::move(*proposal), std::move(*justify));
    }
    const auto certifying = document.find("certifying");
    if (certifying == document.end()) return std::nullopt;
    auto certificate = quorum_certificate_from_json(*certifying);
    if (!certificate) return std::nullopt;
    chain.certifying = std::move(*certificate);

    Digest recorded{};
    if (!read_digest(document, "record_digest", recorded) ||
        recorded != consensus_chain_record_digest(epoch, chain)) {
        return std::nullopt;
    }
    return chain;
}

}  // namespace

// A slot record is the kind's JSON document plus `seq`; a vote record may
// also carry `chain`. Both keys sit outside the record digest, which covers
// the kind's own fields as before.
struct FileConsensusStore::VoteRecord {
    HotStuffState state;
    uint64_t seq = 0;
    std::size_t slot = 0;  // index into safety_slots
    std::optional<CertifiedChain> chain;
    bool chain_corrupt = false;  // a chain key is there but does not validate
};

struct FileConsensusStore::CommitRecord {
    ConsensusCommit commit;
    uint64_t seq = 0;
    std::size_t slot = 0;
};

namespace {

/// Splits `seq` off a slot document. A document without the key is a record
/// of the earlier release, which wrote each record once: seq 0.
[[nodiscard]] bool take_seq(json& document, uint64_t& seq) {
    seq = 0;
    const auto it = document.find("seq");
    if (it == document.end()) return true;
    if (!it->is_number_unsigned()) return false;
    seq = it->get<uint64_t>();
    document.erase(it);
    return true;
}

[[nodiscard]] std::array<fs::path, 2> slot_paths(const fs::path& directory, const char* kind,
                                                 EpochId epoch) {
    const auto stem = std::string(kind) + "-" + std::to_string(epoch.underlying());
    return {directory / (stem + ".json"), directory / (stem + ".b.json")};
}

}  // namespace

FileConsensusStore::FileConsensusStore(fs::path directory) : directory_(std::move(directory)) {
    fs::create_directories(directory_);
}

std::array<fs::path, 2> FileConsensusStore::safety_slots(EpochId epoch) const {
    return slot_paths(directory_, "hotstuff-safety", epoch);
}

std::array<fs::path, 2> FileConsensusStore::commit_slots(EpochId epoch) const {
    return slot_paths(directory_, "hotstuff-commit", epoch);
}

fs::path FileConsensusStore::chain_path(EpochId epoch) const {
    return directory_ / ("hotstuff-chain-" + std::to_string(epoch.underlying()) + ".json");
}

std::variant<FileConsensusStore::VoteRecord, IConsensusStore::LoadResult>
FileConsensusStore::newest_vote_record(EpochId epoch) const {
    std::optional<VoteRecord> newest;
    bool present = false;
    const auto slots = safety_slots(epoch);
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
        std::error_code ec;
        const bool exists = fs::exists(slots[slot], ec);
        // A stat failure is not proof of absence.
        if (ec) return LoadResult::Corrupt;
        if (!exists) continue;
        present = true;
        auto document = parse_file(slots[slot]);
        if (!document || !document->is_object()) continue;
        VoteRecord record;
        record.slot = slot;
        if (!take_seq(*document, record.seq)) continue;
        std::optional<json> chain_document;
        if (const auto chain = document->find("chain"); chain != document->end()) {
            chain_document = *chain;
            document->erase(chain);
        }
        auto state = hotstuff_state_from_json(*document);
        // A record that names another epoch is a misplaced or rolled disk.
        if (!state || state->epoch != epoch) continue;
        record.state = std::move(*state);
        if (chain_document) {
            if (auto chain = chain_from_json(*chain_document, epoch)) {
                record.chain = std::move(*chain);
            } else {
                record.chain_corrupt = true;
            }
        }
        if (!newest || record.seq > newest->seq) newest = std::move(record);
    }
    if (newest) return std::move(*newest);
    return present ? LoadResult::Corrupt : LoadResult::Absent;
}

bool FileConsensusStore::store_before_vote(const HotStuffState& state) {
    const auto existing = newest_vote_record(state.epoch);
    uint64_t seq = 1;
    std::size_t slot = 0;
    if (const auto* result = std::get_if<LoadResult>(&existing)) {
        // Corrupt state is never overwritten as if it were fresh: it may hide
        // a vote this node already cast.
        if (*result == LoadResult::Corrupt) return false;
    } else {
        // Monotonicity guard. The stored values may only stay or grow.
        const auto& prior = std::get<VoteRecord>(existing);
        if (state.epoch != prior.state.epoch) return false;
        if (state.last_voted_view < prior.state.last_voted_view) return false;
        if (state.high_qc.view < prior.state.high_qc.view) return false;
        if (state.locked_qc.view < prior.state.locked_qc.view) return false;
        seq = prior.seq + 1;
        slot = prior.slot == 0 ? 1 : 0;
        // The chain stays with the epoch's records until store_chain
        // replaces it, as the chain file of the earlier layout did.
        if (prior.chain && !chain_.contains(state.epoch.underlying())) {
            chain_.emplace(state.epoch.underlying(), *prior.chain);
        }
    }
    json record = hotstuff_state_to_json(state);
    record["seq"] = seq;
    if (const auto chain = chain_.find(state.epoch.underlying()); chain != chain_.end()) {
        record["chain"] = chain_to_json(state.epoch, chain->second);
    }
    return write_slot_durable(safety_slots(state.epoch)[slot], record.dump());
}

std::variant<HotStuffState, IConsensusStore::LoadResult> FileConsensusStore::load(
    EpochId epoch) const {
    auto newest = newest_vote_record(epoch);
    if (const auto* result = std::get_if<LoadResult>(&newest)) return *result;
    return std::move(std::get<VoteRecord>(newest).state);
}

bool FileConsensusStore::store_commit(const ConsensusCommit& commit) {
    uint64_t seq = 1;
    std::size_t slot = 0;
    const auto slots = commit_slots(commit.epoch);
    std::optional<CommitRecord> newest;
    for (std::size_t index = 0; index < slots.size(); ++index) {
        auto document = parse_file(slots[index]);
        if (!document || !document->is_object()) continue;
        CommitRecord record;
        record.slot = index;
        if (!take_seq(*document, record.seq)) continue;
        auto parsed = commit_from_json(*document);
        if (!parsed || parsed->epoch != commit.epoch) continue;
        record.commit = *parsed;
        if (!newest || record.seq > newest->seq) newest = record;
    }
    if (newest) {
        seq = newest->seq + 1;
        slot = newest->slot == 0 ? 1 : 0;
    }
    json record = commit_to_json(commit);
    record["seq"] = seq;
    return write_slot_durable(slots[slot], record.dump());
}

std::optional<ConsensusCommit> FileConsensusStore::latest_commit(EpochId epoch) const {
    std::optional<CommitRecord> newest;
    for (const auto& path : commit_slots(epoch)) {
        std::error_code ec;
        if (!fs::exists(path, ec) || ec) continue;
        auto document = parse_file(path);
        if (!document || !document->is_object()) continue;
        CommitRecord record;
        if (!take_seq(*document, record.seq)) continue;
        auto commit = commit_from_json(*document);
        if (!commit || commit->epoch != epoch) continue;
        record.commit = *commit;
        if (!newest || record.seq > newest->seq) newest = record;
    }
    if (!newest) return std::nullopt;
    return newest->commit;
}

bool FileConsensusStore::store_chain(EpochId epoch, const CertifiedChain& chain) {
    if (chain.chain.empty() || chain.chain.size() > constants::kMaxSyncChainBlocks) return false;
    chain_[epoch.underlying()] = chain;
    return true;
}

std::variant<CertifiedChain, IConsensusStore::LoadResult> FileConsensusStore::load_chain(
    EpochId epoch) const {
    const auto newest = newest_vote_record(epoch);
    if (const auto* record = std::get_if<VoteRecord>(&newest)) {
        if (record->chain) return *record->chain;
        if (record->chain_corrupt) return LoadResult::Corrupt;
        // A vote record without a chain: the earlier release's chain file,
        // when it is there, is the last chain this node stored.
    } else if (std::get<LoadResult>(newest) == LoadResult::Corrupt) {
        return LoadResult::Corrupt;
    }
    const auto path = chain_path(epoch);
    std::error_code ec;
    const bool present = fs::exists(path, ec);
    if (ec) return LoadResult::Corrupt;
    if (!present) return LoadResult::Absent;
    const auto document = parse_file(path);
    if (!document) return LoadResult::Corrupt;
    auto chain = chain_from_json(*document, epoch);
    if (!chain) return LoadResult::Corrupt;
    return std::move(*chain);
}

}  // namespace nexus::security
