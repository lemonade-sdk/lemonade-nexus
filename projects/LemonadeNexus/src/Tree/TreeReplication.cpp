#include <LemonadeNexus/Tree/TreeReplication.hpp>

#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Consensus/CommitProof.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <nlohmann/json.hpp>

namespace nexus::tree {

namespace {

EntryEvidenceVerdict refused(std::string reason, security::EpochId epoch = 0) {
    return {EntryEvidence::Refused, std::move(reason), epoch};
}

}  // namespace

security::EpochId entry_epoch(const TreeLogEntry& entry) {
    if (entry.kind != TreeLogEntryKind::Batch) return 0;
    const auto it = entry.commit.find("epoch");
    if (it == entry.commit.end() || !it->is_number_unsigned()) return 0;
    return security::EpochId(it->get<uint64_t>());
}

EntryEvidenceVerdict verify_certified_entry(const TreeLogEntry& entry,
                                            const security::NetworkId& network_id,
                                            const EpochAuthorityLookup& authority) {
    if (entry.kind != TreeLogEntryKind::Batch) {
        return refused("not a consensus entry");
    }
    const security::EpochId epoch = entry_epoch(entry);
    if (epoch == security::EpochId(0)) return refused("the entry names no consensus epoch");
    const auto header_it = entry.commit.find("proposal");
    const auto proof_it = entry.commit.find("proof");
    if (header_it == entry.commit.end() || proof_it == entry.commit.end()) {
        return refused("the entry carries no commit proof", epoch);
    }
    const auto header = security::proposal_from_json(*header_it);
    const auto proof = security::commit_proof_from_json(*proof_it);
    if (!header || !proof) return refused("the consensus evidence is malformed", epoch);
    if (proof->chain.size() != 3 ||
        security::proposal_digest(proof->chain[0].proposal) != security::proposal_digest(*header)) {
        return refused("the commit proof does not commit the recorded header", epoch);
    }
    if (header->network_id != network_id || header->epoch != epoch ||
        header->security_ruleset != security::constants::kSecurityRulesetVersion ||
        header->consensus_ruleset != security::constants::kConsensusRulesetVersion) {
        return refused("the header names another network, epoch, or ruleset", epoch);
    }
    if (header->timestamp_hint != entry.block_time_ms ||
        header->transitions_digest != entry.ops_digest ||
        header->previous_state_root != entry.previous_root ||
        header->proposed_state_root != entry.state_root) {
        return refused("the entry contradicts its certified header", epoch);
    }
    security::BlockPayload payload;
    payload.kind = security::BlockPayloadKind::TreeBatch;
    payload.body = entry.batch;
    if (security::block_payload_digest(payload) != entry.ops_digest) {
        return refused("the batch does not match the certified ops digest", epoch);
    }

    const auto known = authority ? authority(epoch) : std::nullopt;
    if (!known) {
        return {EntryEvidence::UnknownEpoch,
                "the authority of epoch " + std::to_string(epoch.underlying()) +
                    " is not verified here yet",
                epoch};
    }
    if (known->epoch != epoch || known->network_id != network_id) {
        return refused("the epoch authority source answered for another epoch", epoch);
    }
    const security::QcValidationContext context{security::constants::kConsensusRulesetVersion,
                                                network_id, epoch, known->consensus_quorum};
    const auto failure =
        security::verify_commit_proof(entry.ops_digest, *proof, context, known->vote_keys);
    if (failure != security::CommitProofFailure::None) {
        return refused("the commit proof does not verify under epoch " +
                           std::to_string(epoch.underlying()) + "'s vote keys (" +
                           std::string(security::commit_proof_failure_name(failure)) + ")",
                       epoch);
    }
    return {EntryEvidence::Ok, {}, epoch};
}

std::vector<uint8_t> encode_replicated_entry(const TreeLogEntry& entry) {
    return nlohmann::json::to_msgpack(tree_log_entry_to_json(entry));
}

std::optional<TreeLogEntry> decode_replicated_entry(std::span<const uint8_t> bytes) {
    if (bytes.empty() || bytes.size() > kMaxReplicatedEntryBytes) return std::nullopt;
    const auto doc = nlohmann::json::from_msgpack(bytes.begin(), bytes.end(), true, false);
    if (doc.is_discarded()) return std::nullopt;
    try {
        return tree_log_entry_from_json(doc);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

}  // namespace nexus::tree
