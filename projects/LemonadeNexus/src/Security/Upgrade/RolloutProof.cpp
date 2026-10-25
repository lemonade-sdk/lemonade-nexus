#include <LemonadeNexus/Security/Upgrade/RolloutProof.hpp>

#include <LemonadeNexus/Security/Attestation/ReleaseBundleGenerator.hpp>
#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Consensus/CommitProof.hpp>
#include <LemonadeNexus/Security/Consensus/QuorumValidation.hpp>
#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <nlohmann/json.hpp>

#include <map>
#include <set>

namespace nexus::security {

namespace {

using json = nlohmann::json;

std::optional<SecurityMessage> decode_for(std::span<const uint8_t> bytes,
                                          const NetworkId& network_id,
                                          SecurityMessageKind kind) {
    auto decoded = decode_security_message(bytes);
    auto* message = std::get_if<SecurityMessage>(&decoded);
    if (message == nullptr || message->kind != kind || message->network_id != network_id) {
        return std::nullopt;
    }
    return std::move(*message);
}

}  // namespace

std::string rollout_proof_json(const RolloutProof& proof) {
    json links = json::array();
    for (const auto& link : proof.links) links.push_back(crypto::to_hex(link));
    json records = json::array();
    for (const auto& record : proof.records) records.push_back(crypto::to_hex(record));
    return json{{"format_version", kRolloutProofFormatVersion},
                {"genesis_public_key", crypto::to_base64(proof.genesis_public_key)},
                {"base", crypto::to_hex(proof.base)},
                {"links", std::move(links)},
                {"records", std::move(records)}}
        .dump();
}

std::optional<RolloutProof> parse_rollout_proof(std::string_view json_text, std::string& error) {
    if (json_text.size() > kMaxRolloutProofBytes) {
        error = "the rollout proof is larger than the bound";
        return std::nullopt;
    }
    const auto root = json::parse(json_text, nullptr, false);
    if (root.is_discarded() || !root.is_object()) {
        error = "the rollout proof is not a JSON object";
        return std::nullopt;
    }
    try {
        if (root.at("format_version").get<uint32_t>() != kRolloutProofFormatVersion) {
            error = "the rollout proof has an unsupported format";
            return std::nullopt;
        }
        RolloutProof proof;
        const auto genesis = crypto::from_base64(root.at("genesis_public_key").get<std::string>());
        if (genesis.size() != proof.genesis_public_key.size()) {
            error = "the rollout proof names no Ed25519 Genesis key";
            return std::nullopt;
        }
        std::copy(genesis.begin(), genesis.end(), proof.genesis_public_key.begin());
        proof.base = crypto::from_hex(root.at("base").get<std::string>());
        for (const auto& link : root.at("links")) {
            proof.links.push_back(crypto::from_hex(link.get<std::string>()));
        }
        for (const auto& record : root.at("records")) {
            proof.records.push_back(crypto::from_hex(record.get<std::string>()));
        }
        return proof;
    } catch (const std::exception& e) {
        error = std::string("the rollout proof does not parse: ") + e.what();
        return std::nullopt;
    }
}

std::optional<VerifiedRollout> verify_rollout_proof(const RolloutProof& proof,
                                                    const NetworkId& network_id,
                                                    std::string& error) {
    // 0. The Genesis key: only the true key derives the pinned network id.
    const auto& genesis_public_key = proof.genesis_public_key;
    if (derive_network_id(genesis_public_key, constants::kSecurityRulesetVersion,
                          constants::kConsensusRulesetVersion) != network_id) {
        error = "the proof's Genesis key does not derive this network id";
        return std::nullopt;
    }
    // 1. Epoch 1 from the Genesis key.
    const auto base = decode_for(proof.base, network_id, SecurityMessageKind::AuthorityChainPage);
    const auto* page = base ? std::get_if<AuthorityChainPage>(&base->body) : nullptr;
    if (page == nullptr || !page->has_base) {
        error = "the proof has no Genesis base";
        return std::nullopt;
    }
    auto authority = verify_epoch_one_authority(page->base_certificate, genesis_public_key,
                                                page->base_vote_keys);
    if (!authority || authority->network_id != network_id) {
        error = "the Genesis base does not verify for this network";
        return std::nullopt;
    }
    std::map<EpochId, VerifiedEpochAuthority> authorities;
    authorities.emplace(authority->epoch, *authority);

    // 2. Each finalized handoff, under the previous epoch's frozen keys.
    for (const auto& bytes : proof.links) {
        const auto message = decode_for(bytes, network_id, SecurityMessageKind::EpochHandoffProof);
        const auto* link = message ? std::get_if<EpochHandoffProofMsg>(&message->body) : nullptr;
        if (link == nullptr) {
            error = "an authority chain link does not decode";
            return std::nullopt;
        }
        auto advanced = advance_epoch_authority(*authority, link->handoff, link->proof);
        auto* next = std::get_if<VerifiedEpochAuthority>(&advanced);
        if (next == nullptr) {
            error = "an authority chain link does not verify at epoch " +
                    std::to_string(authority->epoch.underlying());
            return std::nullopt;
        }
        authority = *next;
        authorities.emplace(authority->epoch, *authority);
    }

    // 3. The rollout records, each finalized under its own epoch.
    VerifiedRollout result;
    result.epoch = authority->epoch;
    result.genesis_public_key = genesis_public_key;
    result.network_id = network_id;
    for (std::size_t i = 0; i < proof.records.size(); ++i) {
        const auto message = decode_for(proof.records[i], network_id, SecurityMessageKind::Upgrade);
        const auto* upgrade = message ? std::get_if<UpgradeMsg>(&message->body) : nullptr;
        if (upgrade == nullptr || upgrade->topic != UpgradeTopic::RecordProof ||
            !upgrade->proof.has_value() || upgrade->proof->chain.empty()) {
            error = "rollout record " + std::to_string(i) + " carries no commit proof";
            return std::nullopt;
        }
        const auto record = decode_upgrade_record(upgrade->body);
        if (!record || record->network_id != network_id) {
            error = "rollout record " + std::to_string(i) + " does not decode for this network";
            return std::nullopt;
        }
        const EpochId epoch = upgrade->proof->chain.front().proposal.epoch;
        const auto judge = authorities.find(epoch);
        if (judge == authorities.end()) {
            error = "rollout record " + std::to_string(i) + " finalized in an unproven epoch";
            return std::nullopt;
        }
        const QcValidationContext context{constants::kConsensusRulesetVersion, network_id, epoch,
                                          judge->second.consensus_quorum};
        const BlockPayload payload{BlockPayloadKind::UpgradeProgress, upgrade->body};
        if (verify_commit_proof(block_payload_digest(payload), *upgrade->proof, context,
                                judge->second.vote_keys) != CommitProofFailure::None) {
            error = "rollout record " + std::to_string(i) + " has a commit proof that does not verify";
            return std::nullopt;
        }
        const UpgradeWitnessSet witnesses{network_id, epoch, judge->second.members};
        const bool first = i == 0;
        if (first && record->event != UpgradeEvent::Start) {
            error = "the rollout records do not begin with a Start record";
            return std::nullopt;
        }
        if (!first && record->event == UpgradeEvent::Start) {
            error = "the rollout records hold a second Start record";
            return std::nullopt;
        }
        const auto failure = check_upgrade_record(result.state, *record, &witnesses, first);
        if (failure != UpgradeRecordFailure::None) {
            error = "rollout record " + std::to_string(i) + " is refused: " +
                    std::string(upgrade_record_failure_name(failure));
            return std::nullopt;
        }
        apply_upgrade_record(result.state, *record);
    }
    return result;
}

bool rollout_complete(const VerifiedRollout& rollout, uint64_t release_number,
                      std::string& reason) {
    const auto& state = rollout.state;
    if (!state.active()) {
        reason = "no finalized rollout record";
        return false;
    }
    if (state.release_number != release_number) {
        reason = "the newest finalized rollout is release " + std::to_string(state.release_number) +
                 ", not " + std::to_string(release_number);
        return false;
    }
    if (state.halted) {
        reason = "the rollout of release " + std::to_string(release_number) + " halted";
        return false;
    }
    if (!state.complete()) {
        reason = "the rollout of release " + std::to_string(release_number) + " is open: " +
                 std::to_string(state.upgraded.size()) + " of " +
                 std::to_string(state.order.size()) + " servers upgraded";
        return false;
    }
    reason = "the rollout of release " + std::to_string(release_number) + " is complete";
    return true;
}

std::optional<PreviousRollout> previous_rollout_state(const VerifiedRollout& rollout,
                                                     uint64_t release_number,
                                                     const ReleaseApprovalBundleV1* previous,
                                                     std::string& reason) {
    const auto& state = rollout.state;
    if (!state.active() || state.release_number != release_number) {
        // rollout_complete names the mismatch.
        (void)rollout_complete(rollout, release_number, reason);
        return std::nullopt;
    }
    if (previous != nullptr) {
        std::string error;
        if (!verify_release_approval_signatures(*previous, rollout.genesis_public_key,
                                                rollout.network_id, error)) {
            reason = "the previous approval does not verify for this network: " + error;
            return std::nullopt;
        }
        if (previous->approval.release_number != release_number ||
            release_approval_digest(previous->approval) != state.approval_digest) {
            reason = "the previous approval is not the approval that the finalized Start "
                     "record of release " + std::to_string(release_number) + " names";
            return std::nullopt;
        }
    }
    if (state.halted) {
        if (previous == nullptr) {
            reason = "the rollout of release " + std::to_string(release_number) +
                     " halted; the halted approval is needed to check the fix";
            return std::nullopt;
        }
        reason = "the rollout of release " + std::to_string(release_number) + " halted: " +
                 std::to_string(state.upgraded.size()) + " of " +
                 std::to_string(state.order.size()) +
                 " servers run it, the others run the release before it";
        return PreviousRollout::Halted;
    }
    if (!rollout_complete(rollout, release_number, reason)) return std::nullopt;
    return PreviousRollout::Complete;
}

bool release_follows_rollout(const VerifiedRollout& rollout, uint64_t release_number,
                             const ReleaseApprovalBundleV1& previous,
                             const ReleaseApprovalV1& next, std::string& reason) {
    const auto state = previous_rollout_state(rollout, release_number, &previous, reason);
    if (!state) return false;
    const bool halted = *state == PreviousRollout::Halted;
    const auto& prior = previous.approval;
    if (next.network_id_hex != prior.network_id_hex ||
        next.signer_pubkey_b64 != prior.signer_pubkey_b64 ||
        next.network_id_hex != crypto::to_hex(rollout.network_id)) {
        reason = "the new approval names another network or release signer";
        return false;
    }
    if (next.release_number <= release_number) {
        reason = "the new approval's release number is not above " +
                 std::to_string(release_number);
        return false;
    }
    std::map<std::string, std::set<std::string>> required;
    for (const auto& path : release_overlap_paths(prior, halted)) {
        required[path.path].insert(path.sha256.begin(), path.sha256.end());
    }
    std::map<std::string, std::set<std::string>> carried;
    for (const auto& path : next.previous_release_paths) {
        if (!carried.emplace(path.path, std::set<std::string>(path.sha256.begin(), path.sha256.end()))
                 .second) {
            reason = "the new approval lists " + path.path + " twice as a previous path";
            return false;
        }
    }
    const std::set<std::string> none;
    for (const auto& path : next.approved_paths) {
        const auto want = required.find(path.path);
        const auto have = carried.find(path.path);
        const auto& want_set = want == required.end() ? none : want->second;
        const auto& have_set = have == carried.end() ? none : have->second;
        if (want_set != have_set) {
            reason = "the new approval's previous hashes for " + path.path +
                     (halted ? " are not exactly those of the halted release and the release "
                               "before it"
                             : " are not exactly those of the previous release");
            return false;
        }
        if (have != carried.end()) carried.erase(have);
    }
    if (!carried.empty()) {
        reason = "the new approval lists a previous path it does not approve: " +
                 carried.begin()->first;
        return false;
    }
    reason += halted ? "; the new approval covers both releases"
                     : "; the new approval overlaps with exactly the previous release";
    return true;
}

}  // namespace nexus::security
