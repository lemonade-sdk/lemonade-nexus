#pragma once

// Durable consensus storage.
//
// The safety file is what stops a restarted node from voting twice in one
// view. Every write is crash-atomic, every load fails closed, and a stored
// value never moves backwards.
//
// The chain file keeps the blocks the stored high certificate names. Without
// them, a committee that restarts at once holds a certificate over a block no
// member has, and no leader can propose on it again. The chain file is
// recovery data, not safety state: a missing or damaged one only means the
// blocks come from peers through restart sync.
//
// Architecture reference: Security Architecture Final Draft 1.1, section 19.

#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <filesystem>
#include <optional>
#include <variant>

namespace nexus::security {

// A virtual interface, not the repository CRTP pattern: HotStuffService must
// run against a recording fake in tests, and the cost is one indirect call
// per vote.
class IConsensusStore {
public:
    virtual ~IConsensusStore() = default;

    // False means the state is not on disk. The caller MUST NOT vote.
    [[nodiscard]] virtual bool store_before_vote(const HotStuffState& state) = 0;

    enum class LoadResult { Absent, Corrupt };

    // Absent: nothing was ever stored for this epoch. Corrupt: something is
    // there but cannot be trusted. Corrupt is NOT Absent — treating corrupt
    // safety state as fresh would re-enable double voting after a disk
    // rollback.
    [[nodiscard]] virtual std::variant<HotStuffState, LoadResult> load(EpochId epoch) const = 0;

    virtual bool store_commit(const ConsensusCommit& commit) = 0;

    [[nodiscard]] virtual std::optional<ConsensusCommit> latest_commit(EpochId epoch) const = 0;

    /// Stores the certified blocks below the high certificate: the
    /// uncommitted chain, oldest first, with `chain.certifying` over its last
    /// block. Replaces the previous chain record of `epoch`. False when the
    /// chain is empty, longer than kMaxSyncChainBlocks, or not on disk; the
    /// caller then MUST NOT store a safety state that names the new high
    /// certificate.
    [[nodiscard]] virtual bool store_chain(EpochId epoch, const CertifiedChain& chain) = 0;

    /// The stored chain of `epoch`. Absent: nothing stored, for example state
    /// from a release that stored no blocks. Corrupt: a record is there but
    /// does not parse or verify. The record is not authority either way: the
    /// caller validates every certificate before it adopts a block.
    [[nodiscard]] virtual std::variant<CertifiedChain, LoadResult> load_chain(
        EpochId epoch) const = 0;
};

// One directory, one file per epoch and kind:
//   hotstuff-safety-<epoch>.json
//   hotstuff-commit-<epoch>.json
//   hotstuff-chain-<epoch>.json
// The chain file holds block headers and certificates only, never a block
// payload: the store must be readable before the data key unlocks, and a
// payload can carry application data the storage vault keeps encrypted.
class FileConsensusStore final : public IConsensusStore {
public:
    // Creates the directory when it does not exist.
    explicit FileConsensusStore(std::filesystem::path directory);

    // Refuses (false) when the new state would regress the stored one: a
    // lower last_voted_view, a lower high_qc or locked_qc view, or another
    // epoch. A regression means a logic error or a rolled-back disk — voting
    // must stop, not proceed.
    [[nodiscard]] bool store_before_vote(const HotStuffState& state) override;

    [[nodiscard]] std::variant<HotStuffState, LoadResult> load(EpochId epoch) const override;

    bool store_commit(const ConsensusCommit& commit) override;

    [[nodiscard]] std::optional<ConsensusCommit> latest_commit(EpochId epoch) const override;

    [[nodiscard]] bool store_chain(EpochId epoch, const CertifiedChain& chain) override;

    [[nodiscard]] std::variant<CertifiedChain, LoadResult> load_chain(
        EpochId epoch) const override;

private:
    [[nodiscard]] std::filesystem::path safety_path(EpochId epoch) const;
    [[nodiscard]] std::filesystem::path commit_path(EpochId epoch) const;
    [[nodiscard]] std::filesystem::path chain_path(EpochId epoch) const;

    std::filesystem::path directory_;
};

}  // namespace nexus::security
