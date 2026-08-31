#pragma once

// Durable mesh-eligibility observations.
//
// Two rules the file format exists to serve. A restart must not invent history:
// an absent file yields no observations, and no observations means no facts.
// And a restart must not lose the distinction between "nothing was stored" and
// "what was stored is damaged" — Corrupt is reported as Corrupt, so a node
// cannot treat lost eligibility state as a clean slate.
//
// Loading re-verifies every signature through EligibilityLedger::restore, so an
// edited file cannot assert a fact no observer signed. Storage holds bytes;
// trust comes from the signatures inside them.

#include <LemonadeNexus/Security/Eligibility/EligibilityLedger.hpp>

#include <filesystem>
#include <map>
#include <set>
#include <variant>
#include <vector>

namespace nexus::security {

enum class EligibilityLoadResult { Absent, Corrupt };

class EligibilityStore {
public:
    explicit EligibilityStore(std::filesystem::path directory);

    /// Replaces the stored observations for `epoch`. Crash-atomic.
    [[nodiscard]] bool store(EpochId epoch,
                             const std::vector<EligibilityLedger::PersistedRecord>& records);

    /// Loads and re-validates into `ledger`. A file for another epoch is
    /// Absent, not Corrupt: observations expire at the boundary, so an older
    /// file is expected rather than damaged.
    [[nodiscard]] std::variant<std::monostate, EligibilityLoadResult> load(
        EpochId epoch, const MeshFactContext& context, EligibilityLedger& ledger) const;

    /// Removes stored observations for epochs before `epoch`.
    void discard_before(EpochId epoch);

    /// Proved faults, which are NOT epoch-scoped. A fault is a fact about a
    /// node identity, so it outlives the epoch that proved it and there is no
    /// transition back: nothing here clears one.
    [[nodiscard]] bool store_faults(const std::map<NodeId, std::set<ObjectiveFault>>& faults);

    /// Loads the fault file. Absent means no fault was ever proved; Corrupt
    /// means the file exists and cannot be believed, which the caller must fail
    /// closed on rather than read as "no faults".
    [[nodiscard]] std::variant<std::map<NodeId, std::set<ObjectiveFault>>, EligibilityLoadResult>
    load_faults() const;

    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    [[nodiscard]] std::filesystem::path path_for(EpochId epoch) const;

    std::filesystem::path directory_;
};

}  // namespace nexus::security
