#pragma once

#include <LemonadeNexus/Core/IService.hpp>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; class KeyWrappingService; }
namespace nexus::storage { class FileStorageService; }
namespace nexus::gossip { class GossipService; }
namespace nexus::core { struct ServerConfig; class TrustPolicyService; }

namespace nexus::core {

/// Governs admission of a new SERVER to the mesh. A candidate proves possession
/// of its gossip key (challenge → signed request), the request parks as a
/// PendingAdmission, and the root-key holder decides (sole discretion below the
/// vote threshold, governed ballot above). On approval the root key signs a
/// ServerCertificate the candidate collects and installs — no manual file copy.
class ServerAdmissionService : public IService<ServerAdmissionService> {
    friend class IService<ServerAdmissionService>;

public:
    enum class State : uint8_t { Pending, Approved, Denied, Expired, Completed };
    [[nodiscard]] static const char* state_name(State s);

    struct Admission {
        std::string request_id;
        std::string candidate_pubkey;   // base64 Ed25519 gossip key
        std::string server_id;          // requested DNS label
        std::string region;
        std::string tpm_ak_pubkey;      // optional (Tier1-capable cert)
        std::string tpm_ek_cert;        // optional
        std::string source_ip;
        State       state{State::Pending};
        uint64_t    created_at{0};
        uint64_t    expires_at{0};
        std::string issued_cert_json;   // set when Approved
        std::string decision_reason;
        std::string decided_by;         // "auto" | "admin" | "ballot"
        std::string ballot_claim_json;  // candidate self-signed claim (vote regime)
    };

    struct Config {
        bool     enabled{true};
        bool     auto_approve_bootstrap{true};
        float    admission_quorum_ratio{0.75f};
        uint32_t min_tier1_for_vote{6};
        uint32_t request_ttl_sec{3600};
        uint32_t max_pending{8};
        uint32_t nonce_ttl_sec{300};
        uint32_t denied_cooldown_sec{86400};
    };

    ServerAdmissionService(const ServerConfig& config,
                           crypto::SodiumCryptoService& crypto,
                           crypto::KeyWrappingService& key_wrapping,
                           storage::FileStorageService& storage,
                           gossip::GossipService& gossip,
                           TrustPolicyService* trust_policy);

    // --- IService ---
    void on_start();
    void on_stop();
    [[nodiscard]] std::string_view name() const { return "ServerAdmissionService"; }

    /// True when this server holds the root key and onboarding is enabled.
    [[nodiscard]] bool accepts_onboarding() const;

    /// "sole_discretion" or "vote" given the current eligible-voter count.
    [[nodiscard]] std::string regime() const;
    [[nodiscard]] uint32_t eligible_voter_count() const;

    /// Issue a single-use challenge nonce (base64) for a candidate pubkey.
    [[nodiscard]] std::string issue_challenge(const std::string& candidate_pubkey);

    struct RequestInput {
        std::string candidate_pubkey;
        std::string server_id;
        std::string region;
        std::string tpm_ak_pubkey;
        std::string tpm_ek_cert;
        std::string nonce;        // echoed from the challenge
        uint64_t    timestamp{0};
        std::string signature;    // base64 Ed25519 over the canonical request
        std::string source_ip;
    };
    struct Result {
        bool ok{false}; int status{200}; std::string error; std::string request_id;
        bool needs_ballot{false};  // caller should invoke start_pending_ballot()
    };

    /// Verify PoP + caps, create (or idempotently refresh) a PendingAdmission.
    /// Below the vote threshold with the bootstrap window open, auto-approves.
    [[nodiscard]] Result create_request(const RequestInput& in);

    /// Open the governed Tier1 ballot for a request that needs one (called by
    /// the handler after create_request returns, so no lock is held).
    void start_pending_ballot(const std::string& request_id);

    /// Ballot decision hook (wired to GossipService's decision callback).
    void on_ballot_decision(const std::string& request_id, bool approved,
                            const std::string& reason);

    /// Candidate polls its request; fills cert bundle when approved.
    [[nodiscard]] std::optional<Admission> status(const std::string& request_id,
                                                  const std::string& candidate_pubkey);

    /// Candidate acknowledges receipt → Completed (audit retained).
    [[nodiscard]] bool acknowledge(const std::string& request_id,
                                   const std::string& candidate_pubkey);

    // --- Admin (sole discretion) ---
    [[nodiscard]] std::vector<Admission> pending() const;
    [[nodiscard]] Result approve(const std::string& request_id,
                                 const std::string& pubkey_or_fingerprint,
                                 bool supersede);
    [[nodiscard]] Result deny(const std::string& request_id, const std::string& reason);

    /// Canonical bytes a candidate signs for create_request (tag "ln-onboard:v1").
    [[nodiscard]] static std::vector<uint8_t> canonical_request(const RequestInput& in);
    /// Canonical bytes a candidate signs for status/ack (tag "ln-onboard-poll:v1").
    [[nodiscard]] static std::vector<uint8_t> canonical_poll(const std::string& tag,
                                                             const std::string& request_id,
                                                             uint64_t timestamp);

private:
    void sweep_expired();
    void persist();
    void load();
    [[nodiscard]] bool ever_approved() const;
    [[nodiscard]] Result do_approve_locked(Admission& a, const std::string& decided_by,
                                           bool supersede);
    [[nodiscard]] bool verify_sig(const std::string& pubkey_b64,
                                  const std::vector<uint8_t>& msg,
                                  const std::string& sig_b64) const;

    const ServerConfig&            config_;
    crypto::SodiumCryptoService&   crypto_;
    crypto::KeyWrappingService&    key_wrapping_;
    storage::FileStorageService&   storage_;
    gossip::GossipService&         gossip_;
    TrustPolicyService*            trust_policy_{nullptr};
    Config                         cfg_;

    mutable std::mutex mu_;
    std::unordered_map<std::string, Admission> admissions_;   // by request_id
    std::unordered_map<std::string, uint64_t>  nonces_;       // candidate_pubkey -> expiry
    std::unordered_map<std::string, std::string> nonce_values_; // candidate_pubkey -> nonce
    std::unordered_map<std::string, uint64_t>  denied_until_; // candidate_pubkey -> cooldown end
    bool ever_approved_{false};
};

} // namespace nexus::core
