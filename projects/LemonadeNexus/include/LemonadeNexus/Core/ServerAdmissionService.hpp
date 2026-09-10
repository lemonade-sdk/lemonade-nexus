#pragma once

#include <LemonadeNexus/Core/AdmissionTokenStore.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Core/OnboardingTypes.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/TrustTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace nexus::core {

/// Governs admission of a new SERVER. A candidate proves possession of its
/// gossip key (challenge → signed request), the request parks as a
/// PendingAdmission, and the root-key holder decides — admin approve/deny or a
/// pre-minted single-use token. Approval mints only the root-signed Tier-2
/// TRANSPORT certificate: this is operator provisioning, not mesh authority.
/// Tier-1 authority lives in the mesh security system (SecurityRuntime /
/// HotStuff / FROST); the old gossip admission ballot is gone.
class ServerAdmissionService : public IService<ServerAdmissionService> {
    friend class IService<ServerAdmissionService>;

public:
    /// The network every issued certificate binds to, as hex. Approval refuses
    /// to issue until this is set: an unbound certificate validates nowhere.
    void set_network_id(const std::string& network_hex) { network_id_hex_ = network_hex; }

    struct Config {
        bool     enabled{true};
        uint32_t request_ttl_sec{3600};
        uint32_t max_pending{8};
        uint32_t nonce_ttl_sec{300};
        uint32_t denied_cooldown_sec{86400};
    };

    ServerAdmissionService(const ServerConfig& config,
                           crypto::SodiumCryptoService& crypto,
                           crypto::KeyWrappingService& key_wrapping,
                           storage::FileStorageService& storage,
                           gossip::GossipService& gossip);

    // --- IService ---
    void on_start();
    void on_stop();
    [[nodiscard]] std::string_view name() const { return "ServerAdmissionService"; }

    /// True when this server holds the root key and onboarding is enabled.
    [[nodiscard]] bool accepts_onboarding() const;

    /// Issue a single-use challenge nonce (base64) for a candidate pubkey.
    [[nodiscard]] std::string issue_challenge(const std::string& candidate_pubkey);

    struct Result {
        bool ok{false}; int status{200}; std::string error; std::string request_id;
    };

    /// Verify PoP + caps, create (or idempotently refresh) a PendingAdmission.
    /// A valid bound enrollment token admits immediately; otherwise an admin
    /// resolves it via approve()/deny().
    [[nodiscard]] Result create_request(const AdmissionRequest& request,
                                        const std::string& source_ip = {});

    /// Mint a single-use server-admission token (root holder only — returns
    /// nullopt unless accepts_onboarding()). Empty candidate_pubkey = unbound.
    [[nodiscard]] std::optional<std::pair<std::string, AdmissionTokenRecord>>
    mint_admission_token(const std::string& candidate_pubkey, std::chrono::seconds ttl,
                         const std::string& server_id = {});

    /// Candidate polls its request; fills cert bundle when approved.
    [[nodiscard]] std::optional<AdmissionRecord> status(
        const std::string& request_id, const std::string& candidate_pubkey);

    /// Candidate acknowledges receipt → Completed (audit retained).
    [[nodiscard]] bool acknowledge(const std::string& request_id,
                                   const std::string& candidate_pubkey);

    // --- Admin (sole discretion) ---
    [[nodiscard]] std::vector<AdmissionRecord> pending() const;
    [[nodiscard]] Result approve(const std::string& request_id,
                                 const std::string& pubkey_or_fingerprint,
                                 bool supersede);
    [[nodiscard]] Result deny(const std::string& request_id, const std::string& reason);

private:
    void sweep_expired();
    void persist();
    void load();
    [[nodiscard]] Result do_approve_locked(AdmissionRecord& a,
                                           const std::string& decided_by,
                                           bool supersede);
    /// Check the platform evidence a candidate submitted and derive the policy to
    /// bake into its certificate. nullopt = refuse to issue; the reason lands in
    /// `a.decision_reason`.
    [[nodiscard]] std::optional<PeerPlatformBinding> verify_admission_evidence(
        AdmissionRecord& a) const;
    [[nodiscard]] bool verify_sig(const std::string& pubkey_b64,
                                  const std::vector<uint8_t>& msg,
                                  const std::string& sig_b64) const;

    const ServerConfig&            config_;
    crypto::SodiumCryptoService&   crypto_;
    crypto::KeyWrappingService&    key_wrapping_;
    storage::FileStorageService&   storage_;
    gossip::GossipService&         gossip_;
    Config                         cfg_;
    AdmissionTokenStore            tokens_;

    /// True iff this server's local identity IS the configured root anchor.
    /// Computed once in on_start(); gates all certificate issuance.
    bool is_root_key_holder_{false};

    mutable std::mutex mu_;
    std::unordered_map<std::string, AdmissionRecord> admissions_;   // by request_id
    std::unordered_map<std::string, uint64_t>  nonces_;       // candidate_pubkey -> expiry
    std::unordered_map<std::string, std::string> nonce_values_; // candidate_pubkey -> nonce
    std::unordered_map<std::string, uint64_t>  denied_until_; // candidate_pubkey -> cooldown end
    bool ever_approved_{false};
    std::string network_id_hex_;
};

} // namespace nexus::core
