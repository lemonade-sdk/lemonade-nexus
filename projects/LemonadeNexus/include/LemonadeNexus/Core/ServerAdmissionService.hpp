#pragma once

#include <LemonadeNexus/Core/AdmissionTokenStore.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Core/TrustTypes.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; class KeyWrappingService; }
namespace nexus::storage { class FileStorageService; }
namespace nexus::gossip { class GossipService; }
namespace nexus::core { struct ServerConfig; }

namespace nexus::core {

/// Domain-separation tags for the candidate-signed poll and ack endpoints.
/// Both endpoints sign one canonical shape (canonical_poll); the tag is the
/// only field keeping a captured poll signature unusable as an ack. Every
/// verifier must use these constants — never a re-typed literal.
inline constexpr const char* kOnboardPollTag = "ln-onboard-poll:v1";
inline constexpr const char* kOnboardAckTag  = "ln-onboard-ack:v1";

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
    enum class State : uint8_t { Pending, Approved, Denied, Expired, Completed };
    [[nodiscard]] static const char* state_name(State s);

    struct Admission {
        std::string request_id;
        std::string candidate_pubkey;   // base64 Ed25519 gossip key
        std::string server_id;          // requested DNS label
        std::string region;
        std::string tpm_ak_pubkey;      // optional (Tier1-capable cert)
        std::string tpm_ek_cert;        // optional
        // Platform evidence the candidate claimed and we verified before issuing.
        std::string platform_class;     // "", "tpm2", "snp-vtpm"
        std::string measurement;        // hex SNP launch measurement
        std::string binary_hash;        // hex SHA-256, IMA-confirmed at approval
        std::string evidence_sha256;    // hex; signed by the candidate, binds `evidence`
        std::string evidence;           // the bundle itself — stored, never gossiped
        std::string challenge_nonce;    // the nonce the evidence quote is bound to
        std::string source_ip;
        State       state{State::Pending};
        uint64_t    created_at{0};
        uint64_t    expires_at{0};
        std::string issued_cert_json;   // set when Approved
        std::string decision_reason;
        std::string decided_by;         // "token" | "admin" ("ballot" in historical records)
        std::string decision_mode;      // always "sole" now ("ballot" in historical records)
    };

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

    struct RequestInput {
        std::string candidate_pubkey;
        std::string server_id;
        std::string region;
        std::string tpm_ak_pubkey;
        std::string tpm_ek_cert;
        std::string platform_class;
        std::string measurement;
        std::string binary_hash;
        /// Hex SHA-256 of `evidence`. The digest rather than the bundle is what the
        /// candidate signs, so the several-kilobyte bundle stays out of the signed
        /// canonical while remaining bound to the signature.
        std::string evidence_sha256;
        std::string evidence;     // full bundle, HTTP only; checked against the digest
        std::string nonce;        // echoed from the challenge
        uint64_t    timestamp{0};
        std::string signature;    // base64 Ed25519 over the canonical request
        std::string source_ip;
        std::string enrollment_token;  // optional; not part of the signed canonical
    };
    struct Result {
        bool ok{false}; int status{200}; std::string error; std::string request_id;
    };

    /// Verify PoP + caps, create (or idempotently refresh) a PendingAdmission.
    /// A valid bound enrollment token admits immediately; otherwise an admin
    /// resolves it via approve()/deny().
    [[nodiscard]] Result create_request(const RequestInput& in);

    /// Mint a single-use server-admission token (root holder only — returns
    /// nullopt unless accepts_onboarding()). Empty candidate_pubkey = unbound.
    [[nodiscard]] std::optional<std::pair<std::string, AdmissionTokenRecord>>
    mint_admission_token(const std::string& candidate_pubkey, std::chrono::seconds ttl,
                         const std::string& server_id = {});

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

    /// Canonical bytes a candidate signs for create_request (tag "ln-onboard:v2").
    /// The ONE definition: the onboarding client and this server both call this
    /// rather than open-coding the field order, which is how v1 drifted.
    [[nodiscard]] static std::vector<uint8_t> canonical_request(const RequestInput& in);

    /// Rebuild the signed input from a request body, so the receiver recomputes
    /// exactly the bytes the candidate signed.
    [[nodiscard]] static RequestInput request_from_claim(const nlohmann::json& claim);

    /// The self-signed claim an onboarding request body carries. Excludes the
    /// evidence bundle (bound by digest, sent alongside) and the enrollment
    /// token (a bearer credential, never part of the signed canonical).
    [[nodiscard]] static nlohmann::json claim_from_request(const RequestInput& in);
    /// Canonical bytes a candidate signs for status/ack (tag "ln-onboard-poll:v1").
    [[nodiscard]] static std::vector<uint8_t> canonical_poll(const std::string& tag,
                                                             const std::string& request_id,
                                                             uint64_t timestamp);

private:
    void sweep_expired();
    void persist();
    void load();
    [[nodiscard]] Result do_approve_locked(Admission& a, const std::string& decided_by,
                                           bool supersede);
    /// Check the platform evidence a candidate submitted and derive the policy to
    /// bake into its certificate. nullopt = refuse to issue; the reason lands in
    /// `a.decision_reason`.
    [[nodiscard]] std::optional<PeerPlatformBinding> verify_admission_evidence(
        Admission& a) const;
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
    std::unordered_map<std::string, Admission> admissions_;   // by request_id
    std::unordered_map<std::string, uint64_t>  nonces_;       // candidate_pubkey -> expiry
    std::unordered_map<std::string, std::string> nonce_values_; // candidate_pubkey -> nonce
    std::unordered_map<std::string, uint64_t>  denied_until_; // candidate_pubkey -> cooldown end
    bool ever_approved_{false};
};

} // namespace nexus::core
