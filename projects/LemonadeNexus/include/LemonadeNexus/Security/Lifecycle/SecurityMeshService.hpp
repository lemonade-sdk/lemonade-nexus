#pragma once

// The ownership shell around the new security stack.
//
// This service owns the runtime, the router, the store, the evidence
// producer, and the driver, wires them to the gossip transport, and paces the
// driver from a timer. It makes no security decision: it is ownership,
// timers, and wiring. Everything security runs on the io thread — the
// transport sink, the peer-certified callback, and the tick.

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseChain.hpp>
#include <LemonadeNexus/Security/Epoch/EpochStore.hpp>
#include <LemonadeNexus/Security/Genesis/GenesisService.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityDriver.hpp>
#include <LemonadeNexus/Security/SecurityRuntime.hpp>
#include <LemonadeNexus/Security/Storage/StorageKeyService.hpp>
#include <LemonadeNexus/Security/Storage/StorageShareStore.hpp>
#include <LemonadeNexus/Security/Transport/PairwiseSeal.hpp>
#include <LemonadeNexus/Security/Transport/SecurityRouter.hpp>
#include <LemonadeNexus/Security/Upgrade/UpgradeService.hpp>

#include <asio.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string_view>
#include <vector>

namespace nexus::security {

// Liveness pacing only: the tick drives retries and windows inside the
// driver and never affects the validity of any message.
inline constexpr uint64_t kDriverTickMs = 100;

struct SecurityMeshConfig {
    std::filesystem::path data_root;
    // The pinned bootstrap anchor. Verification only; its authority ends at
    // Epoch 1 activation (architecture 14).
    crypto::Ed25519PublicKey genesis_public_key{};
    // The gossip identity keypair: the node identity on the security wire.
    crypto::Ed25519Keypair identity{};
    LinuxAttestationProfile profile;
    /// Digest of the verified release approval this process loaded, all-zero
    /// when none is packaged. A new founding commits it through the bootstrap
    /// certificate.
    Digest release_approval_digest{};
    /// The verified packaged release approval, or nullopt. When set, the
    /// service keeps the release chain (ReleaseChain): the attestation profile
    /// then comes from the newest accepted approval, a newer approval from a
    /// peer or the updater is adopted at runtime, and a stored bootstrap
    /// certificate is accepted when its founding approval carries the pinned
    /// release signer.
    std::optional<ReleaseApprovalBundleV1> installed_release;
    /// Where platform evidence comes from. Unset means this process collects
    /// it itself, which needs TPM and IMA access here; the assembled server
    /// sets it to the nexus-attestd socket so it needs neither. There is no
    /// fallback: once set, a helper that fails yields empty evidence and the
    /// verifier refuses it.
    PlatformEvidenceSource platform_source;
    /// Where SVSM AK credential activation runs. Same daemon, same rule: the
    /// server process holds no TPM device. Unset means the candidate cannot
    /// complete enrollment and the producer refuses the offer.
    PlatformActivationSource activation_source;
    /// Fires when this node first holds finalized epoch authority (entry into
    /// Active, or genesis certificate issuance). io-thread context.
    std::function<void()> on_epoch_established;
    /// How the storage share is sealed (B6, B7 step 1): the boot set's backend
    /// (attestd_seal_backend in production). Empty means this host cannot
    /// seal; the share then stays in the machine-bound file store.
    SealBackend seal_backend;
    /// The boot set's SealedBlobStore directory (Core/BootSet.hpp
    /// kSealedDirectory under the data root).
    std::filesystem::path sealed_directory;
    /// Expected PCR 8/9 of the installed, verified release approval; staged
    /// for the share like for the gossip identity. nullopt stages nothing.
    std::optional<BootPcrValues> next_boot_chain;
    /// Files encrypted under the data key (Phase 7), or nullptr. Not owning;
    /// must outlive the service.
    StorageVault* vault = nullptr;
};

class SecurityMeshService : public core::IService<SecurityMeshService> {
    friend class core::IService<SecurityMeshService>;

public:
    SecurityMeshService(asio::io_context& io, const SecurityMeshConfig& config,
                        gossip::GossipService& transport,
                        crypto::KeyWrappingService* wrapping);
    /// Detaches the vault from the data key service this object owns.
    ~SecurityMeshService();
    SecurityMeshService(const SecurityMeshService&) = delete;
    SecurityMeshService& operator=(const SecurityMeshService&) = delete;

    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "SecurityMeshService"; }

    [[nodiscard]] const SecurityDriver& driver() const { return driver_; }

    /// True when `node` is in the current epoch's frozen Tier 1 set. The mesh
    /// decided that; consumers only read it.
    ///
    /// Answered from a snapshot under a lock, NOT from the live EpochManager.
    /// Callers reach this from other threads — the HTTP worker serving a DDNS
    /// credential request is one — while the io thread destroys and rebuilds
    /// that manager on every epoch activation. Reading it directly is a race.
    /// The snapshot is refreshed on the io thread each tick, so it trails a
    /// membership change by at most one tick.
    [[nodiscard]] bool is_current_member(const NodeId& node) const {
        std::lock_guard lock(members_mutex_);
        return std::find(current_members_.begin(), current_members_.end(), node) !=
               current_members_.end();
    }
    [[nodiscard]] SecurityRuntime& runtime() { return runtime_; }

    /// A copy of the current Tier 1 membership snapshot (see
    /// is_current_member). Thread-safe.
    [[nodiscard]] std::vector<NodeId> current_members() const {
        std::lock_guard lock(members_mutex_);
        return current_members_;
    }

    /// Registers a block payload handler with the driver
    /// (SecurityDriver::register_payload_handler). Not owning. Call before the
    /// io context runs.
    void register_payload_handler(IBlockPayloadHandler& handler) {
        driver_.register_payload_handler(handler);
    }

    /// Where tree operations forwarded by Tier 1 members go (io thread).
    void set_tree_op_sink(std::function<void(const TreeOpSubmitMsg&, const NodeId&)> sink) {
        driver_.set_tree_op_sink(std::move(sink));
    }

    /// Forwards a tree operation to every peer; the receivers' routers accept
    /// it only from current Tier 1 members. Thread-safe: the send runs on the
    /// io thread.
    void broadcast_tree_op(TreeOpSubmitMsg message);

    /// The verified authority of `epoch` (SecurityDriver::authority_for_epoch).
    /// io thread.
    [[nodiscard]] std::optional<VerifiedEpochAuthority> authority_for_epoch(EpochId epoch) const {
        return driver_.authority_for_epoch(epoch);
    }

    /// An unauthenticated epoch hint (SecurityDriver::note_epoch_hint). io
    /// thread.
    void note_epoch_hint(EpochId epoch) { driver_.note_epoch_hint(epoch); }

    /// Runs `work` on the io thread, unless the service has stopped.
    /// Thread-safe.
    void post(std::function<void()> work);

    /// Runs on the io thread after every driver tick. Call before the io
    /// context runs.
    void set_tick_hook(std::function<void()> hook) { tick_hook_ = std::move(hook); }

    /// The storage key service. Always built: the threshold storage key is not
    /// optional. Its DataKeyService reads (state, data_key) are thread-safe;
    /// everything else runs on the io thread.
    [[nodiscard]] StorageKeyService* storage_key() { return storage_.get(); }

    /// Release adoption and upgrade turns. Always built. io thread only;
    /// other threads reach it through post().
    [[nodiscard]] UpgradeService* upgrade() { return upgrade_.get(); }

    /// The release chain, or nullptr without a packaged approval. io thread.
    [[nodiscard]] const ReleaseChain* release_chain() const { return release_chain_.get(); }

private:
    // The router needs its events sink at construction and the driver needs
    // the router. The proxy breaks the cycle.
    struct EventsProxy final : ISecurityEvents {
        ISecurityEvents* target = nullptr;
        void on_vote_sent(const Vote& v, const NodeId& n) override {
            if (target) target->on_vote_sent(v, n);
        }
        void on_certificate(const QuorumCertificate& q) override {
            if (target) target->on_certificate(q);
        }
        void on_justify_quorum(const QuorumCertificate& q) override {
            if (target) target->on_justify_quorum(q);
        }
        void on_timeout_certificate(const TimeoutCertificate& t) override {
            if (target) target->on_timeout_certificate(t);
        }
        void on_commits(const std::vector<ConsensusCommit>& c) override {
            if (target) target->on_commits(c);
        }
        void on_dkg_round1_complete(EpochId e) override {
            if (target) target->on_dkg_round1_complete(e);
        }
        void on_dkg_complete(EpochId e) override {
            if (target) target->on_dkg_complete(e);
        }
        void on_dkg_failed(DkgFailure f, std::optional<NodeId> c) override {
            if (target) target->on_dkg_failed(f, c);
        }
        void on_authority_signature(const AuthoritySignature& s) override {
            if (target) target->on_authority_signature(s);
        }
        void on_attestation_verdict(const AttestationVerdict& v,
                                    const AttestationEvidence& e) override {
            if (target) target->on_attestation_verdict(v, e);
        }
        void on_epoch_announcement(const EpochAnnouncement& a, const NodeId& n) override {
            if (target) target->on_epoch_announcement(a, n);
        }
        void on_genesis_founding(const GenesisFounding& f, const NodeId& n) override {
            if (target) target->on_genesis_founding(f, n);
        }
        void on_dkg_transcript_attest(const DkgTranscriptAttest& a) override {
            if (target) target->on_dkg_transcript_attest(a);
        }
        void on_bootstrap_certificate(const BootstrapCertificate& c, const NodeId& n) override {
            if (target) target->on_bootstrap_certificate(c, n);
        }
        void on_sync_certificate(const QuorumCertificate& q, const NodeId& n) override {
            if (target) target->on_sync_certificate(q, n);
        }
        void on_vote_accepted(const Vote& v) override {
            if (target) target->on_vote_accepted(v);
        }
        void on_eligibility_observation(const EligibilityObservation& o) override {
            if (target) target->on_eligibility_observation(o);
        }
        void on_genesis_eligibility_attest(const GenesisEligibilityAttest& a) override {
            if (target) target->on_genesis_eligibility_attest(a);
        }
        void on_participation_challenge(const ParticipationChallenge& c,
                                        const NodeId& n) override {
            if (target) target->on_participation_challenge(c, n);
        }
        void on_participation_response(const ParticipationResponse& r) override {
            if (target) target->on_participation_response(r);
        }
        void on_next_epoch_plan(const NextEpochPlanProof& p) override {
            if (target) target->on_next_epoch_plan(p);
        }
        void on_candidate_state_ready(const CandidateStateReadyMsg& m) override {
            if (target) target->on_candidate_state_ready(m);
        }
        void on_readiness_proof(const ReadinessProofMsg& m) override {
            if (target) target->on_readiness_proof(m);
        }
        void on_epoch_handoff_proof(const EpochHandoffProofMsg& m) override {
            if (target) target->on_epoch_handoff_proof(m);
        }
        void on_candidate_sync_response(const SyncResponse& s, const NodeId& n) override {
            if (target) target->on_candidate_sync_response(s, n);
        }
        void on_authority_chain_request(const AuthorityChainRequest& r,
                                        const NodeId& n) override {
            if (target) target->on_authority_chain_request(r, n);
        }
        void on_authority_chain_page(const AuthorityChainPage& p, const NodeId& n) override {
            if (target) target->on_authority_chain_page(p, n);
        }
        void on_tree_op_submit(const TreeOpSubmitMsg& m, const NodeId& n) override {
            if (target) target->on_tree_op_submit(m, n);
        }
        void on_storage_message(const SecurityMessage& m) override {
            if (target) target->on_storage_message(m);
        }
        void on_upgrade_message(const SecurityMessage& m) override {
            if (target) target->on_upgrade_message(m);
        }
    };

    [[nodiscard]] uint64_t now_ms() const;
    void arm_timer();

    SecurityMeshConfig config_;
    gossip::GossipService& transport_;

    // Construction order is load-bearing: the router takes the producer's
    // address, and the producer's vote-key source calls into the driver.
    SecurityRuntime runtime_;
    PairwiseSealer sealer_;
    EpochStore store_;
    // Only the node whose identity IS the pinned anchor holds the one-shot
    // Genesis authority.
    std::unique_ptr<GenesisService> genesis_;
    EventsProxy events_;
    SecurityRouter router_;
    PlatformEvidenceProducer producer_;
    SecurityDriver driver_;

    // The threshold storage key. Built after the driver it registers with;
    // the router reaches it only through the address-captured challenge gate.
    std::unique_ptr<crypto::SodiumCryptoService> storage_crypto_;
    std::unique_ptr<SealedBlobStore> sealed_blobs_;
    std::unique_ptr<FileStorageShareStore> file_share_store_;
    std::unique_ptr<IStorageShareStore> share_store_;
    std::unique_ptr<StorageKeyService> storage_;
    StorageVault* vault_ = nullptr;

    // Release adoption and upgrade turns. The driver reaches the chain only
    // through the address-captured release_commitment callback.
    std::unique_ptr<ReleaseChain> release_chain_;
    std::unique_ptr<UpgradeService> upgrade_;

    /// Installs the attestation profile of the newest accepted approval, or
    /// the incomplete compiled template when the chain holds none.
    void install_release_profile();

    asio::steady_timer timer_;
    std::chrono::steady_clock::time_point started_at_{};
    bool running_ = false;

    /// Cross-thread view of current Tier 1 membership. Written on the io thread
    /// by refresh_members(), read by is_current_member() from any thread.
    mutable std::mutex members_mutex_;
    std::vector<NodeId> current_members_;

    std::function<void()> tick_hook_;

    /// Copy the live membership into the snapshot. io thread only.
    void refresh_members();
};

}  // namespace nexus::security
