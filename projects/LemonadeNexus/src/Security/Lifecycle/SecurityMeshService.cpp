#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Attestation/AmdRevocationCache.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>
#include <LemonadeNexus/Security/Upgrade/RolloutProof.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <future>
#include <memory>

#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>

namespace nexus::security {

namespace {

[[nodiscard]] NodeId self_id(const SecurityMeshConfig& config) {
    NodeId id;
    id.bytes = config.identity.public_key;
    return id;
}

// The network identity binds the pinned anchor and the compiled rulesets;
// every security object on this node binds to it.
[[nodiscard]] NetworkId mesh_network_id(const SecurityMeshConfig& config) {
    return derive_network_id(config.genesis_public_key, constants::kSecurityRulesetVersion,
                             constants::kConsensusRulesetVersion);
}

// The anchor's identity is network state: every node of this network can name
// it, and during the genesis window only it may issue a remote challenge.
[[nodiscard]] NodeId genesis_anchor_id(const SecurityMeshConfig& config) {
    NodeId id{};
    id.bytes = config.genesis_public_key;
    return id;
}

}  // namespace

SecurityMeshService::SecurityMeshService(asio::io_context& io, const SecurityMeshConfig& config,
                                         gossip::GossipService& transport,
                                         crypto::KeyWrappingService* wrapping)
    : config_(config),
      transport_(transport),
      runtime_(SecurityRuntimeConfig{
          .self = self_id(config),
          .network_id = mesh_network_id(config),
          .consensus_directory = config.data_root / "security" / "consensus",
          .attestation_state_directory = config.data_root / "security" / "attestation-state",
          .profile = config.profile,
          // The cache hands over whatever is on disk; verify_snp_revocation
          // decides whether it is any good. With nothing cached the state is
          // empty and new Tier 1 attestation fails closed on it, which never
          // touches an already frozen epoch.
          .amd_revocation =
              AmdRevocationCache(config.data_root / "security" / "revocation")
                  .source([] {
                      return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                                      .count());
                  }),
          // Called only while consensus runs, long after the driver exists.
          .transition_validator =
              [this](const Digest& transitions_digest) {
                  return driver_.accepts_transition(transitions_digest);
              },
          // Same deferral: a payload is judged by its kind's handler, and
          // with no handler registered no payload earns this node's vote.
          .payload_validator =
              [this](const Proposal& proposal, const BlockPayload& payload) {
                  return driver_.accepts_payload(proposal, payload);
              }}),
      sealer_(config.identity.private_key),
      store_(config.data_root / "security", wrapping),
      genesis_(config.identity.public_key == config.genesis_public_key
                   ? std::make_unique<GenesisService>(mesh_network_id(config))
                   : nullptr),
      events_(),
      // The producer is constructed after the router; only its address is
      // taken here, never its state.
      router_(SecurityRouterConfig{
                  .network_id = mesh_network_id(config),
                  .genesis_anchor_id = genesis_anchor_id(config),
                  // Address-only capture: the driver is constructed after the
                  // router and the callback runs only once messages flow.
                  .founding_member =
                      [this](const NodeId& node) {
                          return driver_.is_founding_member(node);
                      },
                  .authority_member =
                      [this](const NodeId& node) {
                          return driver_.is_verified_authority_member(node);
                      },
                  // Address-only capture as above: the storage service, when
                  // enabled, is built after the router.
                  .storage_unlock_challenger =
                      [this](const NodeId& holder, const Digest& context) {
                          return storage_ != nullptr &&
                                 storage_->expects_unlock_challenge(holder, context);
                      }},
              runtime_, transport_, events_, sealer_, &producer_),
      producer_(EvidenceProducerSources{
          config.identity,
          [this](EpochId epoch) { return driver_.vote_key_for_epoch(epoch); },
          config.data_root / "security" / "attestation-cache",
          {},
          config.platform_source,
          config.activation_source}),
      driver_(SecurityDriverConfig{
                  .self = self_id(config),
                  .identity = config.identity,
                  .genesis_public_key = config.genesis_public_key,
                  .release_approval_digest = config.release_approval_digest,
                  // Address-only capture: the chain is built in the body and
                  // the callback runs at driver start. Without a packaged
                  // approval the commitment must equal the loaded digest.
                  .release_commitment =
                      [this](const Digest& committed) {
                          if (!config_.installed_release.has_value()) {
                              return committed == config_.release_approval_digest;
                          }
                          return release_chain_ != nullptr &&
                                 release_chain_->bind_commitment(committed);
                      },
                  // The transport certificate is a mesh fact, and the gossip
                  // layer is where the root signature was already checked. The
                  // security layer reads that answer; it does not re-derive it
                  // and it cannot override it.
                  .certificate_source =
                      [this](const NodeId& node) {
                          return transport_.peer_is_root_certified(node);
                      }},
              runtime_, router_, store_, genesis_.get()),
      timer_(io) {
    events_.target = &driver_;
    if (config.on_epoch_established)
        driver_.set_epoch_established_callback(config.on_epoch_established);
    // The threshold storage key is unconditional: every server runs the holder
    // duties and answers attested unlock requests, with or without a data key.
    storage_crypto_ = std::make_unique<crypto::SodiumCryptoService>();
    storage_crypto_->start();
    const auto storage_directory = config.data_root / "security" / "storage";
    file_share_store_ = std::make_unique<FileStorageShareStore>(
        storage_directory / "sealed", storage_crypto_.get(), wrapping,
        config.identity.public_key);
    if (!config.sealed_directory.empty()) {
        // Also without a backend: the vote-key migration must see a sealed
        // wrapping key that this build can no longer unseal.
        sealed_blobs_ =
            std::make_unique<SealedBlobStore>(config.sealed_directory, config.seal_backend);
        sealed_blobs_->set_next_boot_chain(config.next_boot_chain);
    }
    // The vote-key wrapping key joins the boot set before the driver starts
    // and loads a vote key (EpochStore, design B6).
    vote_key_protection_ = store_.open_vote_key_sealing(
        VoteKeySealing{.sealed = sealed_blobs_.get(),
                       .crypto = storage_crypto_.get(),
                       .boot_id = config.boot_id},
        vote_key_error_);
    if (vote_key_protection_ == VoteKeyProtection::Refused) {
        spdlog::error("[security] vote keys: {}", vote_key_error_);
    } else {
        spdlog::info("[security] vote keys at rest: {}",
                     vote_key_protection_name(vote_key_protection_));
    }
    if (config.seal_backend.available() && sealed_blobs_ != nullptr) {
        // The share joins the gossip identity in the sealed boot set. A share
        // kept in the file store before this host could seal moves across on
        // first use.
        share_store_ = std::make_unique<SealedStorageShareStore>(*sealed_blobs_,
                                                                 file_share_store_.get());
    } else {
        spdlog::warn("[storage] this host cannot seal; the storage share stays in the "
                     "machine-bound file store");
        share_store_ = std::make_unique<FileStorageShareStore>(
            storage_directory / "sealed", storage_crypto_.get(), wrapping,
            config.identity.public_key);
    }
    storage_ = std::make_unique<StorageKeyService>(
        StorageKeyServiceConfig{
            .self = self_id(config),
            .identity = config.identity,
            .network_id = mesh_network_id(config),
            .directory = storage_directory,
            .wall_clock_ms =
                [] {
                    return static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                },
            // Lost storage state stops startup only when the files are
            // encrypted (StorageKeyService::start).
            .files_encrypted =
                [vault = config.vault] {
                    return vault != nullptr && vault->mode() == VaultMode::Encrypted;
                }},
        driver_, router_, runtime_, sealer_, *share_store_, *storage_crypto_);
    storage_->attach();
    if (config.vault != nullptr) {
        vault_ = config.vault;
        vault_->attach(&storage_->data_keys());
    }

    if (config.installed_release.has_value()) {
        release_chain_ = std::make_unique<ReleaseChain>(
            config.data_root / "security" / "release", config.genesis_public_key,
            mesh_network_id(config));
        (void)release_chain_->load(config.installed_release);
        install_release_profile();
    }
    upgrade_ = std::make_unique<UpgradeService>(
        UpgradeServiceConfig{
            .self = self_id(config),
            .identity = config.identity,
            .network_id = mesh_network_id(config),
            .directory = config.data_root / "security" / "upgrade",
            .wall_clock_ms =
                [] {
                    return static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                },
            .running_release = config.installed_release.has_value()
                                   ? config.installed_release->approval.release_number
                                   : 0,
            .data_key_state =
                [this]() -> std::string {
                    if (storage_ == nullptr) return "unknown";
                    switch (storage_->data_keys().state()) {
                        case DataKeyState::Unlocked: return "unlocked";
                        case DataKeyState::Locked: return "locked";
                        case DataKeyState::NoStorageKey: return "no_storage_key";
                        case DataKeyState::Retired: return "retired";
                    }
                    return "unknown";
                },
            // A configured collector (nexus-attestd) is what lets a witness
            // attest this server.
            .attestable = [has_collector = static_cast<bool>(config.platform_source)] {
                return has_collector;
            }},
        driver_, router_, runtime_, release_chain_.get());
    upgrade_->set_release_adopted_callback([this](const ReleaseApprovalBundleV1& bundle) {
        install_release_profile();
        if (sealed_blobs_ != nullptr) {
            // Stage the share for the boot chain the new release expects.
            sealed_blobs_->set_next_boot_chain(boot_pcrs_from_approval(bundle.approval));
        }
    });
    // A finalized rollout above the accepted release (a rolled-back release
    // record, or an older package): no profile until a newer approval comes.
    upgrade_->set_release_floor_callback([this] { install_release_profile(); });
    upgrade_->attach();
}

void SecurityMeshService::install_release_profile() {
    if (release_chain_ == nullptr) return;
    // Fail closed: without a verified current approval (a corrupt chain, or a
    // stored approval this build cannot verify) no node can pass Tier 1
    // attestation here, rather than falling back to an older approval.
    runtime_.attestation().replace_profile(
        release_chain_->current().has_value()
            ? profile_from_release_approval(release_chain_->current()->approval)
            : linux_attestation_profile_v3_svsm_release());
}

SecurityMeshService::~SecurityMeshService() {
    if (vault_ != nullptr) {
        vault_->attach(nullptr);
    }
}

uint64_t SecurityMeshService::now_ms() const {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at_)
                                     .count());
}

void SecurityMeshService::on_start() {
    if (running_) {
        return;
    }
    running_ = true;
    started_at_ = std::chrono::steady_clock::now();

    // The transport authenticated the sender; the router applies every
    // protocol gate before any service sees the bytes.
    transport_.set_security_sink(
        [this](const NodeId& sender, std::span<const uint8_t> envelope) {
            (void)router_.receive(sender, envelope, now_ms());
        });
    // Transport reports contact; the driver decides what follows.
    transport_.set_peer_certified_callback([this](const NodeId& peer) {
        driver_.on_peer(peer, now_ms());
        upgrade_->on_peer(peer);
    });

    if (storage_ != nullptr) {
        // A storage service whose durable state does not load stays inert;
        // the rest of the mesh runs.
        (void)storage_->start(now_ms());
    }
    // Corrupt upgrade records leave that service inert, nothing else.
    (void)upgrade_->start(now_ms());
    driver_.start(now_ms());
    refresh_members();
    arm_timer();
}

void SecurityMeshService::refresh_members() {
    // io thread only. Membership changes when an epoch activates, so copying it
    // each tick keeps the cross-thread snapshot at most one tick stale.
    std::vector<NodeId> members;
    bool known = false;
    EpochId epoch{0};
    if (const EpochManager* epochs = runtime_.epochs(); epochs != nullptr) {
        members = epochs->current().tier1_members.members();
        epoch = epochs->current().id;
        known = true;
    } else if (const VerifiedEpochAuthority* authority = driver_.verified_authority();
               authority != nullptr) {
        // Tier 2 path: a non-member has no EpochManager, but it walks the
        // authority chain and holds the current epoch's verified membership.
        // Without this it recognizes no node as Tier 1 and denies their
        // records — the Tier 2 node must still trust the real Tier 1 set.
        members = authority->members;
        epoch = authority->epoch;
        known = true;
    }
    std::lock_guard lock(members_mutex_);
    current_members_ = std::move(members);
    members_known_ = known;
    current_epoch_ = epoch;
}

NetworkId SecurityMeshService::network_id() const { return mesh_network_id(config_); }

std::optional<AuthorityChainPage> SecurityMeshService::authority_chain_page(
    EpochId have_epoch, std::chrono::milliseconds timeout) {
    auto promise = std::make_shared<std::promise<std::optional<AuthorityChainPage>>>();
    auto answer = promise->get_future();
    asio::post(timer_.get_executor(), [this, have_epoch, promise] {
        promise->set_value(running_ ? driver_.authority_chain_page(have_epoch) : std::nullopt);
    });
    if (answer.wait_for(timeout) != std::future_status::ready) {
        return std::nullopt;
    }
    return answer.get();
}

void SecurityMeshService::arm_timer() {
    timer_.expires_after(std::chrono::milliseconds(kDriverTickMs));
    timer_.async_wait([this](const asio::error_code& ec) {
        if (ec || !running_) {
            return;
        }
        driver_.tick(now_ms());
        if (storage_ != nullptr) {
            storage_->tick(now_ms());
        }
        upgrade_->tick(now_ms());
        if (vault_ != nullptr) {
            // Rotation follows the local wall clock (B5a): per server, not
            // consensus.
            vault_->tick(static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count()));
        }
        refresh_members();
        if (tick_hook_) tick_hook_();
        arm_timer();
    });
}

void SecurityMeshService::post(std::function<void()> work) {
    asio::post(timer_.get_executor(), [this, work = std::move(work)]() {
        if (running_) work();
    });
}

void SecurityMeshService::broadcast_tree_op(TreeOpSubmitMsg message) {
    asio::post(timer_.get_executor(), [this, message = std::move(message)]() mutable {
        if (!running_) {
            return;
        }
        const EpochId epoch = driver_.current_epoch().value_or(0);
        (void)router_.broadcast(
            router_.compose(SecurityMessageKind::TreeOpSubmit, std::move(message), epoch));
    });
}

void SecurityMeshService::on_stop() {
    if (!running_) {
        return;
    }
    running_ = false;
    timer_.cancel();
    // The transport must stop feeding a stack that is going away.
    transport_.set_security_sink({});
    transport_.set_peer_certified_callback({});
}

std::optional<std::string> SecurityMeshService::rollout_proof_json() const {
    const auto proof = upgrade_->rollout_proof(config_.genesis_public_key);
    if (!proof) return std::nullopt;
    return ::nexus::security::rollout_proof_json(*proof);
}

}  // namespace nexus::security
