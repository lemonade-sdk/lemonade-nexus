#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>

#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

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
          .profile = config.profile,
          // No CRL cache exists yet, so revocation data is absent and new Tier 1
          // attestation fails closed on it. That is the intended state until a
          // cache producer lands; it never touches a live epoch.
          .amd_revocation = {},
          // Called only while consensus runs, long after the driver exists.
          .transition_validator =
              [this](const Digest& transitions_digest) {
                  return transitions_digest == driver_.pending_handoff_digest();
              }}),
      sealer_(config.identity.private_key),
      store_(config.data_root / "security", wrapping),
      genesis_(config.identity.public_key == config.genesis_public_key
                   ? std::make_unique<GenesisService>(mesh_network_id(config))
                   : nullptr),
      events_(),
      // The producer is constructed after the router; only its address is
      // taken here, never its state.
      router_(SecurityRouterConfig{mesh_network_id(config)}, runtime_, transport_, events_,
              sealer_, &producer_),
      producer_(EvidenceProducerSources{
          config.identity,
          [this](EpochId epoch) { return driver_.vote_key_for_epoch(epoch); },
          config.data_root / "security" / "attestation-cache",
          {}}),
      driver_(SecurityDriverConfig{self_id(config), config.identity, config.genesis_public_key},
              runtime_, router_, store_, genesis_.get()),
      timer_(io) {
    events_.target = &driver_;
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
    transport_.set_peer_certified_callback(
        [this](const NodeId& peer) { driver_.on_peer(peer, now_ms()); });

    driver_.start(now_ms());
    refresh_members();
    arm_timer();
}

void SecurityMeshService::refresh_members() {
    // io thread only. Membership changes when an epoch activates, so copying it
    // each tick keeps the cross-thread snapshot at most one tick stale.
    std::vector<NodeId> members;
    if (const EpochManager* epochs = runtime_.epochs(); epochs != nullptr) {
        members = epochs->current().tier1_members.members();
    }
    std::lock_guard lock(members_mutex_);
    current_members_ = std::move(members);
}

void SecurityMeshService::arm_timer() {
    timer_.expires_after(std::chrono::milliseconds(kDriverTickMs));
    timer_.async_wait([this](const asio::error_code& ec) {
        if (ec || !running_) {
            return;
        }
        driver_.tick(now_ms());
        refresh_members();
        arm_timer();
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

}  // namespace nexus::security
