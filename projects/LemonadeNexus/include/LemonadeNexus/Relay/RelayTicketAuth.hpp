#pragma once

/// Relay tickets that any relay can verify, Tier 1 or Tier 2.
///
/// A current Tier 1 member issues a ticket for its own session (the
/// authenticated caller, `peer_id`) and signs it with its node identity key,
/// the key the finalized membership names. The ticket names the network and
/// the epoch the issuer is a member of. A relay verifies it against the Tier 1
/// membership its security mesh verified from the pinned Genesis key through
/// the authority chain (SecurityDriver, AuthorityChain.hpp). The relay needs no
/// tree and no session state: only that membership, its own relay id, the
/// signature, the expiry, and its own replay set.
///
/// A relay's id is its base64 node identity key. A ticket that names another
/// relay is refused, so a ticket for one relay cannot allocate on another.
///
/// A ticket from an epoch other than the relay's current one is refused, so a
/// ticket issued just before an epoch change must be requested again.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Relay/RelayTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace nexus::relay {

/// Domain of the signed ticket digest (the node identity key signs it).
inline constexpr std::string_view kRelayTicketDomain = "lemonade-nexus/relay-ticket:v2";

/// Longest lifetime (expires_at - issued_at) a relay accepts, in seconds.
inline constexpr uint64_t kRelayTicketMaxLifetimeSec = 120;

/// How far ahead of the relay's clock issued_at may be, in seconds.
inline constexpr uint64_t kRelayTicketClockSkewSec = 60;

/// The verified Tier 1 membership a relay checks tickets against.
struct RelayTicketAuthority {
    security::NetworkId network_id{};
    security::EpochId epoch{0};
    std::vector<security::NodeId> members;
};

/// The digest a ticket's signature covers: domain, network, epoch, issuer,
/// peer, relay, session nonce, issue time, and expiry.
[[nodiscard]] security::Digest relay_ticket_digest(const RelayTicket& ticket);

/// Sets the issuer to `identity.public_key` and signs the ticket. The other
/// fields must be final.
void sign_relay_ticket(RelayTicket& ticket, const crypto::Ed25519Keypair& identity);

enum class RelayTicketCheck : uint8_t {
    Valid,
    /// The relay holds no verified membership (before Epoch 1, or not yet
    /// verified): every ticket is refused.
    NoAuthority,
    /// The ticket names another relay, or this relay has no relay id.
    WrongRelay,
    WrongNetwork,
    WrongEpoch,
    /// The issuer is not in the verified membership.
    NotMember,
    BadSignature,
    Expired,
    NotYetValid,
    LifetimeTooLong,
};

[[nodiscard]] std::string_view relay_ticket_check_name(RelayTicketCheck check);

/// Checks a ticket against the verified membership and the checking relay's
/// own id (`relay_id`, empty refuses every ticket) at `now_sec` (Unix
/// seconds). Replay is the relay's job (one allocation per issuer and nonce).
[[nodiscard]] RelayTicketCheck check_relay_ticket(
    const RelayTicket& ticket, const std::optional<RelayTicketAuthority>& authority,
    std::string_view relay_id, uint64_t now_sec);

}  // namespace nexus::relay
