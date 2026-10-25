#include <LemonadeNexus/Relay/RelayTicketAuth.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <sodium.h>

#include <algorithm>

namespace nexus::relay {

security::Digest relay_ticket_digest(const RelayTicket& ticket) {
    security::CanonicalEncoder encoder(kRelayTicketDomain);
    encoder.add_bytes(ticket.network_id);
    encoder.add_u64(ticket.epoch);
    encoder.add_bytes(ticket.issuer);
    encoder.add_string(ticket.peer_id);
    encoder.add_string(ticket.relay_id);
    encoder.add_bytes(ticket.session_nonce);
    encoder.add_u64(ticket.issued_at);
    encoder.add_u64(ticket.expires_at);
    return encoder.digest();
}

void sign_relay_ticket(RelayTicket& ticket, const crypto::Ed25519Keypair& identity) {
    ticket.issuer = identity.public_key;
    const auto digest = relay_ticket_digest(ticket);
    crypto_sign_detached(ticket.signature.data(), nullptr, digest.data(), digest.size(),
                         identity.private_key.data());
}

std::string_view relay_ticket_check_name(RelayTicketCheck check) {
    switch (check) {
        case RelayTicketCheck::Valid: return "valid";
        case RelayTicketCheck::NoAuthority: return "no verified Tier 1 membership";
        case RelayTicketCheck::WrongNetwork: return "ticket for another network";
        case RelayTicketCheck::WrongEpoch: return "ticket for another epoch";
        case RelayTicketCheck::NotMember: return "issuer is not a Tier 1 member";
        case RelayTicketCheck::BadSignature: return "bad signature";
        case RelayTicketCheck::Expired: return "ticket expired";
        case RelayTicketCheck::NotYetValid: return "ticket issued in the future";
        case RelayTicketCheck::LifetimeTooLong: return "ticket lifetime too long";
    }
    return "unknown";
}

RelayTicketCheck check_relay_ticket(const RelayTicket& ticket,
                                    const std::optional<RelayTicketAuthority>& authority,
                                    uint64_t now_sec) {
    if (!authority) return RelayTicketCheck::NoAuthority;
    if (ticket.network_id != authority->network_id) return RelayTicketCheck::WrongNetwork;
    if (ticket.epoch != authority->epoch.underlying()) return RelayTicketCheck::WrongEpoch;
    security::NodeId issuer;
    issuer.bytes = ticket.issuer;
    if (std::find(authority->members.begin(), authority->members.end(), issuer) ==
        authority->members.end()) {
        return RelayTicketCheck::NotMember;
    }
    const auto digest = relay_ticket_digest(ticket);
    if (crypto_sign_verify_detached(ticket.signature.data(), digest.data(), digest.size(),
                                    ticket.issuer.data()) != 0) {
        return RelayTicketCheck::BadSignature;
    }
    if (ticket.expires_at <= ticket.issued_at ||
        ticket.expires_at - ticket.issued_at > kRelayTicketMaxLifetimeSec) {
        return RelayTicketCheck::LifetimeTooLong;
    }
    if (ticket.issued_at > now_sec + kRelayTicketClockSkewSec) {
        return RelayTicketCheck::NotYetValid;
    }
    if (ticket.expires_at < now_sec) return RelayTicketCheck::Expired;
    return RelayTicketCheck::Valid;
}

}  // namespace nexus::relay
