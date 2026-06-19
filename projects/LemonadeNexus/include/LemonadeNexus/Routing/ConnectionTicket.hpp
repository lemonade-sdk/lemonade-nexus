#pragma once

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Routing/RoutingTypes.hpp>

#include <cstdint>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::routing {

/// Deterministic bytes signed over (excludes the signature field itself).
[[nodiscard]] std::vector<uint8_t> connection_ticket_canonical(const ConnectionTicket& t);

/// Sign the ticket in place with the coordinator's Ed25519 identity key.
void sign_connection_ticket(ConnectionTicket& t,
                            crypto::SodiumCryptoService& crypto,
                            const crypto::Ed25519PrivateKey& privkey);

/// Verify the ticket signature against the coordinator's Ed25519 pubkey.
[[nodiscard]] bool verify_connection_ticket(const ConnectionTicket& t,
                                            crypto::SodiumCryptoService& crypto,
                                            const crypto::Ed25519PublicKey& pubkey);

} // namespace nexus::routing
