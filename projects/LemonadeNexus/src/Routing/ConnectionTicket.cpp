#include <LemonadeNexus/Routing/ConnectionTicket.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <cstring>

namespace nexus::routing {
namespace {

void push_str(std::vector<uint8_t>& v, const std::string& s) {
    // length-prefixed so field boundaries are unambiguous
    uint32_t n = static_cast<uint32_t>(s.size());
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((n >> (i * 8)) & 0xFF));
    v.insert(v.end(), s.begin(), s.end());
}

void push_u64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xFF));
}

} // namespace

std::vector<uint8_t> connection_ticket_canonical(const ConnectionTicket& t) {
    std::vector<uint8_t> v;
    push_str(v, "ln-conn-ticket:v1");
    push_str(v, t.connection_id);
    push_str(v, t.client_node_id);
    push_str(v, t.endpoint_node_id);
    v.insert(v.end(), t.conn_nonce.begin(), t.conn_nonce.end());
    v.push_back(static_cast<uint8_t>(t.data_path));
    push_u64(v, t.issued_at);
    push_u64(v, t.expires_at);
    return v;
}

void sign_connection_ticket(ConnectionTicket& t,
                            crypto::SodiumCryptoService& crypto,
                            const crypto::Ed25519PrivateKey& privkey) {
    const auto canonical = connection_ticket_canonical(t);
    const auto sig = crypto.ed25519_sign(privkey, std::span<const uint8_t>(canonical));
    std::memcpy(t.signature.data(), sig.data(), t.signature.size());
}

bool verify_connection_ticket(const ConnectionTicket& t,
                              crypto::SodiumCryptoService& crypto,
                              const crypto::Ed25519PublicKey& pubkey) {
    const auto canonical = connection_ticket_canonical(t);
    return crypto.ed25519_verify(pubkey, std::span<const uint8_t>(canonical), t.signature);
}

} // namespace nexus::routing
