#include <LemonadeNexus/Auth/LinkTokenLedger.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <algorithm>
#include <cstring>

namespace nexus::auth {

namespace {

bool is_lower_hex(std::string_view s) {
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool bounded(std::string_view s) { return s.size() <= kLinkTokenMaxFieldBytes; }

std::optional<std::vector<uint8_t>> decode_b64(std::string_view s) {
    try {
        return crypto::from_base64(s);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool kind_known(LinkTokenEventKind kind) {
    return kind == LinkTokenEventKind::Mint || kind == LinkTokenEventKind::Spend ||
           kind == LinkTokenEventKind::Refund;
}

char kind_letter(LinkTokenEventKind kind) {
    switch (kind) {
        case LinkTokenEventKind::Mint:   return 'm';
        case LinkTokenEventKind::Spend:  return 's';
        case LinkTokenEventKind::Refund: return 'r';
    }
    return '?';
}

}  // namespace

std::string link_token_hash_hex(std::string_view token) {
    security::CanonicalEncoder enc(kLinkTokenHashDomain);
    enc.add_string(token);
    const auto d = enc.digest();
    return crypto::to_hex(std::span<const uint8_t>(d.data(), d.size()));
}

std::vector<uint8_t> link_token_event_signing_bytes(const LinkTokenEvent& e) {
    security::CanonicalEncoder enc(kLinkTokenEventDomain);
    enc.add_u16(static_cast<uint16_t>(e.kind));
    enc.add_string(e.token_hash);
    enc.add_u32(e.generation);
    enc.add_string(e.network_id);
    enc.add_u64(e.expires_at);
    enc.add_string(e.group_node_id);
    enc.add_u32(static_cast<uint32_t>(e.permissions.size()));
    for (const auto& p : e.permissions) enc.add_string(p);
    enc.add_string(e.owner_user_id);
    enc.add_string(e.owner_pubkey);
    enc.add_u64(e.created_at);
    enc.add_u64(e.timestamp);
    enc.add_string(e.origin_pubkey);
    enc.add_u64(e.origin_seq);
    return enc.bytes();
}

bool link_token_event_signature_valid(crypto::SodiumCryptoService& crypto,
                                      const LinkTokenEvent& e) {
    const auto pk = decode_b64(e.origin_pubkey);
    const auto sig = decode_b64(e.signature);
    if (!pk || !sig || pk->size() != crypto::kEd25519PublicKeySize ||
        sig->size() != crypto::kEd25519SignatureSize) {
        return false;
    }
    crypto::Ed25519PublicKey pubkey{};
    crypto::Ed25519Signature signature{};
    std::memcpy(pubkey.data(), pk->data(), pubkey.size());
    std::memcpy(signature.data(), sig->data(), signature.size());
    const auto msg = link_token_event_signing_bytes(e);
    return crypto.ed25519_verify(pubkey, std::span<const uint8_t>(msg), signature);
}

std::optional<std::string> link_token_event_shape_error(const LinkTokenEvent& e) {
    if (!kind_known(e.kind)) return "unknown event kind";
    if (e.token_hash.size() != 64 || !is_lower_hex(e.token_hash)) {
        return "token hash is not 64 lowercase hex digits";
    }
    if (e.generation > kLinkTokenMaxGeneration) return "generation beyond the limit";
    if (e.expires_at == 0 || e.timestamp == 0 || e.origin_seq == 0) {
        return "expiry, timestamp, and origin sequence must be set";
    }
    if (e.origin_pubkey.empty()) return "origin is empty";
    if (!bounded(e.token_hash) || !bounded(e.network_id) || !bounded(e.group_node_id) ||
        !bounded(e.owner_user_id) || !bounded(e.owner_pubkey) || !bounded(e.origin_pubkey) ||
        !bounded(e.signature)) {
        return "a field exceeds its bound";
    }
    if (e.kind == LinkTokenEventKind::Mint) {
        if (e.generation != 0) return "a mint is generation 0";
        if (e.group_node_id.empty() || e.owner_user_id.empty() || e.owner_pubkey.empty()) {
            return "a mint names its group and owner";
        }
        if (e.created_at == 0 || e.expires_at <= e.created_at ||
            e.expires_at - e.created_at > kLinkTokenMaxTtlSec) {
            return "mint lifetime out of bounds";
        }
        if (e.permissions.size() > kLinkTokenMaxPermissions) return "too many permissions";
        for (const auto& p : e.permissions) {
            if (p.empty() || !bounded(p)) return "invalid permission name";
        }
        return std::nullopt;
    }
    if (!e.group_node_id.empty() || !e.permissions.empty() || !e.owner_user_id.empty() ||
        !e.owner_pubkey.empty() || e.created_at != 0) {
        return "only a mint carries grant fields";
    }
    if (e.kind == LinkTokenEventKind::Refund && e.generation >= kLinkTokenMaxGeneration) {
        return "a refund cannot open a generation beyond the limit";
    }
    return std::nullopt;
}

std::optional<std::string> link_token_event_time_error(const LinkTokenEvent& e,
                                                       uint64_t now_sec) {
    if (now_sec >= e.expires_at + kLinkTokenRetentionSec) return "the token's retention ended";
    if (e.expires_at > now_sec + kLinkTokenMaxTtlSec + kLinkTokenMaxFutureSec) {
        return "expiry too far in the future";
    }
    if (e.timestamp > now_sec + kLinkTokenMaxFutureSec) return "timestamp in the future";
    return std::nullopt;
}

std::string link_token_event_key(const LinkTokenEvent& e) {
    std::string key = "lt:" + e.token_hash + ":";
    key.push_back(kind_letter(e.kind));
    if (e.kind != LinkTokenEventKind::Mint) {
        key += ":" + std::to_string(e.generation) + ":" + e.origin_pubkey;
    }
    return key;
}

nlohmann::json link_token_event_to_wire(const LinkTokenEvent& e) {
    return nlohmann::json{
        {"kind", static_cast<uint8_t>(e.kind)},
        {"token_hash", e.token_hash},
        {"generation", e.generation},
        {"network_id", e.network_id},
        {"expires_at", e.expires_at},
        {"group_node_id", e.group_node_id},
        {"permissions", e.permissions},
        {"owner_user_id", e.owner_user_id},
        {"owner_pubkey", e.owner_pubkey},
        {"created_at", e.created_at},
        {"timestamp", e.timestamp},
        {"origin_pubkey", e.origin_pubkey},
        {"origin_seq", e.origin_seq},
        {"signature", e.signature},
    };
}

std::optional<LinkTokenEvent> link_token_event_from_wire(const nlohmann::json& j) {
    if (!j.is_object()) return std::nullopt;
    const auto text = [&](const char* k, std::string& out) {
        const auto it = j.find(k);
        if (it == j.end() || !it->is_string()) return false;
        out = it->get<std::string>();
        return bounded(out);
    };
    const auto u64 = [&](const char* k, uint64_t& out) {
        const auto it = j.find(k);
        if (it == j.end()) return false;
        if (it->is_number_unsigned()) {
            out = it->get<uint64_t>();
            return true;
        }
        if (it->is_number_integer() && it->get<int64_t>() >= 0) {
            out = static_cast<uint64_t>(it->get<int64_t>());
            return true;
        }
        return false;
    };
    LinkTokenEvent e;
    uint64_t kind = 0;
    uint64_t generation = 0;
    if (!u64("kind", kind) || kind > 0xFF || !u64("generation", generation) ||
        generation > kLinkTokenMaxGeneration || !text("token_hash", e.token_hash) ||
        !text("network_id", e.network_id) || !u64("expires_at", e.expires_at) ||
        !text("group_node_id", e.group_node_id) || !text("owner_user_id", e.owner_user_id) ||
        !text("owner_pubkey", e.owner_pubkey) || !u64("created_at", e.created_at) ||
        !u64("timestamp", e.timestamp) || !text("origin_pubkey", e.origin_pubkey) ||
        !u64("origin_seq", e.origin_seq) || !text("signature", e.signature)) {
        return std::nullopt;
    }
    e.kind = static_cast<LinkTokenEventKind>(kind);
    e.generation = static_cast<uint32_t>(generation);
    const auto perms = j.find("permissions");
    if (perms == j.end() || !perms->is_array() || perms->size() > kLinkTokenMaxPermissions) {
        return std::nullopt;
    }
    for (const auto& p : *perms) {
        if (!p.is_string()) return std::nullopt;
        e.permissions.push_back(p.get<std::string>());
        if (!bounded(e.permissions.back())) return std::nullopt;
    }
    return e;
}

// --- Ledger -----------------------------------------------------------------

LinkTokenLedger::AddResult LinkTokenLedger::add(const LinkTokenEvent& e, uint64_t now_sec) {
    if (link_token_event_shape_error(e) || link_token_event_time_error(e, now_sec)) {
        return AddResult::Refused;
    }
    auto it = tokens_.find(e.token_hash);
    if (it == tokens_.end()) {
        if (tokens_.size() >= kLinkTokenMaxTokens) return AddResult::Full;
        Token t;
        t.network_id = e.network_id;
        t.expires_at = e.expires_at;
        it = tokens_.emplace(e.token_hash, std::move(t)).first;
    } else if (it->second.network_id != e.network_id || it->second.expires_at != e.expires_at) {
        return AddResult::Refused;
    }
    auto& token = it->second;
    const auto key = link_token_event_key(e);
    if (const auto held = token.events.find(key); held != token.events.end()) {
        return held->second == e ? AddResult::Duplicate : AddResult::Refused;
    }
    if (token.events.size() >= kLinkTokenMaxEventsPerToken) return AddResult::Full;
    token.events.emplace(key, e);
    if (e.kind == LinkTokenEventKind::Mint) token.mint = e;
    return AddResult::Added;
}

std::optional<std::string> LinkTokenLedger::spend_winner(std::string_view token_hash,
                                                         uint32_t generation) const {
    const auto it = tokens_.find(token_hash);
    if (it == tokens_.end()) return std::nullopt;
    std::optional<std::string> winner;
    for (const auto& [key, e] : it->second.events) {
        if (e.kind != LinkTokenEventKind::Spend || e.generation != generation) continue;
        if (!winner || e.origin_pubkey < *winner) winner = e.origin_pubkey;
    }
    return winner;
}

std::optional<LinkTokenLedger::Live> LinkTokenLedger::live(std::string_view token_hash,
                                                           uint64_t now_sec) const {
    const auto it = tokens_.find(token_hash);
    if (it == tokens_.end() || !it->second.mint || now_sec >= it->second.expires_at) {
        return std::nullopt;
    }
    const auto& events = it->second.events;
    const auto refunded_by = [&](uint32_t generation, const std::string& origin) {
        for (const auto& [key, e] : events) {
            if (e.kind == LinkTokenEventKind::Refund && e.generation == generation &&
                e.origin_pubkey == origin) {
                return true;
            }
        }
        return false;
    };
    for (uint32_t g = 0; g <= kLinkTokenMaxGeneration; ++g) {
        const auto winner = spend_winner(token_hash, g);
        if (!winner) return Live{*it->second.mint, g};
        // Only the server whose spend counts may restore the token; a refund
        // by a server that lost the tie never revives it.
        if (!refunded_by(g, *winner)) return std::nullopt;
    }
    return std::nullopt;
}

std::size_t LinkTokenLedger::live_count_for_owner(std::string_view owner_user_id,
                                                  uint64_t now_sec) const {
    std::size_t n = 0;
    for (const auto& [hash, token] : tokens_) {
        if (token.mint && token.mint->owner_user_id == owner_user_id && live(hash, now_sec)) ++n;
    }
    return n;
}

std::size_t LinkTokenLedger::prune(uint64_t now_sec) {
    return std::erase_if(tokens_, [now_sec](const auto& kv) {
        return now_sec >= kv.second.expires_at + kLinkTokenRetentionSec;
    });
}

std::vector<LinkTokenEvent> LinkTokenLedger::events() const {
    std::vector<LinkTokenEvent> out;
    for (const auto& [hash, token] : tokens_) {
        for (const auto& [key, e] : token.events) out.push_back(e);
    }
    return out;
}

}  // namespace nexus::auth
