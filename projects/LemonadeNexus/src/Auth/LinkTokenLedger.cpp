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
           kind == LinkTokenEventKind::Refund || kind == LinkTokenEventKind::Revoke;
}

bool is_hex64(std::string_view s) { return s.size() == 64 && is_lower_hex(s); }

/// The event without its code binding: what a replica from a release before
/// invite codes holds, and what the event signature covers.
LinkTokenEvent without_code(LinkTokenEvent e) {
    e.code_hash.clear();
    e.code_signature.clear();
    return e;
}

bool verify_b64(crypto::SodiumCryptoService& crypto, std::string_view origin_pubkey,
                std::span<const uint8_t> msg, std::string_view signature_b64) {
    const auto pk = decode_b64(origin_pubkey);
    const auto sig = decode_b64(signature_b64);
    if (!pk || !sig || pk->size() != crypto::kEd25519PublicKeySize ||
        sig->size() != crypto::kEd25519SignatureSize) {
        return false;
    }
    crypto::Ed25519PublicKey pubkey{};
    crypto::Ed25519Signature signature{};
    std::memcpy(pubkey.data(), pk->data(), pubkey.size());
    std::memcpy(signature.data(), sig->data(), signature.size());
    return crypto.ed25519_verify(pubkey, msg, signature);
}

char kind_letter(LinkTokenEventKind kind) {
    switch (kind) {
        case LinkTokenEventKind::Mint:   return 'm';
        case LinkTokenEventKind::Spend:  return 's';
        case LinkTokenEventKind::Refund: return 'r';
        case LinkTokenEventKind::Revoke: return 'x';
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

bool is_link_code(std::string_view secret) {
    return secret.size() == kLinkCodeDigits &&
           std::all_of(secret.begin(), secret.end(),
                       [](char c) { return c >= '0' && c <= '9'; });
}

std::string link_code_hash_hex(std::string_view code) {
    security::CanonicalEncoder enc(kLinkCodeHashDomain);
    enc.add_string(code);
    const auto d = enc.digest();
    return crypto::to_hex(std::span<const uint8_t>(d.data(), d.size()));
}

std::vector<uint8_t> link_code_binding_bytes(const LinkTokenEvent& e) {
    security::CanonicalEncoder enc(kLinkCodeBindingDomain);
    enc.add_string(e.token_hash);
    enc.add_string(e.code_hash);
    enc.add_string(e.network_id);
    enc.add_u64(e.expires_at);
    enc.add_string(e.origin_pubkey);
    enc.add_u64(e.origin_seq);
    return enc.bytes();
}

uint64_t link_code_expires_at(const LinkTokenEvent& mint) {
    return std::min(mint.expires_at, mint.created_at + kLinkCodeMaxTtlSec);
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
    const auto msg = link_token_event_signing_bytes(e);
    if (!verify_b64(crypto, e.origin_pubkey, std::span<const uint8_t>(msg), e.signature)) {
        return false;
    }
    if (e.code_hash.empty()) return e.code_signature.empty();
    const auto binding = link_code_binding_bytes(e);
    return verify_b64(crypto, e.origin_pubkey, std::span<const uint8_t>(binding),
                      e.code_signature);
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
        !bounded(e.signature) || !bounded(e.code_hash) || !bounded(e.code_signature)) {
        return "a field exceeds its bound";
    }
    if (e.kind != LinkTokenEventKind::Mint && (!e.code_hash.empty() || !e.code_signature.empty())) {
        return "only a mint carries a code binding";
    }
    if (e.kind == LinkTokenEventKind::Mint) {
        if (e.generation != 0) return "a mint is generation 0";
        if (e.code_hash.empty()) {
            if (!e.code_signature.empty()) return "a code signature needs a code hash";
        } else if (!is_hex64(e.code_hash)) {
            return "code hash is not 64 lowercase hex digits";
        } else if (e.code_signature.empty() != e.signature.empty()) {
            // A signed mint signs its code binding too; an unsigned (local)
            // mint signs neither.
            return "a signed mint signs its code binding";
        }
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
    if (e.kind == LinkTokenEventKind::Revoke && e.generation != 0) return "a revoke is generation 0";
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
    nlohmann::json j{
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
    // Absent, not empty, so an event without a code keeps the form an
    // earlier release writes and reads back unchanged.
    if (!e.code_hash.empty()) j["code_hash"] = e.code_hash;
    if (!e.code_signature.empty()) j["code_signature"] = e.code_signature;
    return j;
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
    const auto optional_text = [&](const char* k, std::string& out) {
        return j.find(k) == j.end() || text(k, out);
    };
    if (!optional_text("code_hash", e.code_hash) ||
        !optional_text("code_signature", e.code_signature)) {
        return std::nullopt;
    }
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
    const auto index_code = [&] {
        if (e.kind == LinkTokenEventKind::Mint && !e.code_hash.empty()) {
            codes_[e.code_hash].insert(e.token_hash);
        }
    };
    if (const auto held = token.events.find(key); held != token.events.end()) {
        if (held->second == e) return AddResult::Duplicate;
        if (e.kind != LinkTokenEventKind::Mint || without_code(held->second) != without_code(e)) {
            return AddResult::Refused;
        }
        // The same signed mint, with or without its code binding: the copy
        // with the binding is kept, whichever arrived first.
        if (e.code_hash.empty() || !held->second.code_hash.empty()) return AddResult::Duplicate;
        held->second = e;
        token.mint = e;
        index_code();
        return AddResult::Added;
    }
    if (token.events.size() >= kLinkTokenMaxEventsPerToken) return AddResult::Full;
    token.events.emplace(key, e);
    if (e.kind == LinkTokenEventKind::Mint) {
        token.mint = e;
        index_code();
    }
    return AddResult::Added;
}

std::optional<LinkTokenLedger::Live> LinkTokenLedger::live_by_code(std::string_view code_hash,
                                                                   uint64_t now_sec) const {
    const auto it = codes_.find(code_hash);
    if (it == codes_.end()) return std::nullopt;
    std::optional<std::string> only;
    for (const auto& token_hash : it->second) {
        const auto t = tokens_.find(token_hash);
        if (t == tokens_.end() || !t->second.mint || now_sec >= link_code_expires_at(*t->second.mint)) {
            continue;
        }
        if (only) return std::nullopt;  // two unexpired mints share the code
        only = token_hash;
    }
    if (!only) return std::nullopt;
    return live(*only, now_sec);
}

bool LinkTokenLedger::code_in_use(std::string_view code_hash, uint64_t now_sec) const {
    const auto it = codes_.find(code_hash);
    if (it == codes_.end()) return false;
    return std::any_of(it->second.begin(), it->second.end(), [&](const std::string& token_hash) {
        const auto t = tokens_.find(token_hash);
        return t != tokens_.end() && t->second.mint &&
               now_sec < link_code_expires_at(*t->second.mint);
    });
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
    if (it == tokens_.end() || !it->second.mint || now_sec >= it->second.expires_at ||
        revoked(token_hash)) {
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

bool LinkTokenLedger::revoked(std::string_view token_hash) const {
    const auto it = tokens_.find(token_hash);
    if (it == tokens_.end()) return false;
    return std::any_of(it->second.events.begin(), it->second.events.end(), [](const auto& kv) {
        return kv.second.kind == LinkTokenEventKind::Revoke;
    });
}

std::vector<LinkTokenEvent> LinkTokenLedger::mints() const {
    std::vector<LinkTokenEvent> out;
    for (const auto& [hash, token] : tokens_) {
        if (token.mint) out.push_back(*token.mint);
    }
    return out;
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
    const auto removed = std::erase_if(tokens_, [now_sec](const auto& kv) {
        return now_sec >= kv.second.expires_at + kLinkTokenRetentionSec;
    });
    if (removed > 0) {
        for (auto it = codes_.begin(); it != codes_.end();) {
            std::erase_if(it->second, [&](const std::string& token_hash) {
                return tokens_.find(token_hash) == tokens_.end();
            });
            it = it->second.empty() ? codes_.erase(it) : std::next(it);
        }
    }
    return removed;
}

std::vector<LinkTokenEvent> LinkTokenLedger::events() const {
    std::vector<LinkTokenEvent> out;
    for (const auto& [hash, token] : tokens_) {
        for (const auto& [key, e] : token.events) out.push_back(e);
    }
    return out;
}

}  // namespace nexus::auth
