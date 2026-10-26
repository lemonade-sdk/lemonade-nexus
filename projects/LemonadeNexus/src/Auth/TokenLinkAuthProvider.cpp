#include <LemonadeNexus/Auth/TokenLinkAuthProvider.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <span>
#include <sstream>
#include <system_error>

namespace nexus::auth {

using json = nlohmann::json;

namespace {

constexpr std::string_view kLedgerCategory = "link_tokens";
constexpr std::string_view kLedgerFile     = "ledger.json";

uint64_t system_now_sec() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

uint64_t system_now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

/// Write a legacy token `record` to `path`, replacing any file there.
bool write_legacy_record(const std::filesystem::path& path, const LinkTokenRecord& record) {
    json j = {
        {"owner_user_id", record.owner_user_id},
        {"owner_pubkey",  record.owner_pubkey},
        {"group_node_id", record.group_node_id},
        {"created_at",    record.created_at},
        {"expires_at",    record.expires_at},
        {"permissions",   record.permissions},
    };
    try {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs) {
            spdlog::error("[token-link] Failed to open token file: {}", path.string());
            return false;
        }
        ofs << j.dump(2);
        return ofs.good();
    } catch (const std::exception& e) {
        spdlog::error("[token-link] Exception writing token file: {}", e.what());
        return false;
    }
}

} // namespace

TokenLinkAuthProvider::TokenLinkAuthProvider(storage::FileStorageService& storage,
                                             crypto::SodiumCryptoService& crypto)
    : storage_(storage)
    , crypto_(crypto)
{
    load();
}

AuthResult TokenLinkAuthProvider::do_authenticate(const nlohmann::json& credentials) {
    (void)credentials;
    // Link tokens authorize placement, not identity: the joining device still
    // proves its Ed25519 key. Present the token in POST /api/join instead.
    return AuthResult{
        .authenticated = false,
        .error_message = "token-link is not a standalone auth method; "
                         "pass link_token to /api/join alongside ed25519 auth",
    };
}

uint64_t TokenLinkAuthProvider::now_sec() const {
    return clock_ ? clock_() : system_now_sec();
}

void TokenLinkAuthProvider::set_clock_for_testing(std::function<uint64_t()> now_sec) {
    std::lock_guard lock(mutex_);
    clock_ = std::move(now_sec);
}

void TokenLinkAuthProvider::set_replication(EventSigner signer, EventPublisher publisher) {
    std::lock_guard lock(mutex_);
    signer_ = std::move(signer);
    publisher_ = std::move(publisher);
}

void TokenLinkAuthProvider::author_locked(LinkTokenEvent& e, bool sign) {
    e.timestamp = now_sec();
    if (sign && signer_ && signer_(e)) {
        self_origin_ = e.origin_pubkey;
        return;
    }
    // Not replicated: an unsigned event that only this server holds.
    e.origin_pubkey = std::string(kLinkTokenLocalOrigin);
    local_seq_ = std::max(local_seq_ + 1, system_now_ms());
    e.origin_seq = local_seq_;
    e.signature.clear();
}

bool TokenLinkAuthProvider::save_locked() {
    json events = json::array();
    for (const auto& e : ledger_.events()) events.push_back(link_token_event_to_wire(e));
    storage::SignedEnvelope env;
    env.type = "link_token_ledger";
    env.data = json{{"events", std::move(events)}}.dump();
    env.timestamp = now_sec();
    if (!storage_.write_file(kLedgerCategory, kLedgerFile, env)) {
        spdlog::error("[token-link] failed to save the link token ledger");
        return false;
    }
    return true;
}

void TokenLinkAuthProvider::load() {
    std::lock_guard lock(mutex_);
    const auto env = storage_.read_file(kLedgerCategory, kLedgerFile);
    if (!env) return;
    const auto j = json::parse(env->data, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        spdlog::warn("[token-link] link token ledger unreadable; starting empty");
        return;
    }
    const auto now = now_sec();
    std::size_t held = 0;
    for (const auto& item : j.value("events", json::array())) {
        const auto e = link_token_event_from_wire(item);
        if (!e) continue;
        if (e->origin_pubkey == kLinkTokenLocalOrigin) {
            local_seq_ = std::max(local_seq_, e->origin_seq);
        }
        if (ledger_.add(*e, now) == LinkTokenLedger::AddResult::Added) ++held;
    }
    spdlog::info("[token-link] restored {} link token event(s)", held);
}

LinkTokenRecord TokenLinkAuthProvider::record_from_grant(const LinkTokenEvent& mint) {
    LinkTokenRecord record{
        .owner_user_id = mint.owner_user_id,
        .owner_pubkey  = mint.owner_pubkey,
        .group_node_id = mint.group_node_id,
        .created_at    = mint.created_at,
        .expires_at    = mint.expires_at,
        .permissions   = mint.permissions,
    };
    record.token_hash = mint.token_hash;
    record.grant = mint;
    return record;
}

std::optional<std::pair<std::string, LinkTokenRecord>>
TokenLinkAuthProvider::mint(const std::string& owner_user_id,
                            const std::string& owner_pubkey,
                            const std::string& group_node_id,
                            std::chrono::seconds ttl,
                            std::vector<std::string> permissions) {
    if (owner_user_id.empty() || group_node_id.empty()) return std::nullopt;
    ttl = std::clamp(ttl, std::chrono::seconds{60}, kMaxTtl);

    std::array<uint8_t, 32> raw{};
    crypto_.random_bytes(std::span<uint8_t>(raw));
    auto token = "lnk_" + crypto::to_hex(std::span<const uint8_t>(raw));

    LinkTokenEvent mint;
    EventPublisher publisher;
    {
        std::lock_guard lock(mutex_);
        const auto now = now_sec();
        ledger_.prune(now);
        if (ledger_.live_count_for_owner(owner_user_id, now) >= kLinkTokenMaxPerOwner) {
            spdlog::warn("[token-link] owner {} holds {} live link tokens; refusing another",
                         owner_user_id, kLinkTokenMaxPerOwner);
            return std::nullopt;
        }
        mint.kind          = LinkTokenEventKind::Mint;
        mint.token_hash    = link_token_hash_hex(token);
        mint.generation    = 0;
        mint.expires_at    = now + static_cast<uint64_t>(ttl.count());
        mint.group_node_id = group_node_id;
        mint.permissions   = std::move(permissions);
        mint.owner_user_id = owner_user_id;
        mint.owner_pubkey  = owner_pubkey;
        mint.created_at    = now;
        author_locked(mint, true);
        if (ledger_.add(mint, now) != LinkTokenLedger::AddResult::Added || !save_locked()) {
            spdlog::error("[token-link] could not record a new link token");
            return std::nullopt;
        }
        publisher = publisher_;
    }
    if (publisher && !mint.signature.empty()) (void)publisher(mint);

    spdlog::info("[token-link] Minted link token for group {} (owner {}, ttl {}s)",
                 group_node_id, owner_user_id, ttl.count());
    return std::make_pair(std::move(token), record_from_grant(mint));
}

std::optional<LinkTokenRecord> TokenLinkAuthProvider::verify(std::string_view token) {
    if (token.empty()) return std::nullopt;
    {
        std::lock_guard lock(mutex_);
        if (const auto live = ledger_.live(link_token_hash_hex(token), now_sec())) {
            auto record = record_from_grant(live->mint);
            record.generation = live->generation;
            return record;
        }
    }
    return legacy_verify(token);
}

std::optional<LinkTokenRecord> TokenLinkAuthProvider::consume(std::string_view token) {
    if (token.empty()) return std::nullopt;
    const auto hash = link_token_hash_hex(token);

    LinkTokenEvent spend;
    LinkTokenRecord record;
    EventPublisher publisher;
    {
        std::lock_guard lock(mutex_);
        const auto now = now_sec();
        const auto live = ledger_.live(hash, now);
        if (!live) {
            if (ledger_.holds(hash)) {
                spdlog::warn("[token-link] Link token spent or expired");
                return std::nullopt;
            }
            // Not a replicated token: it may be one an earlier release
            // minted on this server.
            return legacy_consume(token);
        }
        spend.kind       = LinkTokenEventKind::Spend;
        spend.token_hash = hash;
        spend.generation = live->generation;
        spend.network_id = live->mint.network_id;
        spend.expires_at = live->mint.expires_at;
        // Only a replicated (signed) token gets replicated spends.
        author_locked(spend, !live->mint.signature.empty());
        if (ledger_.add(spend, now) != LinkTokenLedger::AddResult::Added) {
            spdlog::error("[token-link] could not record a link token spend");
            return std::nullopt;
        }
        if (!save_locked()) {
            // The token stays spent in memory; without a durable spend it is
            // not handed out.
            return std::nullopt;
        }
        record = record_from_grant(live->mint);
        record.generation = spend.generation;
        record.spent_by = spend.origin_pubkey;
        if (!spend.signature.empty()) publisher = publisher_;
    }

    if (publisher) (void)publisher(spend);

    spdlog::info("[token-link] Consumed link token for group {}", record.group_node_id);
    return record;
}

bool TokenLinkAuthProvider::refund(std::string_view token, const LinkTokenRecord& record) {
    if (token.empty() || record.owner_user_id.empty() || record.group_node_id.empty()) {
        return false;
    }
    if (record.token_hash.empty()) return legacy_refund(token, record);
    if (link_token_hash_hex(token) != record.token_hash || !record.grant) return false;

    LinkTokenEvent refund;
    EventPublisher publisher;
    {
        std::lock_guard lock(mutex_);
        const auto now = now_sec();
        if (record.expires_at <= now || record.generation >= kLinkTokenMaxGeneration) {
            return false;
        }
        const auto winner = ledger_.spend_winner(record.token_hash, record.generation);
        if (!winner || *winner != record.spent_by) return false;
        refund.kind          = LinkTokenEventKind::Refund;
        refund.token_hash    = record.token_hash;
        refund.generation    = record.generation;
        refund.network_id    = record.grant->network_id;
        refund.expires_at    = record.grant->expires_at;
        author_locked(refund, !record.grant->signature.empty());
        // A refund names the same origin as the spend it undoes; a changed
        // signer (replication wired or lost in between) cannot restore it.
        if (refund.origin_pubkey != record.spent_by) return false;
        if (ledger_.add(refund, now) != LinkTokenLedger::AddResult::Added || !save_locked()) {
            return false;
        }
        if (!refund.signature.empty()) publisher = publisher_;
    }
    if (publisher) (void)publisher(refund);
    spdlog::info("[token-link] Restored unused link token for group {}", record.group_node_id);
    return true;
}

bool TokenLinkAuthProvider::apply_replicated(const LinkTokenEvent& event) {
    if (event.signature.empty() || event.origin_pubkey == kLinkTokenLocalOrigin) return false;
    std::lock_guard lock(mutex_);
    const auto now = now_sec();
    ledger_.prune(now);
    const auto result = ledger_.add(event, now);
    if (result == LinkTokenLedger::AddResult::Duplicate) return true;
    if (result != LinkTokenLedger::AddResult::Added) return false;
    if (event.kind == LinkTokenEventKind::Spend && !self_origin_.empty() &&
        event.origin_pubkey != self_origin_) {
        // A second redemption of one generation: only one server's spend
        // counts. Without tree operations the other server may already have
        // used the token (the race window in Security.md); log it for audit.
        const auto winner = ledger_.spend_winner(event.token_hash, event.generation);
        for (const auto& held : ledger_.events()) {
            if (held.token_hash == event.token_hash && held.kind == LinkTokenEventKind::Spend &&
                held.generation == event.generation && held.origin_pubkey == self_origin_) {
                spdlog::warn("[token-link] link token generation {} was redeemed here and on "
                             "server {}; the redemption by {} counts", event.generation,
                             event.origin_pubkey.substr(0, 12),
                             winner ? winner->substr(0, 12) : std::string{"?"});
                break;
            }
        }
    }
    (void)save_locked();
    return true;
}

void TokenLinkAuthProvider::purge() {
    std::lock_guard lock(mutex_);
    ledger_.clear();
    for (const auto& name : storage_.list_files(kLedgerCategory)) {
        (void)storage_.delete_file(kLedgerCategory, name + ".json");
    }
    spdlog::info("[token-link] removed every link token (this server left Tier 1)");
}

// --- Tokens minted by an earlier release ----------------------------------

std::optional<LinkTokenRecord> TokenLinkAuthProvider::legacy_verify(std::string_view token) {
    if (token.empty()) return std::nullopt;

    auto path = legacy_token_path(token);
    json j;
    {
        std::ifstream ifs(path);
        if (!ifs) return std::nullopt;
        std::ostringstream ss;
        ss << ifs.rdbuf();
        j = json::parse(ss.str(), nullptr, false);
        if (j.is_discarded() || !j.is_object()) return std::nullopt;
    }

    LinkTokenRecord record{
        .owner_user_id = j.value("owner_user_id", std::string{}),
        .owner_pubkey  = j.value("owner_pubkey", std::string{}),
        .group_node_id = j.value("group_node_id", std::string{}),
        .created_at    = j.value("created_at", uint64_t{0}),
        .expires_at    = j.value("expires_at", uint64_t{0}),
    };
    if (!j.contains("permissions")) {
        // Minted before invites carried permissions. Acceptance re-checks the
        // inviter's authority for these, so the default grants nothing extra.
        for (const auto p : tree::rules::kDefaultInvitePermissions) {
            record.permissions.emplace_back(p);
        }
    } else if (j["permissions"].is_array()) {
        for (const auto& p : j["permissions"]) {
            if (!p.is_string()) return std::nullopt;
            record.permissions.push_back(p.get<std::string>());
        }
    } else {
        return std::nullopt;
    }

    if (record.expires_at <= now_sec()) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        spdlog::debug("[token-link] Rejected expired link token");
        return std::nullopt;
    }

    if (record.owner_user_id.empty() || record.group_node_id.empty()) return std::nullopt;
    return record;
}

std::optional<LinkTokenRecord> TokenLinkAuthProvider::legacy_consume(std::string_view token) {
    auto record = legacy_verify(token);
    if (!record) return std::nullopt;

    std::error_code ec;
    if (!std::filesystem::remove(legacy_token_path(token), ec)) {
        // Already consumed by a concurrent request — treat as spent.
        spdlog::warn("[token-link] Link token already consumed");
        return std::nullopt;
    }

    spdlog::info("[token-link] Consumed link token for group {}", record->group_node_id);
    return record;
}

bool TokenLinkAuthProvider::legacy_refund(std::string_view token, const LinkTokenRecord& record) {
    if (record.expires_at <= now_sec()) return false;
    const auto path = legacy_token_path(token);
    std::error_code ec;
    if (std::filesystem::exists(path, ec) || ec) return false;
    if (!write_legacy_record(path, record)) return false;
    spdlog::info("[token-link] Restored unused link token for group {}", record.group_node_id);
    return true;
}

std::size_t TokenLinkAuthProvider::revoke_where(
        const std::function<bool(const LinkTokenRecord&)>& match) {
    // Replicated tokens: a Revoke event ends the token on every Tier 1
    // server that holds or later receives it, whatever its generation.
    std::vector<LinkTokenEvent> to_publish;
    EventPublisher publisher;
    std::size_t removed = 0;
    {
        std::lock_guard lock(mutex_);
        const auto now = now_sec();
        ledger_.prune(now);
        for (const auto& mint : ledger_.mints()) {
            if (ledger_.revoked(mint.token_hash) || !match(record_from_grant(mint))) continue;
            LinkTokenEvent revoke;
            revoke.kind       = LinkTokenEventKind::Revoke;
            revoke.token_hash = mint.token_hash;
            revoke.network_id = mint.network_id;
            revoke.expires_at = mint.expires_at;
            author_locked(revoke, !mint.signature.empty());
            if (ledger_.add(revoke, now) != LinkTokenLedger::AddResult::Added) continue;
            ++removed;
            if (!revoke.signature.empty()) to_publish.push_back(std::move(revoke));
        }
        if (removed > 0) (void)save_locked();
        publisher = publisher_;
    }
    if (publisher) {
        for (const auto& e : to_publish) (void)publisher(e);
    }

    // Tokens an earlier release stored as one plaintext file each.
    const auto dir = storage_.data_root() / std::string(kLedgerCategory);
    std::error_code ec;
    if (std::filesystem::is_directory(dir, ec)) {
        std::vector<std::filesystem::path> doomed;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            if (entry.path().extension() != ".json" || entry.path().filename() == kLedgerFile) {
                continue;
            }
            std::ifstream ifs(entry.path());
            if (!ifs) continue;
            std::ostringstream ss;
            ss << ifs.rdbuf();
            const auto j = json::parse(ss.str(), nullptr, false);
            if (j.is_discarded() || !j.is_object()) continue;
            LinkTokenRecord record;
            record.owner_user_id = j.value("owner_user_id", std::string{});
            record.owner_pubkey  = j.value("owner_pubkey", std::string{});
            record.group_node_id = j.value("group_node_id", std::string{});
            if (match(record)) doomed.push_back(entry.path());
        }
        for (const auto& path : doomed) {
            if (std::filesystem::remove(path, ec)) ++removed;
        }
    }
    if (removed > 0) spdlog::info("[token-link] Revoked {} link token(s)", removed);
    return removed;
}

std::filesystem::path TokenLinkAuthProvider::legacy_token_path(std::string_view token) const {
    auto hash = crypto_.sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(token.data()), token.size()));
    auto name = crypto::to_hex(std::span<const uint8_t>(hash));
    return storage_.data_root() / std::string(kLedgerCategory) / (name + ".json");
}

} // namespace nexus::auth
