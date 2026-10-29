#include <LemonadeNexus/Auth/TokenLinkAuthProvider.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>
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

/// Draws the minting server makes before it gives up on a free invite code.
constexpr int kCodeDraws = 8;

/// A uniformly random invite code of kLinkCodeDigits decimal digits.
std::string draw_code(crypto::SodiumCryptoService& crypto) {
    constexpr uint32_t kSpace = [] {
        uint32_t n = 1;
        for (std::size_t i = 0; i < auth::kLinkCodeDigits; ++i) n *= 10;
        return n;
    }();
    constexpr uint32_t kLimit = (std::numeric_limits<uint32_t>::max() / kSpace) * kSpace;
    for (;;) {
        std::array<uint8_t, 4> raw{};
        crypto.random_bytes(std::span<uint8_t>(raw));
        uint32_t v = (uint32_t{raw[0]} << 24) | (uint32_t{raw[1]} << 16) |
                     (uint32_t{raw[2]} << 8) | uint32_t{raw[3]};
        if (v >= kLimit) continue;  // rejection keeps every code equally likely
        v %= kSpace;
        std::string code(auth::kLinkCodeDigits, '0');
        for (std::size_t i = auth::kLinkCodeDigits; i-- > 0;) {
            code[i] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
        return code;
    }
}

enum class LegacyFileState { Absent, Unreadable, Present };

struct LegacyFile {
    LegacyFileState state = LegacyFileState::Absent;
    json data;
};

/// Read a legacy token record, through the storage vault when it covers the
/// path (StorageVault "link-token-legacy"). Unreadable (locked, refused, read
/// failure, or not a JSON object) is never treated as absent.
LegacyFile read_legacy_file(const storage::FileStorageService& storage,
                            const std::filesystem::path& path) {
    LegacyFile out;
    std::string text;
    if (auto* vault = storage.vault_for(path)) {
        auto read = vault->read(path);
        if (read.status == security::VaultReadStatus::Missing) return out;
        if (read.status != security::VaultReadStatus::Ok) {
            spdlog::error("[token-link] legacy token file {} does not open under the data key",
                          path.filename().string());
            out.state = LegacyFileState::Unreadable;
            return out;
        }
        text = std::move(read.bytes);
    } else {
        std::error_code ec;
        const auto status = std::filesystem::status(path, ec);
        if (ec || !std::filesystem::exists(status)) {
            if (!ec || ec == std::errc::no_such_file_or_directory) return out;
            out.state = LegacyFileState::Unreadable;
            return out;
        }
        std::ifstream ifs(path, std::ios::binary);
        std::ostringstream ss;
        if (ifs) ss << ifs.rdbuf();
        if (!ifs || ifs.bad()) {
            out.state = LegacyFileState::Unreadable;
            return out;
        }
        text = std::move(ss).str();
    }
    auto parsed = json::parse(text, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        out.state = LegacyFileState::Unreadable;
        return out;
    }
    out.state = LegacyFileState::Present;
    out.data = std::move(parsed);
    return out;
}

/// Remove a legacy token file (and a staged vault copy). True when it is gone.
bool remove_legacy_file(const storage::FileStorageService& storage,
                        const std::filesystem::path& path) {
    if (auto* vault = storage.vault_for(path)) return vault->remove(path);
    std::error_code ec;
    std::filesystem::remove(path, ec);
    return !std::filesystem::exists(path, ec) && !ec;
}

/// Write a legacy token `record` to `path` durably, through the vault when it
/// covers the path.
bool write_legacy_record(const storage::FileStorageService& storage,
                         const std::filesystem::path& path, const LinkTokenRecord& record) {
    json j = {
        {"owner_user_id", record.owner_user_id},
        {"owner_pubkey",  record.owner_pubkey},
        {"group_node_id", record.group_node_id},
        {"created_at",    record.created_at},
        {"expires_at",    record.expires_at},
        {"permissions",   record.permissions},
    };
    const auto text = j.dump(2);
    if (auto* vault = storage.vault_for(path)) return vault->write(path, text);
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (!security::write_durable(path, text)) {
        spdlog::error("[token-link] Failed to write token file: {}", path.string());
        return false;
    }
    return true;
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
    e.code_signature.clear();
}

std::optional<LinkTokenLedger::Live> TokenLinkAuthProvider::live_by_code_locked(
        std::string_view code, std::string_view source, uint64_t now) {
    // The hash and the lookup run before any limit is consulted, so a refused
    // attempt costs what a wrong code costs.
    const auto code_hash = link_code_hash_hex(code);
    auto live = ledger_.live_by_code(code_hash, now);

    const auto window_open = [now](const CodeFailures& f) {
        return f.count > 0 && now < f.window_start + kLinkCodeFailureWindowSec;
    };
    const auto note_failure = [now, &window_open](CodeFailures& f) {
        if (!window_open(f)) {
            f.window_start = now;
            f.count = 0;
        }
        ++f.count;
    };

    // Entries whose window and lockout both passed carry nothing.
    std::erase_if(code_failures_by_source_, [&](const auto& kv) {
        return !window_open(kv.second) && now >= kv.second.locked_until;
    });
    auto by_source = code_failures_by_source_.find(source);
    if (by_source == code_failures_by_source_.end()) {
        if (code_failures_by_source_.size() >= kLinkCodeMaxSources) {
            spdlog::debug("[token-link] invite code refused: source table full");
            return std::nullopt;
        }
        by_source = code_failures_by_source_.emplace(std::string(source), CodeFailures{}).first;
    }
    const bool source_locked = now < by_source->second.locked_until;
    const bool server_locked = window_open(code_failures_all_) &&
                               code_failures_all_.count >= kLinkCodeMaxFailuresPerServer;
    if (source_locked || server_locked) {
        // Refused outright, right or wrong; a refused attempt counts toward
        // neither limit, so a locked address cannot close codes for everyone.
        spdlog::debug("[token-link] invite code refused: {} limit", source_locked ? "source" : "server");
        return std::nullopt;
    }
    if (!live) {
        // Unknown, expired, spent, or shared: one wrong attempt for this
        // address and for the server. The code is not logged.
        note_failure(by_source->second);
        if (by_source->second.count >= kLinkCodeMaxFailuresPerSource) {
            by_source->second.locked_until = now + kLinkCodeFailureWindowSec;
        }
        note_failure(code_failures_all_);
        spdlog::debug("[token-link] invite code refused");
    }
    return live;
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

std::optional<MintedLinkToken>
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

    std::string code;
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
        // The code is unique among the unexpired codes this server holds.
        // Another server can still mint the same code in the same window;
        // then neither code redeems (LinkTokenLedger::live_by_code) and both
        // tokens do.
        for (int draw = 0; draw < kCodeDraws && code.empty(); ++draw) {
            auto candidate = draw_code(crypto_);
            if (!ledger_.code_in_use(link_code_hash_hex(candidate), now)) code = std::move(candidate);
        }
        if (code.empty()) {
            spdlog::error("[token-link] no free invite code in {} draws; refusing to mint",
                          kCodeDraws);
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
        mint.code_hash     = link_code_hash_hex(code);
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
    return MintedLinkToken{std::move(token), std::move(code), record_from_grant(mint)};
}

std::optional<LinkTokenRecord> TokenLinkAuthProvider::verify(std::string_view token_or_code,
                                                             std::string_view source) {
    if (token_or_code.empty()) return std::nullopt;
    {
        std::lock_guard lock(mutex_);
        const auto now = now_sec();
        const auto live = is_link_code(token_or_code)
                              ? live_by_code_locked(token_or_code, source, now)
                              : ledger_.live(link_token_hash_hex(token_or_code), now);
        if (live) {
            auto record = record_from_grant(live->mint);
            record.generation = live->generation;
            return record;
        }
        // A code never names a token from an earlier release.
        if (is_link_code(token_or_code)) return std::nullopt;
    }
    return legacy_verify(token_or_code);
}

std::optional<LinkTokenRecord> TokenLinkAuthProvider::consume(std::string_view token_or_code,
                                                              std::string_view source) {
    if (token_or_code.empty()) return std::nullopt;
    const bool by_code = is_link_code(token_or_code);
    std::string hash = by_code ? std::string{} : link_token_hash_hex(token_or_code);

    LinkTokenEvent spend;
    LinkTokenRecord record;
    EventPublisher publisher;
    {
        std::lock_guard lock(mutex_);
        const auto now = now_sec();
        std::optional<LinkTokenLedger::Live> live;
        if (by_code) {
            live = live_by_code_locked(token_or_code, source, now);
            if (!live) return std::nullopt;
            hash = live->mint.token_hash;
        } else {
            live = ledger_.live(hash, now);
            if (!live) {
                if (ledger_.holds(hash)) {
                    spdlog::warn("[token-link] Link token spent or expired");
                    return std::nullopt;
                }
                // Not a replicated token: it may be one an earlier release
                // minted on this server.
                return legacy_consume(token_or_code);
            }
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

bool TokenLinkAuthProvider::refund(std::string_view token_or_code,
                                   const LinkTokenRecord& record) {
    if (token_or_code.empty() || record.owner_user_id.empty() || record.group_node_id.empty()) {
        return false;
    }
    const bool by_code = is_link_code(token_or_code);
    if (record.token_hash.empty()) return !by_code && legacy_refund(token_or_code, record);
    if (!record.grant) return false;
    // The secret presented must name the record's token, as the token or as
    // the code its mint binds.
    const bool names_token =
        by_code ? !record.grant->code_hash.empty() &&
                      link_code_hash_hex(token_or_code) == record.grant->code_hash
                : link_token_hash_hex(token_or_code) == record.token_hash;
    if (!names_token) return false;

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

    const auto path = legacy_token_path(token);
    const auto file = read_legacy_file(storage_, path);
    // An unreadable record is refused, and it stays on disk as it is.
    if (file.state != LegacyFileState::Present) return std::nullopt;
    const auto& j = file.data;

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
        (void)remove_legacy_file(storage_, path);
        spdlog::debug("[token-link] Rejected expired link token");
        return std::nullopt;
    }

    if (record.owner_user_id.empty() || record.group_node_id.empty()) return std::nullopt;
    return record;
}

std::optional<LinkTokenRecord> TokenLinkAuthProvider::legacy_consume(std::string_view token) {
    // consume() holds mutex_, so the read and the removal are one step for
    // every other redemption on this server.
    auto record = legacy_verify(token);
    if (!record) return std::nullopt;

    if (!remove_legacy_file(storage_, legacy_token_path(token))) {
        // Still on disk: not consumed, so not handed out.
        spdlog::error("[token-link] Link token file could not be removed; not redeemed");
        return std::nullopt;
    }

    spdlog::info("[token-link] Consumed link token for group {}", record->group_node_id);
    return record;
}

bool TokenLinkAuthProvider::legacy_refund(std::string_view token, const LinkTokenRecord& record) {
    if (record.expires_at <= now_sec()) return false;
    const auto path = legacy_token_path(token);
    // Present or unreadable: a record stands there and is never replaced.
    if (read_legacy_file(storage_, path).state != LegacyFileState::Absent) return false;
    if (!write_legacy_record(storage_, path, record)) return false;
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

    // Tokens an earlier release stored as one file each. An unreadable file is
    // skipped and stays: it is neither matched nor removed.
    const auto dir = storage_.data_root() / std::string(kLedgerCategory);
    std::error_code ec;
    if (std::filesystem::is_directory(dir, ec)) {
        std::vector<std::filesystem::path> doomed;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            if (entry.path().extension() != ".json" || entry.path().filename() == kLedgerFile) {
                continue;
            }
            const auto file = read_legacy_file(storage_, entry.path());
            if (file.state != LegacyFileState::Present) continue;
            const auto& j = file.data;
            LinkTokenRecord record;
            record.owner_user_id = j.value("owner_user_id", std::string{});
            record.owner_pubkey  = j.value("owner_pubkey", std::string{});
            record.group_node_id = j.value("group_node_id", std::string{});
            if (match(record)) doomed.push_back(entry.path());
        }
        for (const auto& path : doomed) {
            if (remove_legacy_file(storage_, path)) ++removed;
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
