#include <LemonadeNexus/Auth/TokenLinkAuthProvider.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

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

uint64_t now_epoch_sec() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

} // namespace

TokenLinkAuthProvider::TokenLinkAuthProvider(storage::FileStorageService& storage,
                                             crypto::SodiumCryptoService& crypto)
    : storage_(storage)
    , crypto_(crypto)
{
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

std::optional<std::pair<std::string, LinkTokenRecord>>
TokenLinkAuthProvider::mint(const std::string& owner_user_id,
                            const std::string& owner_pubkey,
                            const std::string& group_node_id,
                            std::chrono::seconds ttl) {
    if (owner_user_id.empty() || group_node_id.empty()) return std::nullopt;
    ttl = std::clamp(ttl, std::chrono::seconds{60}, kMaxTtl);

    std::array<uint8_t, 32> raw{};
    crypto_.random_bytes(std::span<uint8_t>(raw));
    auto token = "lnk_" + crypto::to_hex(std::span<const uint8_t>(raw));

    auto now = now_epoch_sec();
    LinkTokenRecord record{
        .owner_user_id = owner_user_id,
        .owner_pubkey  = owner_pubkey,
        .group_node_id = group_node_id,
        .created_at    = now,
        .expires_at    = now + static_cast<uint64_t>(ttl.count()),
    };

    json j = {
        {"owner_user_id", record.owner_user_id},
        {"owner_pubkey",  record.owner_pubkey},
        {"group_node_id", record.group_node_id},
        {"created_at",    record.created_at},
        {"expires_at",    record.expires_at},
    };

    auto path = token_path(token);
    try {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs) {
            spdlog::error("[token-link] Failed to open token file: {}", path.string());
            return std::nullopt;
        }
        ofs << j.dump(2);
        if (!ofs.good()) return std::nullopt;
    } catch (const std::exception& e) {
        spdlog::error("[token-link] Exception writing token file: {}", e.what());
        return std::nullopt;
    }

    spdlog::info("[token-link] Minted link token for group {} (owner {}, ttl {}s)",
                 group_node_id, owner_user_id, ttl.count());
    return std::make_pair(std::move(token), std::move(record));
}

std::optional<LinkTokenRecord> TokenLinkAuthProvider::verify(std::string_view token) {
    if (token.empty()) return std::nullopt;

    auto path = token_path(token);
    json j;
    {
        std::ifstream ifs(path);
        if (!ifs) return std::nullopt;
        std::ostringstream ss;
        ss << ifs.rdbuf();
        j = json::parse(ss.str(), nullptr, false);
        if (j.is_discarded()) return std::nullopt;
    }

    LinkTokenRecord record{
        .owner_user_id = j.value("owner_user_id", std::string{}),
        .owner_pubkey  = j.value("owner_pubkey", std::string{}),
        .group_node_id = j.value("group_node_id", std::string{}),
        .created_at    = j.value("created_at", uint64_t{0}),
        .expires_at    = j.value("expires_at", uint64_t{0}),
    };

    if (record.expires_at <= now_epoch_sec()) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        spdlog::debug("[token-link] Rejected expired link token");
        return std::nullopt;
    }

    if (record.owner_user_id.empty() || record.group_node_id.empty()) return std::nullopt;
    return record;
}

std::optional<LinkTokenRecord> TokenLinkAuthProvider::consume(std::string_view token) {
    auto record = verify(token);
    if (!record) return std::nullopt;

    std::error_code ec;
    if (!std::filesystem::remove(token_path(token), ec)) {
        // Already consumed by a concurrent request — treat as spent.
        spdlog::warn("[token-link] Link token already consumed");
        return std::nullopt;
    }

    spdlog::info("[token-link] Consumed link token for group {}", record->group_node_id);
    return record;
}

std::filesystem::path TokenLinkAuthProvider::token_path(std::string_view token) const {
    // Store hashed so a data-root leak doesn't expose live tokens.
    auto hash = crypto_.sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(token.data()), token.size()));
    auto name = crypto::to_hex(std::span<const uint8_t>(hash));
    return storage_.data_root() / "link_tokens" / (name + ".json");
}

} // namespace nexus::auth
